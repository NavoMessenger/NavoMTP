use std::path::{Path, PathBuf};

use crate::daemon::{self, DaemonOptions};

/// Parses daemon-related options from CLI arguments.
pub fn parse_daemon_args(args: &[String]) -> DaemonOptions {
    let mut opts = DaemonOptions::default();
    let mut i = 0;

    while i < args.len() {
        match args[i].as_str() {
            "--daemon" | "-d" => {
                opts.daemonize = true;
            }
            "--foreground" | "-f" => {
                opts.foreground = true;
            }
            "--strict-runtime-paths" => {
                opts.strict_runtime_paths = true;
            }
            "--pid-file" => {
                i += 1;
                if i < args.len() {
                    opts.pid_file = Some(PathBuf::from(&args[i]));
                }
            }
            s if s.starts_with("--pid-file=") => {
                opts.pid_file = Some(PathBuf::from(s.trim_start_matches("--pid-file=")));
            }
            "--run-as-user" => {
                i += 1;
                if i < args.len() {
                    opts.user = Some(args[i].clone());
                }
            }
            s if s.starts_with("--run-as-user=") => {
                opts.user = Some(s.trim_start_matches("--run-as-user=").to_string());
            }
            "--run-as-group" => {
                i += 1;
                if i < args.len() {
                    opts.group = Some(args[i].clone());
                }
            }
            s if s.starts_with("--run-as-group=") => {
                opts.group = Some(s.trim_start_matches("--run-as-group=").to_string());
            }
            "--working-dir" => {
                i += 1;
                if i < args.len() {
                    opts.working_dir = Some(PathBuf::from(&args[i]));
                }
            }
            s if s.starts_with("--working-dir=") => {
                opts.working_dir = Some(PathBuf::from(s.trim_start_matches("--working-dir=")));
            }
            _ => {}
        }
        i += 1;
    }

    opts
}

/// Sends SIGTERM and waits briefly for graceful PID-file cleanup.
pub(super) fn stop(pid_file: &Path, strict_runtime_paths: bool) -> i32 {
    use nix::sys::signal::Signal;

    println!("Stopping telemt daemon...");

    match daemon::signal_pid_file(pid_file, Signal::SIGTERM, strict_runtime_paths) {
        Ok(()) => {
            println!("Stop signal sent successfully");

            // Wait for process to exit for up to ten seconds.
            for _ in 0..20 {
                std::thread::sleep(std::time::Duration::from_millis(500));
                if let daemon::DaemonStatus::NotRunning =
                    daemon::check_status(pid_file, strict_runtime_paths)
                {
                    println!("Daemon stopped");
                    return 0;
                }
            }
            println!("Daemon may still be shutting down");
            0
        }
        Err(e) => {
            eprintln!("Failed to stop daemon: {}", e);
            1
        }
    }
}

/// Sends SIGHUP to trigger configuration reload.
pub(super) fn reload(pid_file: &Path, strict_runtime_paths: bool) -> i32 {
    use nix::sys::signal::Signal;

    println!("Reloading telemt configuration...");

    match daemon::signal_pid_file(pid_file, Signal::SIGHUP, strict_runtime_paths) {
        Ok(()) => {
            println!("Reload signal sent successfully");
            0
        }
        Err(e) => {
            eprintln!("Failed to reload daemon: {}", e);
            1
        }
    }
}

/// Reports daemon status without mutating PID lifecycle state.
pub(super) fn status(pid_file: &Path, strict_runtime_paths: bool) -> i32 {
    match daemon::check_status(pid_file, strict_runtime_paths) {
        daemon::DaemonStatus::Running(pid) => {
            println!("telemt is running (pid {})", pid);
            0
        }
        daemon::DaemonStatus::Stale(pid) => {
            println!("telemt is not running (stale pid file, was pid {})", pid);
            1
        }
        daemon::DaemonStatus::NotRunning => {
            println!("telemt is not running");
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    use super::*;

    const CONTROL_PID: &str = "TELEMT_RUNTIME_PATH_TEST_PID";
    const CONTROL_READY: &str = "TELEMT_RUNTIME_PATH_TEST_READY";
    const CONTROL_RELOADED: &str = "TELEMT_RUNTIME_PATH_TEST_RELOADED";

    struct ControlChild(Child);

    impl Drop for ControlChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn wait_for_file(path: &Path) -> bool {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if path.exists() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        false
    }

    #[test]
    fn runtime_path_policy_defaults_to_compatibility_for_all_commands() {
        for command in ["run", "start", "stop", "reload", "status"] {
            let args = vec![command.to_string(), "config.toml".to_string()];
            assert!(
                !crate::cli::parse_command(&args)
                    .daemon_opts
                    .strict_runtime_paths
            );
            assert!(!parse_daemon_args(&args).strict_runtime_paths);

            for position in [1, args.len()] {
                let mut strict_args = args.clone();
                strict_args.insert(position, "--strict-runtime-paths".to_string());
                let parsed = crate::cli::parse_command(&strict_args);
                assert!(parsed.daemon_opts.strict_runtime_paths);
                assert!(parse_daemon_args(&strict_args).strict_runtime_paths);
                assert_eq!(parsed.config_path, "config.toml");
            }
        }
        let args = vec![
            "--strict-runtime-paths".to_string(),
            "config.toml".to_string(),
        ];
        let parsed = crate::cli::parse_command(&args);
        assert_eq!(parsed.subcommand, crate::cli::Subcommand::Run);
        assert!(parsed.daemon_opts.strict_runtime_paths);
        assert_eq!(parsed.config_path, "config.toml");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn daemon_control_subprocess() {
        let Some(pid_path) = std::env::var_os(CONTROL_PID) else {
            return;
        };
        let ready = PathBuf::from(std::env::var_os(CONTROL_READY).unwrap());
        let reloaded = PathBuf::from(std::env::var_os(CONTROL_RELOADED).unwrap());
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).unwrap();
        let mut reload =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).unwrap();
        let mut owner = daemon::PidFile::new(PathBuf::from(pid_path), false);
        owner.acquire().unwrap();
        fs::write(&ready, b"ready").unwrap();
        let deadline = tokio::time::sleep(Duration::from_secs(15));
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                _ = terminate.recv() => break,
                _ = reload.recv() => fs::write(&reloaded, b"reloaded").unwrap(),
                _ = &mut deadline => panic!("daemon control subprocess timed out"),
            }
        }
        owner.release().unwrap();
    }

    #[test]
    fn control_commands_follow_runtime_path_policy() {
        for (mode, linked_parent, trusted_parent) in [
            (0o777, false, false),
            (0o777, true, false),
            (0o755, false, true),
        ] {
            let root = tempfile::tempdir().unwrap();
            let real = root.path().join("run");
            let linked = root.path().join("linked");
            fs::create_dir(&real).unwrap();
            fs::set_permissions(&real, fs::Permissions::from_mode(mode)).unwrap();
            symlink(&real, &linked).unwrap();
            let pid_path = if linked_parent { &linked } else { &real }.join("telemt.pid");
            let ready = root.path().join("ready");
            let reloaded = root.path().join("reloaded");
            let mut child = ControlChild(
                Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "cli::daemon_commands::tests::daemon_control_subprocess",
                        "--nocapture",
                    ])
                    .env(CONTROL_PID, &pid_path)
                    .env(CONTROL_READY, &ready)
                    .env(CONTROL_RELOADED, &reloaded)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .unwrap(),
            );
            assert!(
                wait_for_file(&ready),
                "daemon control subprocess did not become ready"
            );
            let command = |name: &str, strict: bool| {
                let mut args = vec![
                    name.to_string(),
                    "--pid-file".to_string(),
                    pid_path.to_str().unwrap().to_string(),
                ];
                if strict {
                    args.push("--strict-runtime-paths".to_string());
                }
                crate::cli::execute_subcommand(&crate::cli::parse_command(&args))
            };

            assert_eq!(command("status", false), Some(0));
            if trusted_parent {
                assert_eq!(command("status", true), Some(0));
                assert_eq!(command("reload", true), Some(0));
                assert!(wait_for_file(&reloaded));
                assert_eq!(command("stop", true), Some(0));
            } else {
                assert_eq!(command("status", true), Some(1));
                assert_eq!(command("reload", true), Some(1));
                assert!(!reloaded.exists());
                assert_eq!(command("stop", true), Some(1));
                assert_eq!(command("status", false), Some(0));
                assert_eq!(command("reload", false), Some(0));
                assert!(wait_for_file(&reloaded));
                assert_eq!(command("stop", false), Some(0));
            }
            assert!(child.0.wait().unwrap().success());
            assert!(!pid_path.exists());
            assert_eq!(command("status", false), Some(1));
        }
    }

    #[test]
    fn status_does_not_remove_stale_pid_file() {
        let directory = tempfile::tempdir().unwrap();
        let pid_file = directory.path().join("telemt.pid");
        fs::write(&pid_file, b"2000000000\n").unwrap();

        assert_eq!(status(&pid_file, false), 1);
        assert!(pid_file.exists());
    }
}
