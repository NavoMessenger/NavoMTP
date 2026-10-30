//! CLI commands: --init (fire-and-forget setup), daemon options, subcommands
//!
//! Subcommands:
//! - `start [OPTIONS] [config.toml]` - Start the daemon
//! - `stop [--pid-file PATH] [--strict-runtime-paths]` - Stop a running daemon
//! - `reload [--pid-file PATH] [--strict-runtime-paths]` - Reload configuration (SIGHUP)
//! - `status [--pid-file PATH] [--strict-runtime-paths]` - Check daemon status
//! - `run [OPTIONS] [config.toml]` - Run in foreground (default behavior)
//! - `healthcheck [OPTIONS] [config.toml]` - Run control-plane health probe

use std::path::PathBuf;

use crate::healthcheck::{self, HealthcheckMode};

#[cfg(unix)]
use crate::daemon::{DEFAULT_PID_FILE, DaemonOptions};

// Unix daemon control and argument parsing.
#[cfg(unix)]
mod daemon_commands;
// Fire-and-forget installation workflow.
mod init;

#[cfg(unix)]
pub use daemon_commands::parse_daemon_args;
pub use init::{InitOptions, parse_init_args, run_init};

/// CLI subcommand to execute.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Subcommand {
    /// Run the proxy (default, or explicit `run` subcommand).
    Run,
    /// Start as daemon (`start` subcommand).
    Start,
    /// Stop a running daemon (`stop` subcommand).
    Stop,
    /// Reload configuration (`reload` subcommand).
    Reload,
    /// Check daemon status (`status` subcommand).
    Status,
    /// Run health probe and exit with status code.
    Healthcheck,
    /// Fire-and-forget setup (`--init`).
    Init,
}

/// Parsed subcommand with its options.
#[derive(Debug)]
pub struct ParsedCommand {
    /// Selected command mode.
    pub subcommand: Subcommand,
    /// PID file used by daemon-control commands.
    pub pid_file: PathBuf,
    /// Configuration file passed to runtime or healthcheck.
    pub config_path: String,
    /// Requested healthcheck mode.
    pub healthcheck_mode: HealthcheckMode,
    /// Invalid healthcheck mode retained for command diagnostics.
    pub healthcheck_mode_invalid: Option<String>,
    #[cfg(unix)]
    /// Unix daemon lifecycle options.
    pub daemon_opts: DaemonOptions,
    /// Fire-and-forget initialization options.
    pub init_opts: Option<InitOptions>,
}

impl Default for ParsedCommand {
    fn default() -> Self {
        Self {
            subcommand: Subcommand::Run,
            #[cfg(unix)]
            pid_file: PathBuf::from(DEFAULT_PID_FILE),
            #[cfg(not(unix))]
            pid_file: PathBuf::from("/var/run/telemt.pid"),
            config_path: "config.toml".to_string(),
            healthcheck_mode: HealthcheckMode::Liveness,
            healthcheck_mode_invalid: None,
            #[cfg(unix)]
            daemon_opts: DaemonOptions::default(),
            init_opts: None,
        }
    }
}

/// Parse CLI arguments into a command structure.
pub fn parse_command(args: &[String]) -> ParsedCommand {
    let mut cmd = ParsedCommand::default();

    // Check for --init first (legacy form)
    if args.iter().any(|a| a == "--init") {
        cmd.subcommand = Subcommand::Init;
        cmd.init_opts = parse_init_args(args);
        return cmd;
    }

    if let Some(first) = args.first() {
        match first.as_str() {
            "start" => {
                cmd.subcommand = Subcommand::Start;
                #[cfg(unix)]
                {
                    cmd.daemon_opts = parse_daemon_args(args);
                    // Force daemonize for start command
                    cmd.daemon_opts.daemonize = true;
                }
            }
            "stop" => {
                cmd.subcommand = Subcommand::Stop;
            }
            "reload" => {
                cmd.subcommand = Subcommand::Reload;
            }
            "status" => {
                cmd.subcommand = Subcommand::Status;
            }
            "healthcheck" => {
                cmd.subcommand = Subcommand::Healthcheck;
            }
            "run" => {
                cmd.subcommand = Subcommand::Run;
                #[cfg(unix)]
                {
                    cmd.daemon_opts = parse_daemon_args(args);
                }
            }
            _ => {
                // No subcommand, default to Run
                #[cfg(unix)]
                {
                    cmd.daemon_opts = parse_daemon_args(args);
                }
            }
        }
    }

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "start" | "stop" | "reload" | "status" | "run" | "healthcheck" => {}
            #[cfg(unix)]
            "--strict-runtime-paths" => {
                cmd.daemon_opts.strict_runtime_paths = true;
            }
            "--mode" => {
                i += 1;
                if i < args.len() {
                    match HealthcheckMode::from_cli_arg(&args[i]) {
                        Some(mode) => {
                            cmd.healthcheck_mode = mode;
                            cmd.healthcheck_mode_invalid = None;
                        }
                        None => {
                            cmd.healthcheck_mode_invalid = Some(args[i].clone());
                        }
                    }
                } else {
                    cmd.healthcheck_mode_invalid = Some(String::new());
                }
            }
            s if s.starts_with("--mode=") => {
                let raw = s.trim_start_matches("--mode=");
                match HealthcheckMode::from_cli_arg(raw) {
                    Some(mode) => {
                        cmd.healthcheck_mode = mode;
                        cmd.healthcheck_mode_invalid = None;
                    }
                    None => {
                        cmd.healthcheck_mode_invalid = Some(raw.to_string());
                    }
                }
            }
            "--pid-file" => {
                i += 1;
                if i < args.len() {
                    cmd.pid_file = PathBuf::from(&args[i]);
                    #[cfg(unix)]
                    {
                        cmd.daemon_opts.pid_file = Some(cmd.pid_file.clone());
                    }
                }
            }
            s if s.starts_with("--pid-file=") => {
                cmd.pid_file = PathBuf::from(s.trim_start_matches("--pid-file="));
                #[cfg(unix)]
                {
                    cmd.daemon_opts.pid_file = Some(cmd.pid_file.clone());
                }
            }
            // Config path (positional, non-flag argument)
            s if !s.starts_with('-') => {
                cmd.config_path = s.to_string();
            }
            _ => {}
        }
        i += 1;
    }

    cmd
}

/// Execute a subcommand that doesn't require starting the server.
/// Returns `Some(exit_code)` if the command was handled, `None` if server should start.
#[cfg(unix)]
pub fn execute_subcommand(cmd: &ParsedCommand) -> Option<i32> {
    match cmd.subcommand {
        Subcommand::Stop => Some(daemon_commands::stop(
            &cmd.pid_file,
            cmd.daemon_opts.strict_runtime_paths,
        )),
        Subcommand::Reload => Some(daemon_commands::reload(
            &cmd.pid_file,
            cmd.daemon_opts.strict_runtime_paths,
        )),
        Subcommand::Status => Some(daemon_commands::status(
            &cmd.pid_file,
            cmd.daemon_opts.strict_runtime_paths,
        )),
        Subcommand::Healthcheck => {
            if let Some(invalid_mode) = cmd.healthcheck_mode_invalid.as_ref() {
                if invalid_mode.is_empty() {
                    eprintln!("[telemt] Missing value for --mode (supported: liveness, ready)");
                } else {
                    eprintln!(
                        "[telemt] Invalid --mode value '{invalid_mode}' (supported: liveness, ready)"
                    );
                }
                Some(2)
            } else {
                Some(healthcheck::run(&cmd.config_path, cmd.healthcheck_mode))
            }
        }
        Subcommand::Init => {
            if let Some(opts) = cmd.init_opts.clone() {
                match run_init(opts) {
                    Ok(()) => Some(0),
                    Err(e) => {
                        eprintln!("[telemt] Init failed: {}", e);
                        Some(1)
                    }
                }
            } else {
                Some(1)
            }
        }
        // Run and Start need the server
        Subcommand::Run | Subcommand::Start => None,
    }
}

/// Executes a non-server subcommand on platforms without daemon support.
#[cfg(not(unix))]
pub fn execute_subcommand(cmd: &ParsedCommand) -> Option<i32> {
    match cmd.subcommand {
        Subcommand::Stop | Subcommand::Reload | Subcommand::Status => {
            eprintln!("[telemt] Subcommand not supported on this platform");
            Some(1)
        }
        Subcommand::Healthcheck => {
            if let Some(invalid_mode) = cmd.healthcheck_mode_invalid.as_ref() {
                if invalid_mode.is_empty() {
                    eprintln!("[telemt] Missing value for --mode (supported: liveness, ready)");
                } else {
                    eprintln!(
                        "[telemt] Invalid --mode value '{invalid_mode}' (supported: liveness, ready)"
                    );
                }
                Some(2)
            } else {
                Some(healthcheck::run(&cmd.config_path, cmd.healthcheck_mode))
            }
        }
        Subcommand::Init => {
            if let Some(opts) = cmd.init_opts.clone() {
                match run_init(opts) {
                    Ok(()) => Some(0),
                    Err(e) => {
                        eprintln!("[telemt] Init failed: {}", e);
                        Some(1)
                    }
                }
            } else {
                Some(1)
            }
        }
        Subcommand::Run | Subcommand::Start => None,
    }
}
