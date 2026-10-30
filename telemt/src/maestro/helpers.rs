use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use crate::cli;
use crate::logging::LogCliOptions;

const MAESTRO_COLOR: &str = "\x1b[92m";
const COLOR_RESET: &str = "\x1b[0m";

static MAESTRO_COLORS_ENABLED: AtomicBool = AtomicBool::new(true);

/// Enables or disables ANSI color in direct MAESTRO status lines.
pub(crate) fn set_maestro_colors_enabled(enabled: bool) {
    MAESTRO_COLORS_ENABLED.store(enabled, Ordering::Relaxed);
}

fn format_maestro_line(message: impl AsRef<str>, colors_enabled: bool) -> String {
    if colors_enabled {
        format!("{MAESTRO_COLOR}MAESTRO{COLOR_RESET}: {}", message.as_ref())
    } else {
        format!("MAESTRO: {}", message.as_ref())
    }
}

/// Prints a direct MAESTRO status line outside the tracing subscriber.
pub(crate) fn print_maestro_line(message: impl AsRef<str>) {
    eprintln!(
        "{}",
        format_maestro_line(message, MAESTRO_COLORS_ENABLED.load(Ordering::Relaxed))
    );
}

/// Resolves the config source against startup cwd while retaining symlink components.
pub(crate) fn resolve_runtime_config_path(
    config_path_cli: &str,
    startup_cwd: &Path,
    config_path_explicit: bool,
) -> PathBuf {
    let normalize = |path: PathBuf| {
        let mut normalized = PathBuf::new();
        for component in path.components() {
            match component {
                std::path::Component::CurDir => {}
                std::path::Component::ParentDir => {
                    normalized.pop();
                }
                component => normalized.push(component.as_os_str()),
            }
        }
        normalized
    };

    if config_path_explicit {
        let raw = PathBuf::from(config_path_cli);
        let absolute = if raw.is_absolute() {
            raw
        } else {
            startup_cwd.join(raw)
        };
        return normalize(absolute);
    }

    let etc_telemt = std::path::Path::new("/etc/telemt");
    let candidates = [
        startup_cwd.join("config.toml"),
        startup_cwd.join("telemt.toml"),
        etc_telemt.join("telemt.toml"),
        etc_telemt.join("config.toml"),
    ];
    for candidate in candidates {
        if candidate.is_file() {
            return normalize(candidate);
        }
    }

    startup_cwd.join("config.toml")
}

/// Selects the runtime directory from CLI, startup cwd, and explicit config location.
pub(crate) fn resolve_runtime_base_dir(
    config_path: &Path,
    startup_cwd: &Path,
    config_path_explicit: bool,
    data_path: Option<&Path>,
) -> PathBuf {
    if let Some(path) = data_path {
        return normalize_runtime_dir(path, startup_cwd);
    }

    if startup_cwd != Path::new("/") {
        return normalize_runtime_dir(startup_cwd, startup_cwd);
    }

    if config_path_explicit
        && let Some(parent) = config_path.parent()
        && !parent.as_os_str().is_empty()
    {
        return normalize_runtime_dir(parent, startup_cwd);
    }

    PathBuf::from("/etc/telemt")
}

fn normalize_runtime_dir(path: &Path, startup_cwd: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        startup_cwd.join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                normalized.pop();
            }
            component => normalized.push(component.as_os_str()),
        }
    }
    normalized
}

/// Parsed CLI arguments.
pub(crate) struct CliArgs {
    /// Config source selected by positional arguments.
    pub config_path: String,
    /// Whether the config source was explicitly provided.
    pub config_path_explicit: bool,
    /// Runtime directory override from CLI.
    pub data_path: Option<PathBuf>,
    /// Whether CLI requests minimal logging output.
    pub silent: bool,
    /// Verbosity override from CLI.
    pub log_level: Option<String>,
    /// Logging destination, rotation, and retention overrides.
    pub log_cli_options: LogCliOptions,
}

/// Parses runtime arguments after early daemon and control-command handling.
pub(crate) fn parse_cli() -> CliArgs {
    let mut config_path = "config.toml".to_string();
    let mut config_path_explicit = false;
    let mut data_path: Option<PathBuf> = None;
    let mut silent = false;
    let mut log_level: Option<String> = None;

    let args: Vec<String> = std::env::args().skip(1).collect();

    let log_cli_options = match crate::logging::parse_log_cli_options(&args) {
        Ok(options) => options,
        Err(error) => {
            eprintln!("[telemt] {error}");
            std::process::exit(2);
        }
    };

    // Check for --init first (handled before tokio)
    if let Some(init_opts) = cli::parse_init_args(&args) {
        if let Err(e) = cli::run_init(init_opts) {
            eprintln!("[telemt] Init failed: {}", e);
            std::process::exit(1);
        }
        std::process::exit(0);
    }

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--data-path" => {
                i += 1;
                if i < args.len() {
                    data_path = Some(PathBuf::from(args[i].clone()));
                } else {
                    eprintln!("Missing value for --data-path");
                    std::process::exit(0);
                }
            }
            s if s.starts_with("--data-path=") => {
                data_path = Some(PathBuf::from(
                    s.trim_start_matches("--data-path=").to_string(),
                ));
            }
            "--working-dir" => {
                i += 1;
                if i < args.len() {
                    data_path = Some(PathBuf::from(args[i].clone()));
                } else {
                    eprintln!("Missing value for --working-dir");
                    std::process::exit(0);
                }
            }
            s if s.starts_with("--working-dir=") => {
                data_path = Some(PathBuf::from(
                    s.trim_start_matches("--working-dir=").to_string(),
                ));
            }
            "--silent" | "-s" => {
                silent = true;
            }
            "--log-level" => {
                i += 1;
                if i < args.len() {
                    log_level = Some(args[i].clone());
                }
            }
            s if s.starts_with("--log-level=") => {
                log_level = Some(s.trim_start_matches("--log-level=").to_string());
            }
            "--log-file" | "--log-file-daily" => {
                i += 1;
            }
            s if s.starts_with("--log-file=") || s.starts_with("--log-file-daily=") => {}
            "--log-rotation"
            | "--log-max-size-bytes"
            | "--log-max-files"
            | "--log-max-age-secs" => {
                i += 1;
            }
            s if s.starts_with("--log-rotation=")
                || s.starts_with("--log-max-size-bytes=")
                || s.starts_with("--log-max-files=")
                || s.starts_with("--log-max-age-secs=") => {}
            "--syslog" => {}
            "--help" | "-h" => {
                print_help();
                std::process::exit(0);
            }
            "--version" | "-V" => {
                println!("telemt {}", env!("CARGO_PKG_VERSION"));
                std::process::exit(0);
            }
            // Skip daemon-related flags (already parsed)
            "--daemon" | "-d" | "--foreground" | "-f" => {}
            #[cfg(unix)]
            "--strict-runtime-paths" => {}
            s if s.starts_with("--pid-file") => {
                if !s.contains('=') {
                    // Skip the pid-file value consumed by daemon argument parsing.
                    i += 1;
                }
            }
            s if s.starts_with("--run-as-user") => {
                if !s.contains('=') {
                    i += 1;
                }
            }
            s if s.starts_with("--run-as-group") => {
                if !s.contains('=') {
                    i += 1;
                }
            }
            s if !s.starts_with('-') => {
                if !matches!(s, "run" | "start" | "stop" | "reload" | "status") {
                    config_path = s.to_string();
                    config_path_explicit = true;
                }
            }
            other => {
                eprintln!("Unknown option: {}", other);
            }
        }
        i += 1;
    }

    CliArgs {
        config_path,
        config_path_explicit,
        data_path,
        silent,
        log_level,
        log_cli_options,
    }
}

fn print_help() {
    eprintln!("Usage: telemt [COMMAND] [OPTIONS] [config.toml]");
    eprintln!();
    eprintln!("Commands:");
    eprintln!("  run                     Run in foreground (default if no command given)");
    #[cfg(unix)]
    {
        eprintln!("  start                   Start as background daemon");
        eprintln!("  stop                    Stop a running daemon");
        eprintln!("  reload                  Reload configuration (send SIGHUP)");
        eprintln!("  status                  Check if daemon is running");
    }
    eprintln!();
    eprintln!("Options:");
    eprintln!(
        "  --data-path <DIR>       Set data directory (absolute path; overrides config value)"
    );
    eprintln!("  --working-dir <DIR>     Alias for --data-path");
    eprintln!("  --silent, -s            Suppress info logs");
    eprintln!("  --log-level <LEVEL>     debug|verbose|normal|silent");
    eprintln!("  --help, -h              Show this help");
    eprintln!("  --version, -V           Show version");
    eprintln!();
    eprintln!("Logging options:");
    eprintln!("  --log-file <PATH>       Log to file (default: stderr)");
    eprintln!("  --log-file-daily <PATH> Log to file with daily rotation");
    eprintln!("  --log-rotation <MODE>   never|minutely|hourly|daily|weekly");
    eprintln!("  --log-max-size-bytes N  Rotate file logs when active file exceeds N bytes");
    eprintln!("  --log-max-files N       Keep at most N matching file logs (0 disables)");
    eprintln!("  --log-max-age-secs N    Remove rotated file logs older than N seconds");
    #[cfg(unix)]
    eprintln!("  --syslog                Log to syslog (Unix only)");
    eprintln!();
    #[cfg(unix)]
    {
        eprintln!("Daemon options (Unix only):");
        eprintln!("  --daemon, -d            Fork to background (daemonize)");
        eprintln!("  --foreground, -f        Explicit foreground mode (for systemd)");
        eprintln!("  --pid-file <PATH>       PID file path (default: /var/run/telemt.pid)");
        eprintln!(
            "  --strict-runtime-paths  Require trusted, symlink-free PID/log parents (default: off)"
        );
        eprintln!(
            "                          Applies to run/start/stop/reload/status; parent symlinks and"
        );
        eprintln!(
            "                          writable directories are allowed when this flag is absent"
        );
        eprintln!("  --run-as-user <USER>    Drop privileges to this user after binding");
        eprintln!("  --run-as-group <GROUP>  Drop privileges to this group after binding");
        eprintln!("  --working-dir <DIR>     Working directory for daemon mode");
        eprintln!();
    }
    eprintln!("Setup (fire-and-forget):");
    eprintln!("  --init                  Generate config, install systemd service, start");
    eprintln!("    --port <PORT>          Listen port (default: 443)");
    eprintln!("    --domain <DOMAIN>      TLS domain for masking (default: www.google.com)");
    eprintln!("    --secret <HEX>         32-char hex secret (auto-generated if omitted)");
    eprintln!("    --user <NAME>          Username (default: user)");
    eprintln!("    --config-dir <DIR>     Config directory (default: /etc/telemt)");
    eprintln!("    --no-start             Don't start the service after install");
    #[cfg(unix)]
    {
        eprintln!();
        eprintln!("Examples:");
        eprintln!("  telemt config.toml                    Run in foreground");
        eprintln!("  telemt start config.toml              Start as daemon");
        eprintln!("  telemt start --pid-file /tmp/t.pid    Start with custom PID file");
        eprintln!("  telemt stop                           Stop daemon");
        eprintln!("  telemt reload                         Reload configuration");
        eprintln!("  telemt status                         Check daemon status");
    }
}

// Runtime reporting and startup snapshot helpers.
mod runtime;

pub(crate) use runtime::*;

#[cfg(test)]
mod tests;
