use super::*;

/// Logging verbosity level.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// All messages including trace (trace + debug + info + warn + error).
    Debug,
    /// Detailed operational logs (debug + info + warn + error).
    Verbose,
    /// Standard operational logs (info + warn + error).
    #[default]
    Normal,
    /// Minimal output: only warnings and errors (warn + error).
    /// Proxy links may still be emitted through their dedicated target.
    Silent,
}

impl LogLevel {
    /// Convert to tracing EnvFilter directive string.
    pub fn to_filter_str(&self) -> &'static str {
        match self {
            LogLevel::Debug => "trace",
            LogLevel::Verbose => "debug",
            LogLevel::Normal => "info",
            LogLevel::Silent => "warn",
        }
    }

    /// Parse from a loose string (CLI argument).
    pub fn from_str_loose(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "debug" | "trace" => LogLevel::Debug,
            "verbose" => LogLevel::Verbose,
            "normal" | "info" => LogLevel::Normal,
            "silent" | "quiet" | "error" | "warn" => LogLevel::Silent,
            _ => LogLevel::Normal,
        }
    }
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Debug => write!(f, "debug"),
            LogLevel::Verbose => write!(f, "verbose"),
            LogLevel::Normal => write!(f, "normal"),
            LogLevel::Silent => write!(f, "silent"),
        }
    }
}

/// Logging output destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LoggingDestination {
    /// Write logs to stderr.
    #[default]
    Stderr,
    /// Write logs to syslog on Unix platforms.
    Syslog,
    /// Write logs to a file.
    File,
}

/// Time-based log rotation interval for file logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum LogRotation {
    /// Do not rotate logs by time.
    #[default]
    Never,
    /// Rotate once per minute.
    Minutely,
    /// Rotate once per hour.
    Hourly,
    /// Rotate once per day.
    Daily,
    /// Rotate once per week.
    Weekly,
}

impl LogRotation {
    /// Parse a CLI rotation value.
    pub fn from_cli_arg(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "never" | "none" | "off" => Some(Self::Never),
            "minutely" | "minute" => Some(Self::Minutely),
            "hourly" | "hour" => Some(Self::Hourly),
            "daily" | "day" => Some(Self::Daily),
            "weekly" | "week" => Some(Self::Weekly),
            _ => None,
        }
    }
}

/// File logging and retention settings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Effective logging destination.
    #[serde(default)]
    pub destination: LoggingDestination,
    /// File path used when `destination = "file"`.
    #[serde(default)]
    pub path: Option<String>,
    /// Time rotation interval for file logs.
    #[serde(default)]
    pub rotation: LogRotation,
    /// Maximum active log file size before rotating. `0` disables size rotation.
    #[serde(default)]
    pub max_size_bytes: u64,
    /// Maximum number of matching log files to keep. `0` disables count retention.
    #[serde(default)]
    pub max_files: usize,
    /// Maximum age for rotated log files in seconds. `0` disables age retention.
    #[serde(default)]
    pub max_age_secs: u64,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            destination: LoggingDestination::Stderr,
            path: None,
            rotation: LogRotation::Never,
            max_size_bytes: 0,
            max_files: 0,
            max_age_secs: 0,
        }
    }
}
