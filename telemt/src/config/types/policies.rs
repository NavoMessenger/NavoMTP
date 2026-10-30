use super::*;

/// Middle-End telemetry verbosity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum MeTelemetryLevel {
    #[default]
    Normal,
    Silent,
    Debug,
}

impl MeTelemetryLevel {
    pub fn as_u8(self) -> u8 {
        match self {
            MeTelemetryLevel::Silent => 0,
            MeTelemetryLevel::Normal => 1,
            MeTelemetryLevel::Debug => 2,
        }
    }

    pub fn from_u8(raw: u8) -> Self {
        match raw {
            0 => MeTelemetryLevel::Silent,
            2 => MeTelemetryLevel::Debug,
            _ => MeTelemetryLevel::Normal,
        }
    }

    pub fn allows_normal(self) -> bool {
        !matches!(self, MeTelemetryLevel::Silent)
    }

    pub fn allows_debug(self) -> bool {
        matches!(self, MeTelemetryLevel::Debug)
    }
}

impl std::fmt::Display for MeTelemetryLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MeTelemetryLevel::Silent => write!(f, "silent"),
            MeTelemetryLevel::Normal => write!(f, "normal"),
            MeTelemetryLevel::Debug => write!(f, "debug"),
        }
    }
}

/// Middle-End SOCKS KDF fallback policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum MeSocksKdfPolicy {
    #[default]
    Strict,
    Compat,
}

impl MeSocksKdfPolicy {
    pub fn as_u8(self) -> u8 {
        match self {
            MeSocksKdfPolicy::Strict => 0,
            MeSocksKdfPolicy::Compat => 1,
        }
    }

    pub fn from_u8(raw: u8) -> Self {
        match raw {
            1 => MeSocksKdfPolicy::Compat,
            _ => MeSocksKdfPolicy::Strict,
        }
    }
}

/// Stale ME writer bind policy during drain window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum MeBindStaleMode {
    #[default]
    Never,
    Ttl,
    Always,
}

impl MeBindStaleMode {
    pub fn as_u8(self) -> u8 {
        match self {
            MeBindStaleMode::Never => 0,
            MeBindStaleMode::Ttl => 1,
            MeBindStaleMode::Always => 2,
        }
    }

    pub fn from_u8(raw: u8) -> Self {
        match raw {
            0 => MeBindStaleMode::Never,
            2 => MeBindStaleMode::Always,
            _ => MeBindStaleMode::Ttl,
        }
    }
}

/// RST-on-close mode for accepted client sockets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum RstOnCloseMode {
    /// Normal FIN on all closes (default, no behaviour change).
    #[default]
    Off,
    /// SO_LINGER(0) on accept; cleared after successful auth.
    /// Pre-handshake failures (scanners, DPI, timeouts) send RST;
    /// authenticated relay sessions close gracefully with FIN.
    Errors,
    /// SO_LINGER(0) on accept, never cleared — all closes send RST.
    Always,
}

/// Middle-End writer floor policy mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum MeFloorMode {
    Static,
    #[default]
    Adaptive,
}

impl MeFloorMode {
    pub fn as_u8(self) -> u8 {
        match self {
            MeFloorMode::Static => 0,
            MeFloorMode::Adaptive => 1,
        }
    }

    pub fn from_u8(raw: u8) -> Self {
        match raw {
            1 => MeFloorMode::Adaptive,
            _ => MeFloorMode::Static,
        }
    }
}

/// Middle-End route behavior when no writer is immediately available.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MeRouteNoWriterMode {
    AsyncRecoveryFailfast,
    InlineRecoveryLegacy,
    #[default]
    HybridAsyncPersistent,
}

impl MeRouteNoWriterMode {
    pub fn as_u8(self) -> u8 {
        match self {
            MeRouteNoWriterMode::AsyncRecoveryFailfast => 0,
            MeRouteNoWriterMode::InlineRecoveryLegacy => 1,
            MeRouteNoWriterMode::HybridAsyncPersistent => 2,
        }
    }

    pub fn from_u8(raw: u8) -> Self {
        match raw {
            0 => MeRouteNoWriterMode::AsyncRecoveryFailfast,
            1 => MeRouteNoWriterMode::InlineRecoveryLegacy,
            2 => MeRouteNoWriterMode::HybridAsyncPersistent,
            _ => MeRouteNoWriterMode::HybridAsyncPersistent,
        }
    }
}

/// Middle-End writer selection mode for new client bindings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum MeWriterPickMode {
    SortedRr,
    #[default]
    P2c,
}

impl MeWriterPickMode {
    pub fn as_u8(self) -> u8 {
        match self {
            MeWriterPickMode::SortedRr => 0,
            MeWriterPickMode::P2c => 1,
        }
    }

    pub fn from_u8(raw: u8) -> Self {
        match raw {
            0 => MeWriterPickMode::SortedRr,
            1 => MeWriterPickMode::P2c,
            _ => MeWriterPickMode::P2c,
        }
    }
}

/// Per-user unique source IP limit mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum UserMaxUniqueIpsMode {
    /// Count only currently active source IPs.
    #[default]
    ActiveWindow,
    /// Count source IPs seen within the recent time window.
    TimeWindow,
    /// Enforce both active and recent-window limits at the same time.
    Combined,
}

/// Telemetry controls for hot-path counters and ME diagnostics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryConfig {
    #[serde(default = "default_true")]
    pub core_enabled: bool,
    #[serde(default = "default_true")]
    pub user_enabled: bool,
    #[serde(default)]
    pub me_level: MeTelemetryLevel,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            core_enabled: default_true(),
            user_enabled: default_true(),
            me_level: MeTelemetryLevel::Normal,
        }
    }
}
