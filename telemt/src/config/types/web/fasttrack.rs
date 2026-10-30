use serde::{Deserialize, Serialize};

/// Capability-scan policy for structurally impossible WEB bridge requests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WebDecoyFastTrackMode {
    /// Preserve the legacy full scan without collecting fast-track decisions.
    #[default]
    Off,
    /// Record eligible requests while preserving the legacy full scan.
    Shadow,
    /// Skip the scan only when the public request shape cannot open a bridge.
    Enforce,
}

impl WebDecoyFastTrackMode {
    /// Complete fixed mode set in stable API and metric order.
    pub const ALL: [Self; 3] = [Self::Off, Self::Shadow, Self::Enforce];

    /// Returns the stable serialized mode token.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Shadow => "shadow",
            Self::Enforce => "enforce",
        }
    }
}
