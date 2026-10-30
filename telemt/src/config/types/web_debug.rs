use serde::{Deserialize, Serialize};

use super::web::WebLimitsConfig;

/// Request and response body retention policy for WEB debugging.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WebDebugBodyCapture {
    /// Omits body snapshots entirely.
    Off,
    /// Retains body lengths and completion state without payload bytes.
    #[default]
    Metadata,
    /// Retains a bounded prefix of each body.
    Prefix,
    /// Retains complete bounded carrier bodies and bounded decoy prefixes.
    Full,
}

/// Hot-reloadable WEB server-side debugging policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebDebugConfig {
    /// Enables process-owned WEB debug collection.
    #[serde(default)]
    pub enabled: bool,
    /// Enables generated-bridge diagnostic reports over the HTTPS sideband.
    #[serde(default)]
    pub sideband: bool,
    /// Records typed bridge, session, stream, handshake, and relay events.
    #[serde(default = "default_true")]
    pub capture_lifecycle: bool,
    /// Retains allowlisted header values and names of all other headers.
    #[serde(default = "default_true")]
    pub capture_headers: bool,
    /// Retains request service and body-consumption timing points.
    #[serde(default = "default_true")]
    pub capture_timings: bool,
    /// Parses carrier bodies into bounded frame metadata.
    #[serde(default = "default_true")]
    pub capture_frames: bool,
    /// Controls request and response body byte retention.
    #[serde(default)]
    pub body_capture: WebDebugBodyCapture,
    /// Maximum retained body prefix for recognized WEB requests.
    #[serde(default = "default_body_prefix_bytes")]
    pub body_prefix_bytes: usize,
    /// Maximum retained body prefix for ordinary decoy traffic.
    #[serde(default = "default_decoy_body_prefix_bytes")]
    pub decoy_body_prefix_bytes: usize,
    /// Default observation window presented by the status page.
    #[serde(default = "default_window_secs")]
    pub default_window_secs: u64,
    /// Largest observation window accepted by the status page.
    #[serde(default = "default_max_window_secs")]
    pub max_window_secs: u64,
}

impl Default for WebDebugConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            sideband: false,
            capture_lifecycle: true,
            capture_headers: true,
            capture_timings: true,
            capture_frames: true,
            body_capture: WebDebugBodyCapture::Metadata,
            body_prefix_bytes: default_body_prefix_bytes(),
            decoy_body_prefix_bytes: default_decoy_body_prefix_bytes(),
            default_window_secs: default_window_secs(),
            max_window_secs: default_max_window_secs(),
        }
    }
}

impl WebDebugConfig {
    /// Returns whether newly issued bridges may report diagnostic lifecycle events.
    pub(crate) const fn bridge_diagnostics_enabled(&self) -> bool {
        self.enabled && self.sideband && self.capture_lifecycle
    }
}

fn default_true() -> bool {
    true
}

fn default_body_prefix_bytes() -> usize {
    4096
}

fn default_decoy_body_prefix_bytes() -> usize {
    4096
}

fn default_window_secs() -> u64 {
    180
}

fn default_max_window_secs() -> u64 {
    3600
}

/// Checks whether a hot debug policy fits restart-frozen process capacities.
pub(crate) fn web_debug_fits_limits(policy: &WebDebugConfig, limits: &WebLimitsConfig) -> bool {
    policy.body_prefix_bytes <= limits.max_body_bytes
        && policy.body_prefix_bytes <= limits.debug_bytes_global
        && policy.decoy_body_prefix_bytes <= limits.debug_bytes_global
}
