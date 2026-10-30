use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum UnknownSniAction {
    #[default]
    Drop,
    Mask,
    Accept,
    /// Reject the TLS handshake by sending a fatal `unrecognized_name` alert
    /// (RFC 6066, AlertDescription = 112) before closing the connection.
    /// Mimics nginx `ssl_reject_handshake on;` behavior on the default vhost —
    /// the wire response indistinguishable from a stock modern web server
    /// that simply does not host the requested name.
    #[serde(rename = "reject_handshake")]
    RejectHandshake,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsFetchProfile {
    ModernChromeLike,
    ModernFirefoxLike,
    CompatTls12,
    LegacyMinimal,
}

impl TlsFetchProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            TlsFetchProfile::ModernChromeLike => "modern_chrome_like",
            TlsFetchProfile::ModernFirefoxLike => "modern_firefox_like",
            TlsFetchProfile::CompatTls12 => "compat_tls12",
            TlsFetchProfile::LegacyMinimal => "legacy_minimal",
        }
    }
}

fn default_tls_fetch_profiles() -> Vec<TlsFetchProfile> {
    vec![
        TlsFetchProfile::ModernChromeLike,
        TlsFetchProfile::ModernFirefoxLike,
        TlsFetchProfile::CompatTls12,
        TlsFetchProfile::LegacyMinimal,
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsFetchConfig {
    /// Ordered list of ClientHello profiles used for adaptive fallback.
    #[serde(default = "default_tls_fetch_profiles")]
    pub profiles: Vec<TlsFetchProfile>,

    /// When true and upstream route is configured, TLS fetch fails closed on
    /// upstream connect errors and does not fallback to direct TCP.
    #[serde(default = "default_tls_fetch_strict_route")]
    pub strict_route: bool,

    /// Timeout per one profile attempt in milliseconds.
    #[serde(default = "default_tls_fetch_attempt_timeout_ms")]
    pub attempt_timeout_ms: u64,

    /// Total wall-clock budget in milliseconds across all profile attempts.
    #[serde(default = "default_tls_fetch_total_budget_ms")]
    pub total_budget_ms: u64,

    /// Adds GREASE-style values into selected ClientHello extensions.
    #[serde(default)]
    pub grease_enabled: bool,

    /// Produces deterministic ClientHello randomness for debugging/tests.
    #[serde(default)]
    pub deterministic: bool,

    /// TTL for winner-profile cache entries in seconds.
    /// Set to 0 to disable profile cache.
    #[serde(default = "default_tls_fetch_profile_cache_ttl_secs")]
    pub profile_cache_ttl_secs: u64,
}

impl Default for TlsFetchConfig {
    fn default() -> Self {
        Self {
            profiles: default_tls_fetch_profiles(),
            strict_route: default_tls_fetch_strict_route(),
            attempt_timeout_ms: default_tls_fetch_attempt_timeout_ms(),
            total_budget_ms: default_tls_fetch_total_budget_ms(),
            grease_enabled: false,
            deterministic: false,
            profile_cache_ttl_secs: default_tls_fetch_profile_cache_ttl_secs(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ExclusiveMaskTarget {
    /// Target host after IDNA/IP normalization.
    pub host: String,
    /// TCP port for the selected target.
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AntiCensorshipConfig {
    #[serde(default = "default_tls_domain")]
    pub tls_domain: String,

    /// Additional TLS domains for generating multiple proxy links.
    #[serde(default)]
    pub tls_domains: Vec<String>,

    /// Policy for TLS ClientHello with unknown (non-configured) SNI.
    #[serde(default)]
    pub unknown_sni_action: UnknownSniAction,

    /// Upstream scope used for TLS front metadata fetches.
    /// Empty value keeps default upstream routing behavior.
    #[serde(default = "default_tls_fetch_scope")]
    pub tls_fetch_scope: String,

    /// Fetch strategy for TLS front metadata bootstrap and periodic refresh.
    #[serde(default)]
    pub tls_fetch: TlsFetchConfig,

    #[serde(default = "default_true")]
    pub mask: bool,

    /// Use the ClientHello SNI as the mask TCP target for configured TLS domains.
    #[serde(default = "default_true")]
    pub mask_dynamic: bool,

    #[serde(default)]
    pub mask_host: Option<String>,

    #[serde(default = "default_mask_port")]
    pub mask_port: u16,

    /// Per-SNI TCP mask targets. Keys are SNI domains, values are `host:port`.
    #[serde(default)]
    pub exclusive_mask: HashMap<String, String>,

    /// Parsed runtime cache for per-SNI TCP mask targets.
    #[serde(skip)]
    pub exclusive_mask_targets: HashMap<String, ExclusiveMaskTarget>,

    #[serde(default)]
    pub mask_unix_sock: Option<String>,

    #[serde(default = "default_fake_cert_len")]
    pub fake_cert_len: usize,

    /// Enable TLS certificate emulation using cached real certificates.
    #[serde(default = "default_true")]
    pub tls_emulation: bool,

    /// Directory to store TLS front cache (on disk).
    #[serde(default = "default_tls_front_dir")]
    pub tls_front_dir: String,

    /// Minimum server_hello delay in milliseconds (anti-fingerprint).
    #[serde(default = "default_server_hello_delay_min_ms")]
    pub server_hello_delay_min_ms: u64,

    /// Maximum server_hello delay in milliseconds.
    #[serde(default = "default_server_hello_delay_max_ms")]
    pub server_hello_delay_max_ms: u64,

    /// Number of NewSessionTicket messages to emit post-handshake.
    #[serde(default = "default_tls_new_session_tickets")]
    pub tls_new_session_tickets: u8,

    /// Enable compact ServerHello payload mode.
    /// When false, FakeTLS always uses full ServerHello payload behavior.
    /// When true, compact certificate payload mode can be used by TTL policy.
    #[serde(default = "default_serverhello_compact")]
    pub serverhello_compact: bool,

    /// TTL in seconds for sending full certificate payload per client IP.
    /// First client connection per (SNI domain, client IP) gets full cert payload.
    /// Subsequent handshakes within TTL use compact cert metadata payload.
    /// Applied only when `serverhello_compact` is enabled.
    #[serde(default = "default_tls_full_cert_ttl_secs")]
    pub tls_full_cert_ttl_secs: u64,

    /// Enforce ALPN echo of client preference.
    #[serde(default = "default_alpn_enforce")]
    pub alpn_enforce: bool,

    /// Send PROXY protocol header when connecting to mask_host.
    /// 0 = disabled, 1 = v1 (text), 2 = v2 (binary).
    /// Allows the backend to see the real client IP.
    #[serde(default)]
    pub mask_proxy_protocol: u8,

    /// Enable shape-channel hardening on mask backend path by padding
    /// client->mask stream tail to configured buckets on stream end.
    #[serde(default = "default_mask_shape_hardening")]
    pub mask_shape_hardening: bool,

    /// Opt-in aggressive shape hardening mode.
    /// When enabled, masking may shape some backend-silent timeout paths and
    /// enforces strictly positive above-cap blur when blur is enabled.
    #[serde(default = "default_mask_shape_hardening_aggressive_mode")]
    pub mask_shape_hardening_aggressive_mode: bool,

    /// Minimum bucket size for mask shape hardening padding.
    #[serde(default = "default_mask_shape_bucket_floor_bytes")]
    pub mask_shape_bucket_floor_bytes: usize,

    /// Maximum bucket size for mask shape hardening padding.
    #[serde(default = "default_mask_shape_bucket_cap_bytes")]
    pub mask_shape_bucket_cap_bytes: usize,

    /// Add bounded random tail bytes even when total bytes already exceed
    /// mask_shape_bucket_cap_bytes.
    #[serde(default = "default_mask_shape_above_cap_blur")]
    pub mask_shape_above_cap_blur: bool,

    /// Maximum random bytes appended above cap when above-cap blur is enabled.
    #[serde(default = "default_mask_shape_above_cap_blur_max_bytes")]
    pub mask_shape_above_cap_blur_max_bytes: usize,

    /// Maximum bytes relayed per direction on unauthenticated masking fallback paths.
    /// Set to 0 to disable byte cap (unlimited within relay/idle timeouts).
    #[serde(default = "default_mask_relay_max_bytes")]
    pub mask_relay_max_bytes: usize,

    /// Wall-clock cap for the full masking relay on non-MTProto fallback paths.
    /// Raise when the mask target is a long-lived service (e.g. WebSocket).
    /// Default: 60 000 ms (60 s).
    #[serde(default = "default_mask_relay_timeout_ms")]
    pub mask_relay_timeout_ms: u64,

    /// Per-read idle timeout on masking relay and drain paths.
    /// Limits resource consumption by slow-loris attacks and port scanners.
    /// A read call stalling beyond this is treated as an abandoned connection.
    /// Default: 5 000 ms (5 s).
    #[serde(default = "default_mask_relay_idle_timeout_ms")]
    pub mask_relay_idle_timeout_ms: u64,

    /// Prefetch timeout (ms) for extending fragmented masking classifier window.
    #[serde(default = "default_mask_classifier_prefetch_timeout_ms")]
    pub mask_classifier_prefetch_timeout_ms: u64,

    /// Enable outcome-time normalization envelope for masking fallback.
    #[serde(default = "default_mask_timing_normalization_enabled")]
    pub mask_timing_normalization_enabled: bool,

    /// Lower bound (ms) for masking outcome timing envelope.
    #[serde(default = "default_mask_timing_normalization_floor_ms")]
    pub mask_timing_normalization_floor_ms: u64,

    /// Upper bound (ms) for masking outcome timing envelope.
    #[serde(default = "default_mask_timing_normalization_ceiling_ms")]
    pub mask_timing_normalization_ceiling_ms: u64,
}

impl Default for AntiCensorshipConfig {
    fn default() -> Self {
        Self {
            tls_domain: default_tls_domain(),
            tls_domains: Vec::new(),
            unknown_sni_action: UnknownSniAction::Drop,
            tls_fetch_scope: default_tls_fetch_scope(),
            tls_fetch: TlsFetchConfig::default(),
            mask: default_true(),
            mask_dynamic: default_true(),
            mask_host: None,
            mask_port: default_mask_port(),
            exclusive_mask: HashMap::new(),
            exclusive_mask_targets: HashMap::new(),
            mask_unix_sock: None,
            fake_cert_len: default_fake_cert_len(),
            tls_emulation: true,
            tls_front_dir: default_tls_front_dir(),
            server_hello_delay_min_ms: default_server_hello_delay_min_ms(),
            server_hello_delay_max_ms: default_server_hello_delay_max_ms(),
            tls_new_session_tickets: default_tls_new_session_tickets(),
            serverhello_compact: default_serverhello_compact(),
            tls_full_cert_ttl_secs: default_tls_full_cert_ttl_secs(),
            alpn_enforce: default_alpn_enforce(),
            mask_proxy_protocol: 0,
            mask_shape_hardening: default_mask_shape_hardening(),
            mask_shape_hardening_aggressive_mode: default_mask_shape_hardening_aggressive_mode(),
            mask_shape_bucket_floor_bytes: default_mask_shape_bucket_floor_bytes(),
            mask_shape_bucket_cap_bytes: default_mask_shape_bucket_cap_bytes(),
            mask_shape_above_cap_blur: default_mask_shape_above_cap_blur(),
            mask_shape_above_cap_blur_max_bytes: default_mask_shape_above_cap_blur_max_bytes(),
            mask_relay_max_bytes: default_mask_relay_max_bytes(),
            mask_relay_timeout_ms: default_mask_relay_timeout_ms(),
            mask_relay_idle_timeout_ms: default_mask_relay_idle_timeout_ms(),
            mask_classifier_prefetch_timeout_ms: default_mask_classifier_prefetch_timeout_ms(),
            mask_timing_normalization_enabled: default_mask_timing_normalization_enabled(),
            mask_timing_normalization_floor_ms: default_mask_timing_normalization_floor_ms(),
            mask_timing_normalization_ceiling_ms: default_mask_timing_normalization_ceiling_ms(),
        }
    }
}
