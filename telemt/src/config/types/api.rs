use super::*;

/// Control-plane API settings.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApiConfig {
    /// Enable or disable REST API.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Listen address for API in `IP:PORT` format.
    #[serde(default = "default_api_listen")]
    pub listen: String,

    /// CIDR whitelist allowed to access API.
    #[serde(default = "default_api_whitelist")]
    pub whitelist: Vec<IpNetwork>,

    /// Behavior for requests from source IPs outside `whitelist`.
    /// - `api`: return structured API forbidden response.
    /// - `200`: return `200 OK` with an empty body.
    /// - `drop`: close the connection without HTTP response.
    #[serde(default)]
    pub gray_action: ApiGrayAction,

    /// Optional static value for `Authorization` header validation.
    /// Empty string disables header auth.
    #[serde(default)]
    pub auth_header: String,

    /// Maximum accepted HTTP request body size in bytes.
    #[serde(default = "default_api_request_body_limit_bytes")]
    pub request_body_limit_bytes: usize,

    /// Enable runtime snapshots that require read-lock aggregation on API request path.
    #[serde(default = "default_api_minimal_runtime_enabled")]
    pub minimal_runtime_enabled: bool,

    /// Cache TTL for minimal runtime snapshots in milliseconds (0 disables caching).
    #[serde(default = "default_api_minimal_runtime_cache_ttl_ms")]
    pub minimal_runtime_cache_ttl_ms: u64,

    /// Enables runtime edge endpoints with optional cached aggregation.
    #[serde(default = "default_api_runtime_edge_enabled")]
    pub runtime_edge_enabled: bool,

    /// Cache TTL for runtime edge aggregation payloads in milliseconds.
    #[serde(default = "default_api_runtime_edge_cache_ttl_ms")]
    pub runtime_edge_cache_ttl_ms: u64,

    /// Top-N limit for edge connection leaderboard payloads.
    #[serde(default = "default_api_runtime_edge_top_n")]
    pub runtime_edge_top_n: usize,

    /// Ring-buffer capacity for runtime edge control-plane events.
    #[serde(default = "default_api_runtime_edge_events_capacity")]
    pub runtime_edge_events_capacity: usize,

    /// Read-only mode: mutating endpoints are rejected.
    #[serde(default)]
    pub read_only: bool,
}

impl Default for ApiConfig {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            listen: default_api_listen(),
            whitelist: default_api_whitelist(),
            gray_action: ApiGrayAction::default(),
            auth_header: String::new(),
            request_body_limit_bytes: default_api_request_body_limit_bytes(),
            minimal_runtime_enabled: default_api_minimal_runtime_enabled(),
            minimal_runtime_cache_ttl_ms: default_api_minimal_runtime_cache_ttl_ms(),
            runtime_edge_enabled: default_api_runtime_edge_enabled(),
            runtime_edge_cache_ttl_ms: default_api_runtime_edge_cache_ttl_ms(),
            runtime_edge_top_n: default_api_runtime_edge_top_n(),
            runtime_edge_events_capacity: default_api_runtime_edge_events_capacity(),
            read_only: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ApiGrayAction {
    /// Preserve current API behavior for denied source IPs.
    Api,
    /// Mimic a plain web endpoint by returning `200 OK` with an empty body.
    #[serde(rename = "200")]
    Ok200,
    /// Drop connection without HTTP response for denied source IPs.
    #[default]
    Drop,
}
