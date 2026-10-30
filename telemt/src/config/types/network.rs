use super::*;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyModes {
    #[serde(default)]
    pub classic: bool,
    #[serde(default)]
    pub secure: bool,
    #[serde(default = "default_true")]
    pub tls: bool,
}

impl Default for ProxyModes {
    fn default() -> Self {
        Self {
            classic: false,
            secure: false,
            tls: default_true(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    #[serde(default = "default_true")]
    pub ipv4: bool,

    /// None = auto-detect IPv6 availability.
    #[serde(default = "default_network_ipv6")]
    pub ipv6: Option<bool>,

    /// 4 or 6.
    #[serde(default = "default_prefer_4")]
    pub prefer: u8,

    #[serde(default)]
    pub multipath: bool,

    /// Global switch for STUN probing.
    /// When false, STUN is fully disabled and only non-STUN detection remains.
    #[serde(default = "default_true")]
    pub stun_use: bool,

    /// STUN servers list for public IP discovery.
    #[serde(default = "default_stun_servers")]
    pub stun_servers: Vec<String>,

    /// Enable TCP STUN fallback when UDP is blocked.
    #[serde(default = "default_stun_tcp_fallback")]
    pub stun_tcp_fallback: bool,

    /// HTTP-based public IP detection endpoints (fallback after STUN).
    #[serde(default = "default_http_ip_detect_urls")]
    pub http_ip_detect_urls: Vec<String>,

    /// Cache file path for detected public IP.
    #[serde(default = "default_cache_public_ip_path")]
    pub cache_public_ip_path: String,

    /// Runtime DNS overrides in `host:port:ip` format.
    /// IPv6 IP values must be bracketed: `[2001:db8::1]`.
    #[serde(default)]
    pub dns_overrides: Vec<String>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            ipv4: default_true(),
            ipv6: default_network_ipv6(),
            prefer: default_prefer_4(),
            multipath: false,
            stun_use: default_true(),
            stun_servers: default_stun_servers(),
            stun_tcp_fallback: default_stun_tcp_fallback(),
            http_ip_detect_urls: default_http_ip_detect_urls(),
            cache_public_ip_path: default_cache_public_ip_path(),
            dns_overrides: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum UpstreamType {
    Direct {
        #[serde(default)]
        interface: Option<String>,
        #[serde(default)]
        bind_addresses: Option<Vec<String>>,
        /// Linux-only hard interface pinning via `SO_BINDTODEVICE`.
        /// Optional alias: `force_bind`.
        #[serde(default, alias = "force_bind")]
        bindtodevice: Option<String>,
    },
    Socks4 {
        address: String,
        #[serde(default)]
        interface: Option<String>,
        #[serde(default)]
        user_id: Option<String>,
    },
    Socks5 {
        address: String,
        #[serde(default)]
        interface: Option<String>,
        #[serde(default)]
        username: Option<String>,
        #[serde(default)]
        password: Option<String>,
    },
    Shadowsocks {
        url: String,
        #[serde(default)]
        interface: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamConfig {
    #[serde(flatten)]
    pub upstream_type: UpstreamType,
    #[serde(default = "default_weight")]
    pub weight: u16,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub scopes: String,
    #[serde(skip)]
    pub selected_scope: String,
    /// Allow IPv4 DC targets for this upstream.
    /// `None` means auto-detect from runtime connectivity state.
    #[serde(default)]
    pub ipv4: Option<bool>,
    /// Allow IPv6 DC targets for this upstream.
    /// `None` means auto-detect from runtime connectivity state.
    #[serde(default)]
    pub ipv6: Option<bool>,
    /// Per-upstream IP family preference for Telegram DC targets.
    /// `None` inherits the effective global `[network].prefer` decision.
    #[serde(default)]
    pub prefer: Option<u8>,
}

impl UpstreamConfig {
    pub fn prefer_ipv6(&self, default_prefer_ipv6: bool) -> bool {
        match self.prefer {
            Some(6) => true,
            Some(4) => false,
            _ => default_prefer_ipv6,
        }
    }
}
