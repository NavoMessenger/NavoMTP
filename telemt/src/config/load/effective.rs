use super::*;

/// Normalizes source policy and authentication data before external decoy preparation.
pub(super) fn apply(config: &mut ProxyConfig) -> Result<()> {
    // Normalize optional TLS fetch scope: whitespace-only values disable scoped routing.
    config.censorship.tls_fetch_scope = config.censorship.tls_fetch_scope.trim().to_string();

    if config.censorship.tls_fetch.profiles.is_empty() {
        config.censorship.tls_fetch.profiles = TlsFetchConfig::default().profiles;
    } else {
        let mut seen = HashSet::new();
        config
            .censorship
            .tls_fetch
            .profiles
            .retain(|profile| seen.insert(*profile));
    }

    if config.censorship.tls_fetch.attempt_timeout_ms == 0 {
        return Err(ProxyError::Config(
            "censorship.tls_fetch.attempt_timeout_ms must be > 0".to_string(),
        ));
    }
    if config.censorship.tls_fetch.total_budget_ms == 0 {
        return Err(ProxyError::Config(
            "censorship.tls_fetch.total_budget_ms must be > 0".to_string(),
        ));
    }

    // Merge primary + extra TLS domains, deduplicate (primary always first).
    if !config.censorship.tls_domains.is_empty() {
        let mut all = Vec::with_capacity(1 + config.censorship.tls_domains.len());
        all.push(config.censorship.tls_domain.clone());
        for d in std::mem::take(&mut config.censorship.tls_domains) {
            if !d.is_empty() {
                let domain = normalize_domain_to_ascii(&d, "censorship.tls_domains entry")?;
                if !all.contains(&domain) {
                    all.push(domain);
                }
            }
        }
        // keep primary as tls_domain; store remaining back to tls_domains
        if all.len() > 1 {
            config.censorship.tls_domains = all[1..].to_vec();
        }
    }

    let mut exclusive_mask = HashMap::with_capacity(config.censorship.exclusive_mask.len());
    let mut exclusive_mask_targets = HashMap::with_capacity(config.censorship.exclusive_mask.len());
    for (domain, target) in std::mem::take(&mut config.censorship.exclusive_mask) {
        let domain = normalize_domain_to_ascii(&domain, "censorship.exclusive_mask domain")?;
        let target = normalize_exclusive_mask_target(&target, "censorship.exclusive_mask target")?;
        let Some((host, port)) = parse_exclusive_mask_target(&target) else {
            return Err(ProxyError::Config(format!(
                "Invalid censorship.exclusive_mask target for '{}': '{}'. Expected host:port with port > 0",
                domain, target
            )));
        };
        exclusive_mask_targets.insert(
            domain.clone(),
            ExclusiveMaskTarget {
                host: host.to_string(),
                port,
            },
        );
        exclusive_mask.insert(domain, target);
    }
    config.censorship.exclusive_mask = exclusive_mask;
    config.censorship.exclusive_mask_targets = exclusive_mask_targets;

    // Migration: prefer_ipv6 -> network.prefer.
    if config.general.prefer_ipv6 {
        if config.network.prefer == 4 {
            config.network.prefer = 6;
        }
        warn!("prefer_ipv6 is deprecated, use [network].prefer = 6");
    }

    if config.general.use_middle_proxy && !config.general.me_secret_atomic_snapshot {
        config.general.me_secret_atomic_snapshot = true;
        warn!(
            "Auto-enabled me_secret_atomic_snapshot for middle proxy mode to keep KDF key_selector/secret coherent"
        );
    }

    validate_network_cfg(&mut config.network)?;
    crate::network::dns_overrides::validate_entries(&config.network.dns_overrides)?;

    if config.general.use_middle_proxy && config.network.ipv6 == Some(true) {
        warn!(
            "IPv6 with Middle Proxy is experimental and may cause KDF address mismatch; consider disabling IPv6 or ME"
        );
    }

    // Random fake_cert_len only when default is in use.
    if !config.censorship.tls_emulation
        && config.censorship.fake_cert_len == default_fake_cert_len()
    {
        config.censorship.fake_cert_len = rand::rng().random_range(1024..4096);
    }

    // Resolve listen_tcp: explicit value wins, otherwise auto-detect.
    // If unix socket is set → TCP only when listen_addr_ipv4 or listeners are explicitly provided.
    // If no unix socket → TCP always (backward compat).
    let listen_tcp = config.server.listen_tcp.unwrap_or_else(|| {
        if config.server.listen_unix_sock.is_some() {
            // Unix socket present: TCP only if user explicitly set addresses or listeners.
            config.server.listen_addr_ipv4.is_some() || !config.server.listeners.is_empty()
        } else {
            true
        }
    });

    // Migration: Populate listeners if empty (skip when listen_tcp = false).
    if config.server.listeners.is_empty() && listen_tcp {
        let ipv4_str = config
            .server
            .listen_addr_ipv4
            .as_deref()
            .unwrap_or("0.0.0.0");
        if let Ok(ipv4) = ipv4_str.parse::<IpAddr>() {
            config.server.listeners.push(ListenerConfig {
                ip: ipv4,
                transport: ListenerTransport::Mtproxy,
                port: Some(config.server.port),
                client_mss: None,
                synlimit: SynLimitMode::default(),
                synlimit_seconds: default_synlimit_seconds(),
                synlimit_hitcount: default_synlimit_hitcount(),
                synlimit_burst: default_synlimit_burst(),
                synlimit_ios_seconds: default_synlimit_ios_seconds(),
                synlimit_ios_hitcount: default_synlimit_ios_hitcount(),
                synlimit_ios_burst: default_synlimit_ios_burst(),
                synlimit_hashlimit_expire_ms: default_synlimit_hashlimit_expire_ms(),
                synlimit_hashlimit_size: default_synlimit_hashlimit_size(),
                announce: None,
                announce_ip: None,
                proxy_protocol: None,
                reuse_allow: false,
                web_client_ip_source: WebClientIpSource::XForwardedFor,
                web_trusted_proxy_cidrs: Vec::new(),
            });
        }
        if let Some(ipv6_str) = &config.server.listen_addr_ipv6
            && let Ok(ipv6) = ipv6_str.parse::<IpAddr>()
        {
            config.server.listeners.push(ListenerConfig {
                ip: ipv6,
                transport: ListenerTransport::Mtproxy,
                port: Some(config.server.port),
                client_mss: None,
                synlimit: SynLimitMode::default(),
                synlimit_seconds: default_synlimit_seconds(),
                synlimit_hitcount: default_synlimit_hitcount(),
                synlimit_burst: default_synlimit_burst(),
                synlimit_ios_seconds: default_synlimit_ios_seconds(),
                synlimit_ios_hitcount: default_synlimit_ios_hitcount(),
                synlimit_ios_burst: default_synlimit_ios_burst(),
                synlimit_hashlimit_expire_ms: default_synlimit_hashlimit_expire_ms(),
                synlimit_hashlimit_size: default_synlimit_hashlimit_size(),
                announce: None,
                announce_ip: None,
                proxy_protocol: None,
                reuse_allow: false,
                web_client_ip_source: WebClientIpSource::XForwardedFor,
                web_trusted_proxy_cidrs: Vec::new(),
            });
        }
    }

    // Migration: listeners[].port fallback to legacy server.port.
    for listener in &mut config.server.listeners {
        if listener.port.is_none() {
            listener.port = Some(config.server.port);
        }
    }

    // Migration: announce_ip → announce for each listener.
    for listener in &mut config.server.listeners {
        if listener.announce.is_none()
            && let Some(ip) = listener.announce_ip.take()
        {
            listener.announce = Some(ip.to_string());
        }
    }
    validate_listener_runtime_profiles(config)?;

    // Migration: show_link (top-level) → general.links.show.
    if !config.show_link.is_empty() && config.general.links.show.is_empty() {
        config.general.links.show = config.show_link.clone();
    }

    // Migration: Populate upstreams if empty (Default Direct).
    if config.upstreams.is_empty() {
        config.upstreams.push(UpstreamConfig {
            upstream_type: UpstreamType::Direct {
                interface: None,
                bind_addresses: None,
                bindtodevice: None,
            },
            weight: 1,
            enabled: true,
            scopes: String::new(),
            selected_scope: String::new(),
            ipv4: None,
            ipv6: None,
            prefer: None,
        });
    }
    normalize_upstream_family_policy(config);

    // Ensure default DC203 override is present.
    config
        .dc_overrides
        .entry("203".to_string())
        .or_insert_with(|| vec!["91.105.192.100:443".to_string()]);

    validate_logging_config(&config.logging)?;
    validate_upstreams(config)?;
    config.rebuild_runtime_user_auth()?;
    Ok(())
}
