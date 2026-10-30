use super::*;

pub(in crate::api::users) fn empty_user_links() -> UserLinks {
    UserLinks {
        classic: Vec::new(),
        secure: Vec::new(),
        tls: Vec::new(),
        tls_domains: Vec::new(),
    }
}

pub(in crate::api::users) fn build_user_links(
    cfg: &ProxyConfig,
    secret: &str,
    startup_detected_ip_v4: Option<IpAddr>,
    startup_detected_ip_v6: Option<IpAddr>,
) -> UserLinks {
    let hosts = resolve_link_hosts(cfg, startup_detected_ip_v4, startup_detected_ip_v6);
    let port = cfg
        .general
        .links
        .public_port
        .unwrap_or(resolve_default_link_port(cfg));
    let tls_domains = resolve_tls_domains(cfg);
    let extra_tls_domains = resolve_extra_tls_domains(cfg);

    let mut classic = Vec::new();
    let mut secure = Vec::new();
    let mut tls = Vec::new();
    let mut tls_domain_links = Vec::new();

    for host in &hosts {
        if cfg.general.modes.classic {
            classic.push(format!(
                "tg://proxy?server={}&port={}&secret={}",
                host, port, secret
            ));
        }
        if cfg.general.modes.secure {
            secure.push(format!(
                "tg://proxy?server={}&port={}&secret=dd{}",
                host, port, secret
            ));
        }
        if cfg.general.modes.tls {
            for domain in &tls_domains {
                let domain_hex = hex::encode(domain);
                tls.push(format!(
                    "tg://proxy?server={}&port={}&secret=ee{}{}",
                    host, port, secret, domain_hex
                ));
            }
            for domain in &extra_tls_domains {
                let domain_hex = hex::encode(domain);
                let link = format!(
                    "tg://proxy?server={}&port={}&secret=ee{}{}",
                    host, port, secret, domain_hex
                );
                tls_domain_links.push(TlsDomainLink {
                    domain: (*domain).to_string(),
                    link,
                });
            }
        }
    }

    UserLinks {
        classic,
        secure,
        tls,
        tls_domains: tls_domain_links,
    }
}

fn resolve_default_link_port(cfg: &ProxyConfig) -> u16 {
    cfg.server
        .listeners
        .first()
        .and_then(|listener| listener.port)
        .unwrap_or(cfg.server.port)
}

fn resolve_link_hosts(
    cfg: &ProxyConfig,
    startup_detected_ip_v4: Option<IpAddr>,
    startup_detected_ip_v6: Option<IpAddr>,
) -> Vec<String> {
    if let Some(host) = cfg
        .general
        .links
        .public_host
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return vec![host.to_string()];
    }

    let mut hosts = Vec::new();
    for listener in &cfg.server.listeners {
        if let Some(host) = listener
            .announce
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            push_unique_host(&mut hosts, host);
            continue;
        }
        if let Some(ip) = listener.announce_ip
            && !ip.is_unspecified()
        {
            push_unique_host(&mut hosts, &ip.to_string());
            continue;
        }
        if listener.ip.is_unspecified() {
            let detected_ip = if listener.ip.is_ipv4() {
                startup_detected_ip_v4
            } else {
                startup_detected_ip_v6
            };
            if let Some(ip) = detected_ip {
                push_unique_host(&mut hosts, &ip.to_string());
            } else {
                push_unique_host(&mut hosts, &listener.ip.to_string());
            }
            continue;
        }
        push_unique_host(&mut hosts, &listener.ip.to_string());
    }

    if !hosts.is_empty() {
        return hosts;
    }

    if let Some(ip) = startup_detected_ip_v4.or(startup_detected_ip_v6) {
        return vec![ip.to_string()];
    }

    if let Some(host) = cfg.server.listen_addr_ipv4.as_deref() {
        push_host_from_legacy_listen(&mut hosts, host);
    }
    if let Some(host) = cfg.server.listen_addr_ipv6.as_deref() {
        push_host_from_legacy_listen(&mut hosts, host);
    }
    if !hosts.is_empty() {
        return hosts;
    }

    vec!["UNKNOWN".to_string()]
}

fn push_host_from_legacy_listen(hosts: &mut Vec<String>, raw: &str) {
    let candidate = raw.trim();
    if candidate.is_empty() {
        return;
    }

    match candidate.parse::<IpAddr>() {
        Ok(ip) if ip.is_unspecified() => {}
        Ok(ip) => push_unique_host(hosts, &ip.to_string()),
        Err(_) => push_unique_host(hosts, candidate),
    }
}

fn push_unique_host(hosts: &mut Vec<String>, candidate: &str) {
    if !hosts.iter().any(|existing| existing == candidate) {
        hosts.push(candidate.to_string());
    }
}

fn resolve_tls_domains(cfg: &ProxyConfig) -> Vec<&str> {
    let mut domains = Vec::with_capacity(1 + cfg.censorship.tls_domains.len());
    let primary = cfg.censorship.tls_domain.as_str();
    if !primary.is_empty() {
        domains.push(primary);
    }
    for domain in &cfg.censorship.tls_domains {
        let value = domain.as_str();
        if value.is_empty() || domains.contains(&value) {
            continue;
        }
        domains.push(value);
    }
    domains
}

fn resolve_extra_tls_domains(cfg: &ProxyConfig) -> Vec<&str> {
    let mut domains = Vec::with_capacity(cfg.censorship.tls_domains.len());
    let primary = cfg.censorship.tls_domain.as_str();
    for domain in &cfg.censorship.tls_domains {
        let value = domain.as_str();
        if value.is_empty() || value == primary || domains.contains(&value) {
            continue;
        }
        domains.push(value);
    }
    domains
}
