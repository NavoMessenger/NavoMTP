use super::*;

impl UpstreamManager {
    /// Resolves this generation's direct bind candidates without advancing round-robin state.
    pub(crate) async fn direct_bind_ips_for_family(&self, ipv6: bool) -> BTreeSet<IpAddr> {
        let guard = self.upstreams.read().await;
        let target = SocketAddr::new(
            if ipv6 {
                std::net::Ipv6Addr::UNSPECIFIED.into()
            } else {
                std::net::Ipv4Addr::UNSPECIFIED.into()
            },
            0,
        );
        let mut allowed = BTreeSet::new();
        for state in guard.iter() {
            let config = &state.config;
            let UpstreamType::Direct {
                interface,
                bind_addresses,
                ..
            } = &config.upstream_type
            else {
                continue;
            };
            if (if ipv6 { config.ipv6 } else { config.ipv4 }) == Some(false) {
                continue;
            }
            if let Some(addresses) = bind_addresses.as_ref().filter(|v| !v.is_empty()) {
                for address in addresses {
                    if !address
                        .parse::<IpAddr>()
                        .is_ok_and(|ip| ip.is_ipv6() == ipv6)
                    {
                        continue;
                    }
                    if let Some(ip) = Self::resolve_bind_address(
                        interface,
                        &Some(vec![address.clone()]),
                        target,
                        None,
                        true,
                    ) {
                        allowed.insert(ip);
                    }
                }
            } else if let Some(ip) =
                Self::resolve_bind_address(interface, bind_addresses, target, None, true)
            {
                allowed.insert(ip);
            }
        }
        allowed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(source: &str) -> UpstreamConfig {
        toml::from_str(source).unwrap()
    }

    #[tokio::test]
    async fn candidates_follow_generation_policy_without_advancing_round_robin() {
        let manager = UpstreamManager::new(
            vec![
                config("type = 'direct'\nbind_addresses = ['127.0.0.1', '127.0.0.2', '::1']"),
                config("type = 'direct'\ninterface = '127.0.0.3'"),
                config("type = 'direct'\ninterface = '127.0.0.4'\nenabled = false"),
                config("type = 'direct'\ninterface = '127.0.0.5'\nipv4 = false"),
                config("type = 'socks5'\naddress = '127.0.0.1:1080'\ninterface = '127.0.0.6'"),
            ],
            1,
            0,
            1000,
            1,
            1,
            true,
            Arc::new(Stats::new()),
        );
        manager.upstreams.write().await[0].healthy = false;
        let expected = ["127.0.0.1", "127.0.0.2", "127.0.0.3"]
            .into_iter()
            .map(|value| value.parse().unwrap())
            .collect();
        assert_eq!(manager.direct_bind_ips_for_family(false).await, expected);
        assert_eq!(
            manager.direct_bind_ips_for_family(true).await,
            BTreeSet::from(["::1".parse().unwrap()])
        );
        for state in manager.upstreams.read().await.iter() {
            assert_eq!(state.bind_rr.load(Ordering::Relaxed), 0);
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn named_interface_candidates_match_direct_socket_binding() {
        let manager = UpstreamManager::new(
            vec![config(
                "type = 'direct'\ninterface = 'lo'\nbind_addresses = ['127.0.0.1', '::1']",
            )],
            1,
            0,
            1000,
            1,
            1,
            true,
            Arc::new(Stats::new()),
        );
        assert_eq!(
            manager.direct_bind_ips_for_family(false).await,
            BTreeSet::from(["127.0.0.1".parse().unwrap()])
        );
        assert_eq!(
            manager.direct_bind_ips_for_family(true).await,
            BTreeSet::from(["::1".parse().unwrap()])
        );
    }
}
