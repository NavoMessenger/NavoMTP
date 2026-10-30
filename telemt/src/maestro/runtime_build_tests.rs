use super::*;

fn test_listener(port: u16) -> crate::config::ListenerConfig {
    crate::config::ListenerConfig {
        ip: "127.0.0.1".parse().unwrap(),
        transport: crate::config::ListenerTransport::Mtproxy,
        port: Some(port),
        client_mss: None,
        synlimit: crate::config::SynLimitMode::Off,
        synlimit_seconds: 60,
        synlimit_hitcount: 48,
        synlimit_burst: 24,
        synlimit_ios_seconds: 1,
        synlimit_ios_hitcount: 12,
        synlimit_ios_burst: 24,
        synlimit_hashlimit_expire_ms: 60_000,
        synlimit_hashlimit_size: 32_768,
        announce: None,
        announce_ip: None,
        proxy_protocol: None,
        reuse_allow: false,
        web_client_ip_source: crate::config::WebClientIpSource::XForwardedFor,
        web_trusted_proxy_cidrs: Vec::new(),
    }
}

fn web_config_with_fasttrack(mode: &str) -> ProxyConfig {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("config.toml");
    let config = format!(
        r#"
[access.users]
alice = "000102030405060708090a0b0c0d0e0f"

[[server.listeners]]
ip = "127.0.0.1"
port = 18080
transport = "web"
proxy_protocol = false
web_client_ip_source = "x_forwarded_for"
web_trusted_proxy_cidrs = ["127.0.0.1/32"]

[web]
enabled = true
decoy_fasttrack_mode = "{mode}"

[[web.vhosts]]
host = "proxy.example.com"
public_addr = "203.0.113.10:443"

[web.vhosts.decoy]
mode = "http_upstream"
upstream = "http://127.0.0.1:18081"

[[web.vhosts.profiles]]
user = "alice"
secret_mode = "plain"
"#,
    );
    std::fs::write(&path, config).unwrap();
    ProxyConfig::load(path).unwrap()
}

#[test]
fn process_socket_and_logging_changes_are_deferred() {
    let old = ProxyConfig::default();
    let mut new = old.clone();
    new.server.listen_backlog = new.server.listen_backlog.saturating_add(1);
    new.general.disable_colors = !new.general.disable_colors;

    let fields = deferred_process_fields(&old, &new).unwrap();
    assert!(fields.contains(&"server.listeners".to_string()));
    assert!(fields.contains(&"general.disable_colors".to_string()));
}

#[test]
fn global_mss_profiles_are_deferred_with_the_listener_socket_group() {
    let old = ProxyConfig::default();
    let mut desired = old.clone();
    desired.server.client_mss = Some("92".to_string());
    desired.server.client_mss_bulk = Some("1400".to_string());

    let resolved = resolve_reload_config(&old, &desired).unwrap();

    assert_eq!(
        resolved.deferred_process_fields,
        vec!["server.listeners".to_string()]
    );
    assert_eq!(resolved.effective.server.client_mss, old.server.client_mss);
    assert_eq!(
        resolved.effective.server.client_mss_bulk,
        old.server.client_mss_bulk
    );
    assert!(!resolved.runtime_changed);
}

#[test]
fn process_wide_connection_and_direct_buffer_envelopes_are_restart_only() {
    let old = ProxyConfig::default();
    let mut desired = old.clone();
    desired.server.max_connections = old.server.max_connections.saturating_add(1);
    desired.general.direct_relay_buffer_budget_max_bytes = old
        .general
        .direct_relay_buffer_budget_max_bytes
        .saturating_add(4 * 1024);

    let resolved = resolve_reload_config(&old, &desired).unwrap();

    assert_eq!(
        resolved.deferred_process_fields,
        vec![
            "server.max_connections".to_string(),
            "general.direct_relay_buffer_budget_max_bytes".to_string(),
        ]
    );
    assert_eq!(
        resolved.effective.server.max_connections,
        old.server.max_connections
    );
    assert_eq!(
        resolved
            .effective
            .general
            .direct_relay_buffer_budget_max_bytes,
        old.general.direct_relay_buffer_budget_max_bytes
    );
    assert!(!resolved.runtime_changed);
}

#[test]
fn conntrack_control_policy_is_restart_only_as_one_process_owned_unit() {
    let old = ProxyConfig::default();
    let mut desired = old.clone();
    desired.server.conntrack_control.inline_conntrack_control =
        !old.server.conntrack_control.inline_conntrack_control;
    desired.server.conntrack_control.mode = crate::config::ConntrackMode::Notrack;
    desired.server.conntrack_control.backend = crate::config::ConntrackBackend::Iptables;
    desired.server.conntrack_control.profile = crate::config::ConntrackPressureProfile::Aggressive;
    desired.server.conntrack_control.hybrid_listener_ips = vec!["192.0.2.10".parse().unwrap()];
    desired.server.conntrack_control.pressure_high_watermark_pct = 90;
    desired.server.conntrack_control.pressure_low_watermark_pct = 40;
    desired.server.conntrack_control.delete_budget_per_sec = old
        .server
        .conntrack_control
        .delete_budget_per_sec
        .saturating_add(1);

    let resolved = resolve_reload_config(&old, &desired).unwrap();

    assert_eq!(
        resolved.deferred_process_fields,
        vec!["server.conntrack_control".to_string()]
    );
    assert_eq!(
        serde_json::to_value(&resolved.effective.server.conntrack_control).unwrap(),
        serde_json::to_value(&old.server.conntrack_control).unwrap()
    );
    assert!(!resolved.runtime_changed);
}

#[test]
fn mixed_reload_retains_process_state_and_applies_runtime_state() {
    let old = ProxyConfig::default();
    let mut desired = old.clone();
    desired.server.client_mss = Some("92".to_string());
    desired.censorship.tls_domain = "reload.example".to_string();

    let resolved = resolve_reload_config(&old, &desired).unwrap();

    assert_eq!(resolved.effective.server.client_mss, old.server.client_mss);
    assert_eq!(
        resolved.effective.censorship.tls_domain,
        desired.censorship.tls_domain
    );
    assert!(resolved.runtime_changed);
    assert_eq!(
        resolved.deferred_process_fields,
        vec!["server.listeners".to_string()]
    );
}

#[test]
fn listener_announcement_is_runtime_owned_when_bind_identity_is_stable() {
    let mut old = ProxyConfig::default();
    old.server.listeners.push(crate::config::ListenerConfig {
        ip: "0.0.0.0".parse().unwrap(),
        transport: crate::config::ListenerTransport::Mtproxy,
        port: Some(443),
        client_mss: None,
        synlimit: crate::config::SynLimitMode::Off,
        synlimit_seconds: 60,
        synlimit_hitcount: 48,
        synlimit_burst: 24,
        synlimit_ios_seconds: 1,
        synlimit_ios_hitcount: 12,
        synlimit_ios_burst: 24,
        synlimit_hashlimit_expire_ms: 60_000,
        synlimit_hashlimit_size: 32_768,
        announce: None,
        announce_ip: None,
        proxy_protocol: None,
        reuse_allow: false,
        web_client_ip_source: crate::config::WebClientIpSource::XForwardedFor,
        web_trusted_proxy_cidrs: Vec::new(),
    });
    let mut desired = old.clone();
    desired.server.listeners[0].announce = Some("proxy.example".to_string());

    let resolved = resolve_reload_config(&old, &desired).unwrap();

    assert!(resolved.deferred_process_fields.is_empty());
    assert_eq!(
        resolved.effective.server.listeners[0].announce.as_deref(),
        Some("proxy.example")
    );
    assert!(resolved.runtime_changed);
}

#[test]
fn process_field_labels_are_stable_ordered_and_unique() {
    let old = ProxyConfig::default();
    let mut desired = old.clone();
    desired.server.listen_backlog = desired.server.listen_backlog.saturating_add(1);
    desired.server.api.enabled = !desired.server.api.enabled;
    desired.server.api.runtime_edge_events_capacity = desired
        .server
        .api
        .runtime_edge_events_capacity
        .saturating_add(1);
    desired.general.disable_colors = !desired.general.disable_colors;

    let resolved = resolve_reload_config(&old, &desired).unwrap();

    assert_eq!(
        resolved.deferred_process_fields,
        vec![
            "server.listeners".to_string(),
            "server.api.listen".to_string(),
            "server.api.runtime_edge_events_capacity".to_string(),
            "general.disable_colors".to_string(),
        ]
    );
}

#[test]
fn runtime_only_change_does_not_require_process_rebind() {
    let old = ProxyConfig::default();
    let mut new = old.clone();
    new.censorship.tls_domain = "reload.example".to_string();
    assert!(deferred_process_fields(&old, &new).unwrap().is_empty());
}

#[test]
fn web_allocation_limits_are_deferred_until_restart() {
    let mut old = ProxyConfig::default();
    old.rebuild_runtime_user_auth().unwrap();
    old.rebuild_runtime_web().unwrap();
    let mut desired = old.clone();
    desired.web.limits.max_sessions_global += 1;

    let resolved = resolve_reload_config(&old, &desired).unwrap();

    assert_eq!(
        resolved.deferred_process_fields,
        vec!["web.limits".to_string()]
    );
    assert_eq!(
        resolved.effective.web.limits.max_sessions_global,
        old.web.limits.max_sessions_global
    );
    assert!(!resolved.runtime_changed);
}

#[test]
fn web_decoy_fasttrack_mode_is_deferred_without_runtime_publication() {
    let old = web_config_with_fasttrack("off");
    let desired = web_config_with_fasttrack("enforce");

    let resolved = resolve_reload_config(&old, &desired).unwrap();

    assert_eq!(
        resolved.deferred_process_fields,
        vec!["web.decoy_fasttrack_mode".to_string()]
    );
    assert_eq!(
        resolved.effective.web.decoy_fasttrack_mode,
        old.web.decoy_fasttrack_mode
    );
    let effective_runtime = resolved.effective.web.runtime.as_ref().unwrap();
    let effective_vhost = &effective_runtime.vhosts["proxy.example.com"];
    assert_eq!(
        effective_vhost.decoy_fasttrack_mode,
        old.web.decoy_fasttrack_mode
    );
    assert!(!resolved.runtime_changed);
}

#[test]
fn base_path_change_is_runtime_owned_and_rebuilds_route_identity() {
    let old = web_config_with_fasttrack("off");
    let old_runtime = old.web.runtime.as_ref().unwrap();
    let old_capability = old_runtime.vhosts["proxy.example.com"].capabilities[0];
    let mut desired = old.clone();
    desired.web.vhosts[0].base_path = "MixedCase/path".to_string();

    let resolved = resolve_reload_config(&old, &desired).unwrap();

    assert!(resolved.deferred_process_fields.is_empty());
    assert!(resolved.runtime_changed);
    assert_eq!(resolved.effective.web.vhosts[0].base_path, "MixedCase/path");
    let runtime = resolved.effective.web.runtime.as_ref().unwrap();
    let vhost = &runtime.vhosts["proxy.example.com"];
    assert_eq!(vhost.base, "/MixedCase/path/");
    assert_ne!(vhost.capabilities[0], old_capability);
    assert_eq!(vhost.capabilities[0], vhost.profiles[0].capability);
    assert_eq!(runtime.capabilities.as_ref(), vhost.capabilities.as_ref());
    assert!(!runtime.capabilities.contains(&old_capability));
}

#[test]
fn enabling_learning_is_deferred_when_retained_capacity_is_too_small() {
    let mut old = ProxyConfig::default();
    old.web.limits.max_carrier_learning_entries = 1;
    old.web.carriers = crate::config::WebCarriers::Disabled;
    old.web.carrier_learning = false;
    old.rebuild_runtime_user_auth().unwrap();
    old.rebuild_runtime_web().unwrap();
    let mut desired = old.clone();
    desired.web.limits.max_carrier_learning_entries = 3;
    desired.web.carriers = crate::config::WebCarriers::Enabled(vec![
        crate::config::WebCarrier::Websocket,
        crate::config::WebCarrier::Https,
    ]);
    desired.web.carrier_learning = true;

    let resolved = resolve_reload_config(&old, &desired).unwrap();

    assert_eq!(
        resolved.deferred_process_fields,
        vec!["web.limits".to_string(), "web.carrier_learning".to_string()]
    );
    assert_eq!(
        resolved.effective.web.limits.max_carrier_learning_entries,
        1
    );
    assert!(resolved.effective.web.carrier_negotiation_enabled());
    assert!(!resolved.effective.web.carrier_learning);
}

#[test]
fn enabling_carriers_is_deferred_for_dormant_learning_with_small_capacity() {
    let mut old = ProxyConfig::default();
    old.web.limits.max_carrier_learning_entries = 1;
    old.web.carriers = crate::config::WebCarriers::Disabled;
    old.web.carrier_learning = true;
    old.rebuild_runtime_user_auth().unwrap();
    old.rebuild_runtime_web().unwrap();
    let mut desired = old.clone();
    desired.web.limits.max_carrier_learning_entries = 3;
    desired.web.carriers = crate::config::WebCarriers::Enabled(vec![
        crate::config::WebCarrier::Websocket,
        crate::config::WebCarrier::Https,
    ]);

    let resolved = resolve_reload_config(&old, &desired).unwrap();

    assert_eq!(
        resolved.deferred_process_fields,
        vec!["web.limits".to_string(), "web.carriers".to_string()]
    );
    assert_eq!(
        resolved.effective.web.limits.max_carrier_learning_entries,
        1
    );
    assert!(!resolved.effective.web.carrier_negotiation_enabled());
    assert!(resolved.effective.web.carrier_learning);
}

#[test]
fn web_debug_prefix_dependent_on_new_capacity_is_deferred_with_limits() {
    let mut old = ProxyConfig::default();
    old.rebuild_runtime_user_auth().unwrap();
    old.rebuild_runtime_web().unwrap();
    let mut desired = old.clone();
    desired.web.limits.max_body_bytes = 4 * 1024 * 1024;
    desired.web.debug.body_prefix_bytes = 3 * 1024 * 1024;

    let resolved = resolve_reload_config(&old, &desired).unwrap();

    assert_eq!(
        resolved.deferred_process_fields,
        vec!["web.limits".to_string(), "web.debug".to_string()]
    );
    assert_eq!(
        resolved.effective.web.debug.body_prefix_bytes,
        old.web.debug.body_prefix_bytes
    );
}

#[test]
fn strict_middle_proxy_requires_a_prepared_pool() {
    assert!(strict_middle_proxy_unavailable(true, false, false));
    assert!(!strict_middle_proxy_unavailable(true, false, true));
    assert!(!strict_middle_proxy_unavailable(true, true, false));
    assert!(!strict_middle_proxy_unavailable(false, false, false));
}

#[test]
fn endpoint_only_listener_move_is_runtime_rebindable() {
    let mut old = ProxyConfig::default();
    old.server.listeners = vec![test_listener(443)];
    let mut desired = old.clone();
    desired.server.listeners[0].port = Some(8443);

    let resolved = resolve_reload_config(&old, &desired).unwrap();

    assert!(resolved.deferred_process_fields.is_empty());
    assert_eq!(resolved.effective.server.listeners[0].port, Some(8443));
    assert!(resolved.runtime_changed);
}

#[test]
fn synlimited_endpoint_move_remains_restart_only() {
    let mut old = ProxyConfig::default();
    old.server.listeners = vec![test_listener(443)];
    old.server.listeners[0].synlimit = crate::config::SynLimitMode::Nftables;
    let mut desired = old.clone();
    desired.server.listeners[0].port = Some(8443);

    let resolved = resolve_reload_config(&old, &desired).unwrap();

    assert_eq!(
        resolved.deferred_process_fields,
        vec!["server.listeners".to_string()]
    );
    assert_eq!(resolved.effective.server.listeners[0].port, Some(443));
    assert!(!resolved.runtime_changed);
}

#[test]
fn deferred_listener_identity_cannot_create_an_effective_decoy_loop() {
    let mut old = ProxyConfig::default();
    old.server.listeners = vec![test_listener(18080)];
    old.server.listeners[0].transport = crate::config::ListenerTransport::Web;
    let mut desired = old.clone();
    desired.server.listeners[0].port = Some(18081);
    desired.server.listen_backlog = desired.server.listen_backlog.saturating_add(1);
    desired.web.vhosts = vec![
        serde_json::from_value(serde_json::json!({
            "host": "proxy.example",
            "public_addr": "203.0.113.10:443",
            "decoy": {
                "mode": "http_upstream",
                "upstream": "http://127.0.0.1:18080"
            },
            "profiles": []
        }))
        .unwrap(),
    ];

    assert!(desired.validate_web_decoy_listener_separation().is_ok());
    assert!(resolve_reload_config(&old, &desired).is_err());
}
