use crate::config::{ConntrackBackend, ConntrackMode, ProxyConfig};

use super::super::command::is_not_found_error;
use super::super::iptables::{self, is_chain_exists_error};
use super::super::model::{DesiredPolicy, ShadowSlot};
use super::super::nftables;
use super::target;

#[test]
fn desired_policy_derives_exact_listener_targets() {
    let mut config = ProxyConfig::default();
    config.server.port = 8443;
    config.server.listen_addr_ipv4 = Some("0.0.0.0".to_string());
    config.server.listen_addr_ipv6 = Some("2001:db8::10".to_string());
    config.server.conntrack_control.inline_conntrack_control = true;
    config.server.conntrack_control.mode = ConntrackMode::Notrack;
    config.server.conntrack_control.backend = ConntrackBackend::Iptables;

    assert_eq!(
        DesiredPolicy::from_config(&config),
        DesiredPolicy::Rules {
            configured_backend: ConntrackBackend::Iptables,
            v4: vec![target(None, 8443)],
            v6: vec![target(Some("2001:db8::10"), 8443)],
        }
    );

    config.server.conntrack_control.mode = ConntrackMode::Tracked;
    assert_eq!(DesiredPolicy::from_config(&config), DesiredPolicy::Empty);
    config.server.conntrack_control.mode = ConntrackMode::Notrack;
    config.server.conntrack_control.inline_conntrack_control = false;
    assert_eq!(DesiredPolicy::from_config(&config), DesiredPolicy::Empty);
}

#[test]
fn hybrid_policy_is_a_sorted_deduplicated_address_port_product() {
    let mut config = ProxyConfig::default();
    config.server.conntrack_control.inline_conntrack_control = true;
    config.server.conntrack_control.mode = ConntrackMode::Hybrid;
    config.server.conntrack_control.hybrid_listener_ips = vec![
        "2001:db8::10".parse().unwrap(),
        "192.0.2.10".parse().unwrap(),
        "192.0.2.10".parse().unwrap(),
    ];
    config.server.listeners = vec![
        serde_json::from_value(serde_json::json!({
            "ip": "0.0.0.0",
            "port": 8443
        }))
        .unwrap(),
        serde_json::from_value(serde_json::json!({
            "ip": "::",
            "port": 443
        }))
        .unwrap(),
    ];

    assert_eq!(
        DesiredPolicy::from_config(&config),
        DesiredPolicy::Rules {
            configured_backend: ConntrackBackend::Auto,
            v4: vec![
                target(Some("192.0.2.10"), 443),
                target(Some("192.0.2.10"), 8443),
            ],
            v6: vec![
                target(Some("2001:db8::10"), 443),
                target(Some("2001:db8::10"), 8443),
            ],
        }
    );
}

#[test]
fn restore_renderers_keep_staging_detached_from_activation() {
    let stage = iptables::render_stage_script(ShadowSlot::B, &[target(Some("192.0.2.20"), 443)]);
    assert!(stage.contains("-F TELEMT_NT_B\n"));
    assert!(stage.contains("-A TELEMT_NT_B -p tcp --dport 443 -d 192.0.2.20 -j CT --notrack\n"));
    assert!(!stage.contains("-A TELEMT_NOTRACK -j TELEMT_NT_B"));
    assert!(!stage.contains(":TELEMT_"));

    let activation = iptables::render_dispatch_script(Some(ShadowSlot::B));
    assert!(activation.contains("-F TELEMT_NOTRACK\n"));
    assert!(activation.contains("-A TELEMT_NOTRACK -j TELEMT_NT_B\n"));
    assert!(!activation.contains(":TELEMT_"));

    let nft_stage = nftables::render_stage_script(
        ShadowSlot::A,
        &[target(None, 443)],
        &[target(Some("2001:db8::20"), 8443)],
    );
    assert!(!nft_stage.contains("hook prerouting"));
    assert!(nft_stage.contains("tcp dport 443 notrack\n"));
    assert!(nft_stage.contains("tcp dport 8443 ip6 daddr 2001:db8::20 notrack\n"));
    assert!(nftables::render_activate_script(ShadowSlot::A).contains("hook prerouting"));
}

#[test]
fn command_error_classification_only_accepts_absent_owned_objects() {
    assert!(is_not_found_error(
        "iptables: No chain/target/match by that name."
    ));
    assert!(is_not_found_error(
        "Bad rule (does a matching rule exist in that chain?)."
    ));
    assert!(is_not_found_error(
        "Error: Could not process rule: No such file or directory"
    ));
    assert!(!is_not_found_error("Permission denied"));
    assert!(!is_not_found_error(
        "can't initialize iptables table `raw': Table does not exist"
    ));
    assert!(!is_not_found_error(
        "Another app is currently holding the xtables lock"
    ));
    assert!(is_chain_exists_error("iptables: Chain already exists."));
    assert!(!is_chain_exists_error("Permission denied"));
}
