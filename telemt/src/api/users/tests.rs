use super::*;
use crate::ip_tracker::UserIpTracker;
use crate::stats::Stats;

#[tokio::test]
async fn users_from_config_reports_effective_tcp_limit_with_global_fallback() {
    let mut cfg = ProxyConfig::default();
    cfg.access.users.insert(
        "alice".to_string(),
        "0123456789abcdef0123456789abcdef".to_string(),
    );
    cfg.access.user_max_tcp_conns_global_each = 7;

    let stats = Stats::new();
    let tracker = UserIpTracker::new();

    let users = users_from_config(&cfg, &stats, &tracker, None, None, None).await;
    let alice = users
        .iter()
        .find(|entry| entry.username == "alice")
        .expect("alice must be present");
    assert!(!alice.in_runtime);
    assert_eq!(alice.max_tcp_conns, Some(7));

    cfg.access.user_max_tcp_conns.insert("alice".to_string(), 5);
    let users = users_from_config(&cfg, &stats, &tracker, None, None, None).await;
    let alice = users
        .iter()
        .find(|entry| entry.username == "alice")
        .expect("alice must be present");
    assert!(!alice.in_runtime);
    assert_eq!(alice.max_tcp_conns, Some(5));

    cfg.access.user_max_tcp_conns.insert("alice".to_string(), 0);
    let users = users_from_config(&cfg, &stats, &tracker, None, None, None).await;
    let alice = users
        .iter()
        .find(|entry| entry.username == "alice")
        .expect("alice must be present");
    assert!(!alice.in_runtime);
    assert_eq!(alice.max_tcp_conns, Some(7));

    cfg.access.user_max_tcp_conns_global_each = 0;
    let users = users_from_config(&cfg, &stats, &tracker, None, None, None).await;
    let alice = users
        .iter()
        .find(|entry| entry.username == "alice")
        .expect("alice must be present");
    assert!(!alice.in_runtime);
    assert_eq!(alice.max_tcp_conns, None);
}

#[tokio::test]
async fn users_from_config_reports_user_rate_limits() {
    let mut cfg = ProxyConfig::default();
    cfg.access.users.insert(
        "alice".to_string(),
        "0123456789abcdef0123456789abcdef".to_string(),
    );
    cfg.access.user_rate_limits.insert(
        "alice".to_string(),
        RateLimitBps {
            up_bps: 1024,
            down_bps: 0,
        },
    );

    let stats = Stats::new();
    let tracker = UserIpTracker::new();

    let users = users_from_config(&cfg, &stats, &tracker, None, None, None).await;
    let alice = users
        .iter()
        .find(|entry| entry.username == "alice")
        .expect("alice must be present");

    assert_eq!(alice.rate_limit_up_bps, Some(1024));
    assert_eq!(alice.rate_limit_down_bps, None);
}

#[tokio::test]
async fn users_from_config_reports_user_enabled_default_and_override() {
    let mut cfg = ProxyConfig::default();
    cfg.access.users.insert(
        "alice".to_string(),
        "0123456789abcdef0123456789abcdef".to_string(),
    );
    cfg.access.users.insert(
        "bob".to_string(),
        "fedcba9876543210fedcba9876543210".to_string(),
    );
    cfg.access.user_enabled.insert("bob".to_string(), false);

    let stats = Stats::new();
    let tracker = UserIpTracker::new();
    let users = users_from_config(&cfg, &stats, &tracker, None, None, None).await;
    let alice = users
        .iter()
        .find(|entry| entry.username == "alice")
        .expect("alice must be present");
    let bob = users
        .iter()
        .find(|entry| entry.username == "bob")
        .expect("bob must be present");

    assert!(alice.enabled);
    assert!(!bob.enabled);

    cfg.access.user_enabled.insert("bob".to_string(), true);
    let users = users_from_config(&cfg, &stats, &tracker, None, None, None).await;
    let bob = users
        .iter()
        .find(|entry| entry.username == "bob")
        .expect("bob must be present");
    assert!(bob.enabled);
}

#[tokio::test]
async fn users_from_config_marks_runtime_membership_when_snapshot_is_provided() {
    let mut disk_cfg = ProxyConfig::default();
    disk_cfg.access.users.insert(
        "alice".to_string(),
        "0123456789abcdef0123456789abcdef".to_string(),
    );
    disk_cfg.access.users.insert(
        "bob".to_string(),
        "fedcba9876543210fedcba9876543210".to_string(),
    );

    let mut runtime_cfg = ProxyConfig::default();
    runtime_cfg.access.users.insert(
        "alice".to_string(),
        "0123456789abcdef0123456789abcdef".to_string(),
    );

    let stats = Stats::new();
    let tracker = UserIpTracker::new();
    let users =
        users_from_config(&disk_cfg, &stats, &tracker, None, None, Some(&runtime_cfg)).await;

    let alice = users
        .iter()
        .find(|entry| entry.username == "alice")
        .expect("alice must be present");
    let bob = users
        .iter()
        .find(|entry| entry.username == "bob")
        .expect("bob must be present");

    assert!(alice.in_runtime);
    assert!(!bob.in_runtime);
}

#[tokio::test]
async fn users_from_config_returns_tls_link_for_each_tls_domain() {
    let mut cfg = ProxyConfig::default();
    cfg.access.users.insert(
        "alice".to_string(),
        "0123456789abcdef0123456789abcdef".to_string(),
    );
    cfg.general.modes.classic = false;
    cfg.general.modes.secure = false;
    cfg.general.modes.tls = true;
    cfg.general.links.public_host = Some("proxy.example.net".to_string());
    cfg.general.links.public_port = Some(443);
    cfg.censorship.tls_domain = "front-a.example.com".to_string();
    cfg.censorship.tls_domains = vec![
        "front-b.example.com".to_string(),
        "front-c.example.com".to_string(),
        "front-b.example.com".to_string(),
        "front-a.example.com".to_string(),
    ];

    let stats = Stats::new();
    let tracker = UserIpTracker::new();
    let users = users_from_config(&cfg, &stats, &tracker, None, None, None).await;
    let alice = users
        .iter()
        .find(|entry| entry.username == "alice")
        .expect("alice must be present");

    assert_eq!(alice.links.tls.len(), 3);
    assert!(
        alice
            .links
            .tls
            .iter()
            .any(|link| link.ends_with(&hex::encode("front-a.example.com")))
    );
    assert!(
        alice
            .links
            .tls
            .iter()
            .any(|link| link.ends_with(&hex::encode("front-b.example.com")))
    );
    assert!(
        alice
            .links
            .tls
            .iter()
            .any(|link| link.ends_with(&hex::encode("front-c.example.com")))
    );
    assert_eq!(alice.links.tls_domains.len(), 2);
    assert!(
        alice
            .links
            .tls_domains
            .iter()
            .any(|entry| entry.domain == "front-b.example.com"
                && entry.link.ends_with(&hex::encode("front-b.example.com")))
    );
    assert!(
        alice
            .links
            .tls_domains
            .iter()
            .any(|entry| entry.domain == "front-c.example.com"
                && entry.link.ends_with(&hex::encode("front-c.example.com")))
    );
    assert!(
        !alice
            .links
            .tls_domains
            .iter()
            .any(|entry| entry.domain == "front-a.example.com")
    );
}

#[test]
fn build_user_quota_list_skips_users_without_positive_quota_and_sorts_by_username() {
    let mut cfg = ProxyConfig::default();
    cfg.access.users.insert(
        "alice".to_string(),
        "0123456789abcdef0123456789abcdef".to_string(),
    );
    cfg.access.users.insert(
        "bob".to_string(),
        "fedcba9876543210fedcba9876543210".to_string(),
    );
    cfg.access.users.insert(
        "carol".to_string(),
        "aaaabbbbccccddddeeeeffff00001111".to_string(),
    );
    // alice has a positive quota and should be listed.
    cfg.access
        .user_data_quota
        .insert("alice".to_string(), 1 << 20);
    // bob has no quota entry at all (None) — should be skipped.
    // carol has an explicit zero quota — should be skipped.
    cfg.access.user_data_quota.insert("carol".to_string(), 0);

    let stats = Stats::new();
    // Charge some traffic against alice; carol gets traffic too but should
    // still be filtered out by the quota check.
    let alice_stats = stats.get_or_create_user_stats_handle("alice");
    stats.quota_charge_post_write(&alice_stats, 4096);
    let carol_stats = stats.get_or_create_user_stats_handle("carol");
    stats.quota_charge_post_write(&carol_stats, 99);

    let data = build_user_quota_list(&cfg, &stats);

    assert_eq!(data.users.len(), 1);
    let entry = &data.users[0];
    assert_eq!(entry.username, "alice");
    assert_eq!(entry.data_quota_bytes, 1 << 20);
    assert_eq!(entry.used_bytes, 4096);
    assert_eq!(entry.last_reset_epoch_secs, 0);
}

#[test]
fn build_user_quota_list_orders_multiple_users_by_username_ascending() {
    let mut cfg = ProxyConfig::default();
    for name in ["charlie", "alice", "bob"] {
        cfg.access.users.insert(
            name.to_string(),
            "0123456789abcdef0123456789abcdef".to_string(),
        );
        cfg.access.user_data_quota.insert(name.to_string(), 1 << 30);
    }

    let stats = Stats::new();
    let data = build_user_quota_list(&cfg, &stats);

    let names: Vec<&str> = data.users.iter().map(|e| e.username.as_str()).collect();
    assert_eq!(names, vec!["alice", "bob", "charlie"]);
    for entry in &data.users {
        assert_eq!(entry.used_bytes, 0);
        assert_eq!(entry.last_reset_epoch_secs, 0);
        assert_eq!(entry.data_quota_bytes, 1 << 30);
    }
}
