use crate::proxy::client::handle_client_stream_with_shared;
use crate::proxy::handshake::{
    auth_probe_fail_streak_for_testing_in_shared, auth_probe_is_throttled_for_testing_in_shared,
    auth_probe_record_failure_for_testing, clear_auth_probe_state_for_testing_in_shared,
    clear_unknown_sni_warn_state_for_testing_in_shared, clear_warned_secrets_for_testing_in_shared,
    should_emit_unknown_sni_warn_for_testing_in_shared, warned_secrets_for_testing_in_shared,
};
use crate::proxy::middle_relay::{
    clear_desync_dedup_for_testing_in_shared, clear_relay_idle_candidate_for_testing,
    clear_relay_idle_pressure_state_for_testing_in_shared, mark_relay_idle_candidate_for_testing,
    maybe_evict_idle_candidate_on_pressure_for_testing, note_relay_pressure_event_for_testing,
    oldest_relay_idle_candidate_for_testing, relay_idle_mark_seq_for_testing,
    relay_pressure_event_seq_for_testing, should_emit_full_desync_for_testing,
};
use crate::proxy::route_mode::{RelayRouteMode, RouteRuntimeController};
use crate::proxy::shared_state::ProxySharedState;
use crate::{
    config::{ProxyConfig, UpstreamConfig, UpstreamType},
    crypto::SecureRandom,
    ip_tracker::UserIpTracker,
    stats::{ReplayChecker, Stats, beobachten::BeobachtenStore},
    stream::BufferPool,
    transport::UpstreamManager,
};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncWriteExt, duplex};
use tokio::sync::Barrier;

struct ClientHarness {
    config: Arc<ProxyConfig>,
    stats: Arc<Stats>,
    upstream_manager: Arc<UpstreamManager>,
    replay_checker: Arc<ReplayChecker>,
    buffer_pool: Arc<BufferPool>,
    rng: Arc<SecureRandom>,
    route_runtime: Arc<RouteRuntimeController>,
    ip_tracker: Arc<UserIpTracker>,
    beobachten: Arc<BeobachtenStore>,
}

fn new_client_harness() -> ClientHarness {
    let mut cfg = ProxyConfig::default();
    cfg.censorship.mask = false;
    cfg.general.modes.classic = true;
    cfg.general.modes.secure = true;
    let config = Arc::new(cfg);
    let stats = Arc::new(Stats::new());

    let upstream_manager = Arc::new(UpstreamManager::new(
        vec![UpstreamConfig {
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
        }],
        1,
        1,
        1,
        10,
        1,
        false,
        stats.clone(),
    ));

    ClientHarness {
        config,
        stats,
        upstream_manager,
        replay_checker: Arc::new(ReplayChecker::new(128, Duration::from_secs(60))),
        buffer_pool: Arc::new(BufferPool::new()),
        rng: Arc::new(SecureRandom::new()),
        route_runtime: Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct)),
        ip_tracker: Arc::new(UserIpTracker::new()),
        beobachten: Arc::new(BeobachtenStore::new()),
    }
}

async fn drive_invalid_mtproto_handshake(
    shared: Arc<ProxySharedState>,
    peer: std::net::SocketAddr,
) {
    let harness = new_client_harness();
    let (server_side, mut client_side) = duplex(4096);
    let invalid = [0u8; 64];

    let task = tokio::spawn(handle_client_stream_with_shared(
        server_side,
        peer,
        harness.config,
        harness.stats,
        harness.upstream_manager,
        harness.replay_checker,
        harness.buffer_pool,
        harness.rng,
        None,
        harness.route_runtime,
        None,
        harness.ip_tracker,
        harness.beobachten,
        shared,
        false,
    ));

    client_side
        .write_all(&invalid)
        .await
        .expect("failed to write invalid handshake");
    client_side
        .shutdown()
        .await
        .expect("failed to shutdown client");
    let _ = tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .expect("client task timed out")
        .expect("client task join failed");
}

#[test]
fn proxy_shared_state_two_instances_do_not_share_auth_probe_state() {
    let a = ProxySharedState::new();
    let b = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(a.as_ref());

    let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10));
    auth_probe_record_failure_for_testing(a.as_ref(), ip, Instant::now());

    assert_eq!(
        auth_probe_fail_streak_for_testing_in_shared(a.as_ref(), ip),
        Some(1)
    );
    assert_eq!(
        auth_probe_fail_streak_for_testing_in_shared(b.as_ref(), ip),
        None
    );
}

#[test]
fn proxy_shared_state_two_instances_do_not_share_desync_dedup() {
    let a = ProxySharedState::new();
    let b = ProxySharedState::new();
    clear_desync_dedup_for_testing_in_shared(a.as_ref());

    let now = Instant::now();
    let key = 0xA5A5_u64;
    assert!(should_emit_full_desync_for_testing(
        a.as_ref(),
        key,
        false,
        now
    ));
    assert!(should_emit_full_desync_for_testing(
        b.as_ref(),
        key,
        false,
        now
    ));
}

#[test]
fn proxy_shared_state_two_instances_do_not_share_idle_registry() {
    let a = ProxySharedState::new();
    let b = ProxySharedState::new();
    clear_relay_idle_pressure_state_for_testing_in_shared(a.as_ref());

    assert!(mark_relay_idle_candidate_for_testing(a.as_ref(), 111));
    assert_eq!(
        oldest_relay_idle_candidate_for_testing(a.as_ref()),
        Some(111)
    );
    assert_eq!(oldest_relay_idle_candidate_for_testing(b.as_ref()), None);
}

#[test]
fn proxy_shared_state_reset_in_one_instance_does_not_affect_another() {
    let a = ProxySharedState::new();
    let b = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(a.as_ref());

    let ip_a = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
    let ip_b = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 2));
    let now = Instant::now();

    auth_probe_record_failure_for_testing(a.as_ref(), ip_a, now);
    auth_probe_record_failure_for_testing(b.as_ref(), ip_b, now);
    clear_auth_probe_state_for_testing_in_shared(a.as_ref());

    assert_eq!(
        auth_probe_fail_streak_for_testing_in_shared(a.as_ref(), ip_a),
        None
    );
    assert_eq!(
        auth_probe_fail_streak_for_testing_in_shared(b.as_ref(), ip_b),
        Some(1)
    );
}

#[test]
fn proxy_shared_state_parallel_auth_probe_updates_stay_per_instance() {
    let a = ProxySharedState::new();
    let b = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(a.as_ref());

    let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 77));
    let now = Instant::now();

    for _ in 0..5 {
        auth_probe_record_failure_for_testing(a.as_ref(), ip, now);
    }
    for _ in 0..3 {
        auth_probe_record_failure_for_testing(b.as_ref(), ip, now + Duration::from_millis(1));
    }

    assert_eq!(
        auth_probe_fail_streak_for_testing_in_shared(a.as_ref(), ip),
        Some(5)
    );
    assert_eq!(
        auth_probe_fail_streak_for_testing_in_shared(b.as_ref(), ip),
        Some(3)
    );
}

#[tokio::test]
async fn proxy_shared_state_client_pipeline_records_probe_failures_in_instance_state() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());
    let peer_ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 200));
    let peer = std::net::SocketAddr::new(peer_ip, 54001);

    drive_invalid_mtproto_handshake(shared.clone(), peer).await;

    assert_eq!(
        auth_probe_fail_streak_for_testing_in_shared(shared.as_ref(), peer_ip),
        Some(1),
        "invalid handshake in client pipeline must update injected shared auth-probe state"
    );
}

#[tokio::test]
async fn proxy_shared_state_client_pipeline_keeps_auth_probe_isolated_between_instances() {
    let shared_a = ProxySharedState::new();
    let shared_b = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared_a.as_ref());
    clear_auth_probe_state_for_testing_in_shared(shared_b.as_ref());

    let peer_a_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 210));
    let peer_b_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 211));

    drive_invalid_mtproto_handshake(
        shared_a.clone(),
        std::net::SocketAddr::new(peer_a_ip, 54110),
    )
    .await;
    drive_invalid_mtproto_handshake(
        shared_b.clone(),
        std::net::SocketAddr::new(peer_b_ip, 54111),
    )
    .await;

    assert_eq!(
        auth_probe_fail_streak_for_testing_in_shared(shared_a.as_ref(), peer_a_ip),
        Some(1)
    );
    assert_eq!(
        auth_probe_fail_streak_for_testing_in_shared(shared_b.as_ref(), peer_b_ip),
        Some(1)
    );
    assert_eq!(
        auth_probe_fail_streak_for_testing_in_shared(shared_a.as_ref(), peer_b_ip),
        None
    );
    assert_eq!(
        auth_probe_fail_streak_for_testing_in_shared(shared_b.as_ref(), peer_a_ip),
        None
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_shared_state_client_pipeline_high_contention_same_ip_stays_lossless_per_instance() {
    let shared_a = ProxySharedState::new();
    let shared_b = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared_a.as_ref());
    clear_auth_probe_state_for_testing_in_shared(shared_b.as_ref());

    let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 250));
    let workers = 48u16;
    let barrier = Arc::new(Barrier::new((workers as usize) * 2));
    let mut tasks = Vec::new();

    for i in 0..workers {
        let shared_a = shared_a.clone();
        let barrier_a = barrier.clone();
        let peer_a = std::net::SocketAddr::new(ip, 56000 + i);
        tasks.push(tokio::spawn(async move {
            barrier_a.wait().await;
            drive_invalid_mtproto_handshake(shared_a, peer_a).await;
        }));

        let shared_b = shared_b.clone();
        let barrier_b = barrier.clone();
        let peer_b = std::net::SocketAddr::new(ip, 56100 + i);
        tasks.push(tokio::spawn(async move {
            barrier_b.wait().await;
            drive_invalid_mtproto_handshake(shared_b, peer_b).await;
        }));
    }

    for task in tasks {
        task.await.expect("pipeline task join failed");
    }

    let streak_a = auth_probe_fail_streak_for_testing_in_shared(shared_a.as_ref(), ip)
        .expect("instance A must track probe failures");
    let streak_b = auth_probe_fail_streak_for_testing_in_shared(shared_b.as_ref(), ip)
        .expect("instance B must track probe failures");

    assert!(streak_a > 0);
    assert!(streak_b > 0);

    clear_auth_probe_state_for_testing_in_shared(shared_a.as_ref());
    assert_eq!(
        auth_probe_fail_streak_for_testing_in_shared(shared_a.as_ref(), ip),
        None,
        "clearing one instance must reset only that instance"
    );
    assert!(
        auth_probe_fail_streak_for_testing_in_shared(shared_b.as_ref(), ip).is_some(),
        "clearing one instance must not clear the other instance"
    );
}

#[test]
fn proxy_shared_state_auth_saturation_does_not_bleed_across_instances() {
    let a = ProxySharedState::new();
    let b = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(a.as_ref());
    clear_auth_probe_state_for_testing_in_shared(b.as_ref());

    let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77));
    let future_now = Instant::now() + Duration::from_secs(1);
    for _ in 0..8 {
        auth_probe_record_failure_for_testing(a.as_ref(), ip, future_now);
    }

    assert!(auth_probe_is_throttled_for_testing_in_shared(
        a.as_ref(),
        ip
    ));
    assert!(!auth_probe_is_throttled_for_testing_in_shared(
        b.as_ref(),
        ip
    ));
}

#[test]
fn proxy_shared_state_poison_clear_in_one_instance_does_not_affect_other_instance() {
    let a = ProxySharedState::new();
    let b = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(a.as_ref());
    clear_auth_probe_state_for_testing_in_shared(b.as_ref());

    let ip_a = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 31));
    let ip_b = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 32));
    let now = Instant::now();

    auth_probe_record_failure_for_testing(a.as_ref(), ip_a, now);
    auth_probe_record_failure_for_testing(b.as_ref(), ip_b, now);

    let a_for_poison = a.clone();
    let _ = std::thread::spawn(move || {
        let _hold = a_for_poison
            .handshake
            .auth_probe_saturation
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        panic!("intentional poison for per-instance isolation regression coverage");
    })
    .join();

    clear_auth_probe_state_for_testing_in_shared(a.as_ref());

    assert_eq!(
        auth_probe_fail_streak_for_testing_in_shared(a.as_ref(), ip_a),
        None
    );
    assert_eq!(
        auth_probe_fail_streak_for_testing_in_shared(b.as_ref(), ip_b),
        Some(1),
        "poison recovery and clear in one instance must not touch other instance state"
    );
}

#[test]
fn proxy_shared_state_unknown_sni_cooldown_does_not_bleed_across_instances() {
    let a = ProxySharedState::new();
    let b = ProxySharedState::new();
    clear_unknown_sni_warn_state_for_testing_in_shared(a.as_ref());
    clear_unknown_sni_warn_state_for_testing_in_shared(b.as_ref());

    let now = Instant::now();
    assert!(should_emit_unknown_sni_warn_for_testing_in_shared(
        a.as_ref(),
        now
    ));
    assert!(should_emit_unknown_sni_warn_for_testing_in_shared(
        b.as_ref(),
        now
    ));
}

#[test]
fn proxy_shared_state_warned_secret_cache_does_not_bleed_across_instances() {
    let a = ProxySharedState::new();
    let b = ProxySharedState::new();
    clear_warned_secrets_for_testing_in_shared(a.as_ref());
    clear_warned_secrets_for_testing_in_shared(b.as_ref());

    let key = ("isolation-user".to_string(), "invalid_hex".to_string());
    {
        let warned = warned_secrets_for_testing_in_shared(a.as_ref());
        let mut guard = warned
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.insert(key.clone());
    }

    let contains_in_a = {
        let warned = warned_secrets_for_testing_in_shared(a.as_ref());
        let guard = warned
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.contains(&key)
    };
    let contains_in_b = {
        let warned = warned_secrets_for_testing_in_shared(b.as_ref());
        let guard = warned
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.contains(&key)
    };

    assert!(contains_in_a);
    assert!(!contains_in_b);
}

#[test]
fn proxy_shared_state_idle_mark_seq_is_per_instance() {
    let a = ProxySharedState::new();
    let b = ProxySharedState::new();
    clear_relay_idle_pressure_state_for_testing_in_shared(a.as_ref());
    clear_relay_idle_pressure_state_for_testing_in_shared(b.as_ref());

    assert_eq!(relay_idle_mark_seq_for_testing(a.as_ref()), 0);
    assert_eq!(relay_idle_mark_seq_for_testing(b.as_ref()), 0);

    assert!(mark_relay_idle_candidate_for_testing(a.as_ref(), 9001));
    assert_eq!(relay_idle_mark_seq_for_testing(a.as_ref()), 1);
    assert_eq!(relay_idle_mark_seq_for_testing(b.as_ref()), 0);

    assert!(mark_relay_idle_candidate_for_testing(b.as_ref(), 9002));
    assert_eq!(relay_idle_mark_seq_for_testing(a.as_ref()), 1);
    assert_eq!(relay_idle_mark_seq_for_testing(b.as_ref()), 1);
}

#[test]
fn proxy_shared_state_unknown_sni_clear_in_one_instance_does_not_reset_other() {
    let a = ProxySharedState::new();
    let b = ProxySharedState::new();
    clear_unknown_sni_warn_state_for_testing_in_shared(a.as_ref());
    clear_unknown_sni_warn_state_for_testing_in_shared(b.as_ref());

    let now = Instant::now();
    assert!(should_emit_unknown_sni_warn_for_testing_in_shared(
        a.as_ref(),
        now
    ));
    assert!(should_emit_unknown_sni_warn_for_testing_in_shared(
        b.as_ref(),
        now
    ));

    clear_unknown_sni_warn_state_for_testing_in_shared(a.as_ref());
    assert!(should_emit_unknown_sni_warn_for_testing_in_shared(
        a.as_ref(),
        now + Duration::from_millis(1)
    ));
    assert!(!should_emit_unknown_sni_warn_for_testing_in_shared(
        b.as_ref(),
        now + Duration::from_millis(1)
    ));
}

#[test]
fn proxy_shared_state_warned_secret_clear_in_one_instance_does_not_clear_other() {
    let a = ProxySharedState::new();
    let b = ProxySharedState::new();
    clear_warned_secrets_for_testing_in_shared(a.as_ref());
    clear_warned_secrets_for_testing_in_shared(b.as_ref());

    let key = (
        "clear-isolation-user".to_string(),
        "invalid_length".to_string(),
    );
    {
        let warned_a = warned_secrets_for_testing_in_shared(a.as_ref());
        let mut guard_a = warned_a
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard_a.insert(key.clone());

        let warned_b = warned_secrets_for_testing_in_shared(b.as_ref());
        let mut guard_b = warned_b
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard_b.insert(key.clone());
    }

    clear_warned_secrets_for_testing_in_shared(a.as_ref());

    let has_a = {
        let warned = warned_secrets_for_testing_in_shared(a.as_ref());
        let guard = warned
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.contains(&key)
    };
    let has_b = {
        let warned = warned_secrets_for_testing_in_shared(b.as_ref());
        let guard = warned
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.contains(&key)
    };

    assert!(!has_a);
    assert!(has_b);
}

#[test]
fn proxy_shared_state_desync_duplicate_suppression_is_instance_scoped() {
    let a = ProxySharedState::new();
    let b = ProxySharedState::new();
    clear_desync_dedup_for_testing_in_shared(a.as_ref());
    clear_desync_dedup_for_testing_in_shared(b.as_ref());

    let now = Instant::now();
    let key = 0xBEEF_0000_0000_0001u64;
    assert!(should_emit_full_desync_for_testing(
        a.as_ref(),
        key,
        false,
        now
    ));
    assert!(!should_emit_full_desync_for_testing(
        a.as_ref(),
        key,
        false,
        now + Duration::from_millis(1)
    ));
    assert!(should_emit_full_desync_for_testing(
        b.as_ref(),
        key,
        false,
        now
    ));
}

#[test]
fn proxy_shared_state_desync_clear_in_one_instance_does_not_clear_other() {
    let a = ProxySharedState::new();
    let b = ProxySharedState::new();
    clear_desync_dedup_for_testing_in_shared(a.as_ref());
    clear_desync_dedup_for_testing_in_shared(b.as_ref());

    let now = Instant::now();
    let key = 0xCAFE_0000_0000_0001u64;
    assert!(should_emit_full_desync_for_testing(
        a.as_ref(),
        key,
        false,
        now
    ));
    assert!(should_emit_full_desync_for_testing(
        b.as_ref(),
        key,
        false,
        now
    ));

    clear_desync_dedup_for_testing_in_shared(a.as_ref());

    assert!(should_emit_full_desync_for_testing(
        a.as_ref(),
        key,
        false,
        now + Duration::from_millis(2)
    ));
    assert!(!should_emit_full_desync_for_testing(
        b.as_ref(),
        key,
        false,
        now + Duration::from_millis(2)
    ));
}

#[test]
fn proxy_shared_state_idle_candidate_clear_in_one_instance_does_not_affect_other() {
    let a = ProxySharedState::new();
    let b = ProxySharedState::new();
    clear_relay_idle_pressure_state_for_testing_in_shared(a.as_ref());
    clear_relay_idle_pressure_state_for_testing_in_shared(b.as_ref());

    assert!(mark_relay_idle_candidate_for_testing(a.as_ref(), 1001));
    assert!(mark_relay_idle_candidate_for_testing(b.as_ref(), 2002));
    clear_relay_idle_candidate_for_testing(a.as_ref(), 1001);

    assert_eq!(oldest_relay_idle_candidate_for_testing(a.as_ref()), None);
    assert_eq!(
        oldest_relay_idle_candidate_for_testing(b.as_ref()),
        Some(2002)
    );
}

#[test]
fn proxy_shared_state_pressure_seq_increments_are_instance_scoped() {
    let a = ProxySharedState::new();
    let b = ProxySharedState::new();
    clear_relay_idle_pressure_state_for_testing_in_shared(a.as_ref());
    clear_relay_idle_pressure_state_for_testing_in_shared(b.as_ref());

    assert_eq!(relay_pressure_event_seq_for_testing(a.as_ref()), 0);
    assert_eq!(relay_pressure_event_seq_for_testing(b.as_ref()), 0);

    note_relay_pressure_event_for_testing(a.as_ref());
    note_relay_pressure_event_for_testing(a.as_ref());

    assert_eq!(relay_pressure_event_seq_for_testing(a.as_ref()), 2);
    assert_eq!(relay_pressure_event_seq_for_testing(b.as_ref()), 0);
}

#[test]
fn proxy_shared_state_pressure_consumption_does_not_cross_instances() {
    let a = ProxySharedState::new();
    let b = ProxySharedState::new();
    clear_relay_idle_pressure_state_for_testing_in_shared(a.as_ref());
    clear_relay_idle_pressure_state_for_testing_in_shared(b.as_ref());

    assert!(mark_relay_idle_candidate_for_testing(a.as_ref(), 7001));
    assert!(mark_relay_idle_candidate_for_testing(b.as_ref(), 7001));
    note_relay_pressure_event_for_testing(a.as_ref());

    let stats = Stats::new();
    let mut seen_a = 0u64;
    let mut seen_b = 0u64;

    assert!(maybe_evict_idle_candidate_on_pressure_for_testing(
        a.as_ref(),
        7001,
        &mut seen_a,
        &stats
    ));
    assert!(!maybe_evict_idle_candidate_on_pressure_for_testing(
        b.as_ref(),
        7001,
        &mut seen_b,
        &stats
    ));
}
