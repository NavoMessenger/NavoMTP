use super::*;

fn store(records_capacity: usize, bytes_capacity: usize) -> Arc<WebTraceStore> {
    let policy = WebDebugConfig {
        enabled: true,
        ..Default::default()
    };
    let limits = WebLimitsConfig {
        debug_records_capacity: records_capacity,
        debug_bytes_global: bytes_capacity,
        ..Default::default()
    };
    WebTraceStore::new(policy, &limits)
}

#[test]
fn ring_evicts_oldest_records_and_snapshot_leases_survive_clear() {
    let store = store(2, 4 * BASE_RECORD_RESERVATION);
    for _ in 0..3 {
        store.record_lifecycle(
            None,
            Some("192.0.2.10".parse().unwrap()),
            TraceIdentity::default(),
            TraceLifecycleEvent::BridgeIssued,
            None,
            None,
        );
    }

    let snapshot = store.snapshot_matching(|_| true);
    assert_eq!(
        snapshot
            .iter()
            .map(|record| record.record.seq)
            .collect::<Vec<_>>(),
        vec![3, 2]
    );
    assert_eq!(store.status().evictions, 1);
    assert_eq!(store.status().used_bytes, 2 * BASE_RECORD_RESERVATION);

    let policy = WebDebugConfig::default();
    store.apply_policy(2, &policy);
    assert_eq!(store.status().records, 0);
    assert_eq!(store.status().used_bytes, 2 * BASE_RECORD_RESERVATION);
    drop(snapshot);
    assert_eq!(store.status().used_bytes, 0);
}

#[test]
fn capture_policy_epoch_rejects_an_inflight_old_policy_record() {
    let store = store(4, 8 * BASE_RECORD_RESERVATION);
    let request = hyper::Request::builder().uri("/").body(()).unwrap();
    let exchange = store
        .begin_http(&request, "192.0.2.20".parse().unwrap())
        .unwrap();

    let changed = WebDebugConfig {
        enabled: true,
        capture_headers: false,
        ..Default::default()
    };
    store.apply_policy(2, &changed);
    exchange.commit();

    assert_eq!(store.status().records, 0);
    assert_eq!(store.status().used_bytes, 0);
}

#[test]
fn stale_generation_cannot_restore_an_old_policy() {
    let store = store(4, 8 * BASE_RECORD_RESERVATION);
    let current = WebDebugConfig {
        enabled: true,
        capture_headers: false,
        ..Default::default()
    };
    store.apply_policy(3, &current);

    store.apply_policy(2, &WebDebugConfig::default());

    let status = store.status();
    assert_eq!(status.policy_generation, 3);
    assert_eq!(status.policy.as_ref(), &current);
}

#[test]
fn bridge_diagnostic_policy_toggle_preserves_existing_records_and_epoch() {
    let store = store(4, 8 * BASE_RECORD_RESERVATION);
    store.record_lifecycle(
        None,
        Some("192.0.2.25".parse().unwrap()),
        TraceIdentity::default(),
        TraceLifecycleEvent::BridgeIssued,
        None,
        None,
    );
    let before = store.status();
    let mut policy = before.policy.as_ref().clone();
    policy.sideband = true;

    store.apply_policy(2, &policy);

    let after = store.status();
    assert!(after.policy.sideband);
    assert_eq!(after.policy_generation, 2);
    assert_eq!(after.epoch, before.epoch);
    assert_eq!(after.records, before.records);
}

#[test]
fn explicit_clear_fences_inflight_commits_and_preserves_snapshot_leases() {
    let store = store(4, 8 * BASE_RECORD_RESERVATION);
    store.record_lifecycle(
        None,
        Some("192.0.2.30".parse().unwrap()),
        TraceIdentity::default(),
        TraceLifecycleEvent::BridgeIssued,
        None,
        None,
    );
    let snapshot = store.snapshot_matching(|_| true);
    let request = hyper::Request::builder().uri("/").body(()).unwrap();
    let exchange = store
        .begin_http(&request, "192.0.2.30".parse().unwrap())
        .unwrap();

    let cleared = store.clear();
    exchange.commit();

    assert_eq!(cleared.records_cleared, 1);
    assert_eq!(store.status().records, 0);
    assert_eq!(store.status().used_bytes, BASE_RECORD_RESERVATION);
    drop(snapshot);
    assert_eq!(store.status().used_bytes, 0);
}

#[test]
fn lifecycle_context_retains_only_bounded_non_secret_correlations() {
    let store = store(2, 4 * BASE_RECORD_RESERVATION);
    store.record_lifecycle_with_context(
        None,
        Some("192.0.2.40".parse().unwrap()),
        TraceIdentity::default(),
        TraceLifecycleEvent::SessionClosed,
        None,
        Some("bridge_recovery"),
        TraceLifecycleContext {
            peer_gap_ms: Some(125_000),
            predecessor_session_id: Some(41),
        },
    );

    let snapshot = store.snapshot_matching(|_| true);
    let TraceRecordKind::Lifecycle(event) = &snapshot[0].record.kind else {
        panic!("expected lifecycle record");
    };
    assert_eq!(event.reason, Some("bridge_recovery"));
    assert_eq!(event.peer_gap_ms, Some(125_000));
    assert_eq!(event.predecessor_session_id, Some(41));
}
