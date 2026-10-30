use super::*;
use std::time::{Duration, Instant};

#[test]
fn middle_relay_baseline_public_api_idle_roundtrip_contract() {
    let shared = ProxySharedState::new();
    clear_relay_idle_pressure_state_for_testing_in_shared(shared.as_ref());

    assert!(mark_relay_idle_candidate_for_testing(shared.as_ref(), 7001));
    assert_eq!(
        oldest_relay_idle_candidate_for_testing(shared.as_ref()),
        Some(7001)
    );

    clear_relay_idle_candidate_for_testing(shared.as_ref(), 7001);
    assert_ne!(
        oldest_relay_idle_candidate_for_testing(shared.as_ref()),
        Some(7001)
    );

    assert!(mark_relay_idle_candidate_for_testing(shared.as_ref(), 7001));
    assert_eq!(
        oldest_relay_idle_candidate_for_testing(shared.as_ref()),
        Some(7001)
    );

    clear_relay_idle_pressure_state_for_testing_in_shared(shared.as_ref());
}

#[test]
fn middle_relay_baseline_public_api_desync_window_contract() {
    let shared = ProxySharedState::new();
    clear_desync_dedup_for_testing_in_shared(shared.as_ref());

    let key = 0xDEAD_BEEF_0000_0001u64;
    let t0 = Instant::now();

    assert!(should_emit_full_desync_for_testing(
        shared.as_ref(),
        key,
        false,
        t0
    ));
    assert!(!should_emit_full_desync_for_testing(
        shared.as_ref(),
        key,
        false,
        t0 + Duration::from_secs(1)
    ));

    let t1 = t0 + DESYNC_DEDUP_WINDOW + Duration::from_millis(10);
    assert!(should_emit_full_desync_for_testing(
        shared.as_ref(),
        key,
        false,
        t1
    ));

    clear_desync_dedup_for_testing_in_shared(shared.as_ref());
}
