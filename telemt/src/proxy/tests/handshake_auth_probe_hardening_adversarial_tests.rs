use super::*;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

#[test]
fn positive_preauth_throttle_activates_after_failure_threshold() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 20));
    let now = Instant::now();

    for _ in 0..AUTH_PROBE_BACKOFF_START_FAILS {
        auth_probe_record_failure_in(shared.as_ref(), ip, now);
    }

    assert!(
        auth_probe_is_throttled_in(shared.as_ref(), ip, now),
        "peer must be throttled once fail streak reaches threshold"
    );
}

#[test]
fn negative_unrelated_peer_remains_unthrottled() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let attacker = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 12));
    let benign = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 13));
    let now = Instant::now();

    for _ in 0..AUTH_PROBE_BACKOFF_START_FAILS {
        auth_probe_record_failure_in(shared.as_ref(), attacker, now);
    }

    assert!(auth_probe_is_throttled_in(shared.as_ref(), attacker, now));
    assert!(
        !auth_probe_is_throttled_in(shared.as_ref(), benign, now),
        "throttle state must stay scoped to normalized peer key"
    );
}

#[test]
fn edge_expired_entry_is_pruned_and_no_longer_throttled() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 41));
    let base = Instant::now();
    for _ in 0..AUTH_PROBE_BACKOFF_START_FAILS {
        auth_probe_record_failure_in(shared.as_ref(), ip, base);
    }

    let expired_at = base + Duration::from_secs(AUTH_PROBE_TRACK_RETENTION_SECS + 1);
    assert!(
        !auth_probe_is_throttled_in(shared.as_ref(), ip, expired_at),
        "expired entries must not keep throttling peers"
    );

    let state = auth_probe_state_for_testing_in_shared(shared.as_ref());
    assert!(
        state.get(&normalize_auth_probe_ip(ip)).is_none(),
        "expired lookup should prune stale state"
    );
}

#[test]
fn adversarial_saturation_grace_requires_extra_failures_before_preauth_throttle() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let ip = IpAddr::V4(Ipv4Addr::new(198, 18, 0, 7));
    let now = Instant::now();

    for _ in 0..AUTH_PROBE_BACKOFF_START_FAILS {
        auth_probe_record_failure_in(shared.as_ref(), ip, now);
    }
    auth_probe_note_saturation_in(shared.as_ref(), now);

    assert!(
        !auth_probe_should_apply_preauth_throttle_in(shared.as_ref(), ip, now),
        "during global saturation, peer must receive configured grace window"
    );

    for _ in 0..AUTH_PROBE_SATURATION_GRACE_FAILS {
        auth_probe_record_failure_in(shared.as_ref(), ip, now + Duration::from_millis(1));
    }

    assert!(
        auth_probe_should_apply_preauth_throttle_in(
            shared.as_ref(),
            ip,
            now + Duration::from_millis(1)
        ),
        "after grace failures are exhausted, preauth throttle must activate"
    );
}

#[test]
fn integration_over_cap_insertion_keeps_probe_map_bounded() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let now = Instant::now();
    for idx in 0..(AUTH_PROBE_TRACK_MAX_ENTRIES + 1024) {
        let ip = IpAddr::V4(Ipv4Addr::new(
            10,
            ((idx / 65_536) % 256) as u8,
            ((idx / 256) % 256) as u8,
            (idx % 256) as u8,
        ));
        auth_probe_record_failure_in(shared.as_ref(), ip, now);
    }

    let tracked = auth_probe_state_for_testing_in_shared(shared.as_ref()).len();
    assert!(
        tracked <= AUTH_PROBE_TRACK_MAX_ENTRIES,
        "probe map must remain hard bounded under insertion storm"
    );
}

#[test]
fn light_fuzz_randomized_failures_preserve_cap_and_nonzero_streaks() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let mut seed = 0x4D53_5854_6F66_6175u64;
    let now = Instant::now();

    for _ in 0..8192 {
        seed ^= seed << 7;
        seed ^= seed >> 9;
        seed ^= seed << 8;

        let ip = IpAddr::V4(Ipv4Addr::new(
            (seed >> 24) as u8,
            (seed >> 16) as u8,
            (seed >> 8) as u8,
            seed as u8,
        ));
        auth_probe_record_failure_in(
            shared.as_ref(),
            ip,
            now + Duration::from_millis((seed & 0x3f) as u64),
        );
    }

    let state = auth_probe_state_for_testing_in_shared(shared.as_ref());
    assert!(state.len() <= AUTH_PROBE_TRACK_MAX_ENTRIES);
    for entry in state.iter() {
        assert!(entry.value().fail_streak > 0);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_parallel_failure_flood_keeps_state_hard_capped() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let start = Instant::now();
    let mut tasks = Vec::new();

    for worker in 0..8u8 {
        let shared = shared.clone();
        tasks.push(tokio::spawn(async move {
            for i in 0..4096u32 {
                let ip = IpAddr::V4(Ipv4Addr::new(
                    172,
                    worker,
                    ((i >> 8) & 0xff) as u8,
                    (i & 0xff) as u8,
                ));
                auth_probe_record_failure_in(
                    shared.as_ref(),
                    ip,
                    start + Duration::from_millis((i % 4) as u64),
                );
            }
        }));
    }

    for task in tasks {
        task.await.expect("stress worker must not panic");
    }

    let tracked = auth_probe_state_for_testing_in_shared(shared.as_ref()).len();
    assert!(
        tracked <= AUTH_PROBE_TRACK_MAX_ENTRIES,
        "parallel failure flood must not exceed cap"
    );

    let probe = IpAddr::V4(Ipv4Addr::new(172, 3, 4, 5));
    let _ = auth_probe_is_throttled_in(shared.as_ref(), probe, start + Duration::from_millis(2));
}
