use crate::proxy::handshake::{
    auth_probe_fail_streak_for_testing_in_shared, auth_probe_record_failure_for_testing,
    clear_auth_probe_state_for_testing_in_shared,
    clear_unknown_sni_warn_state_for_testing_in_shared,
    should_emit_unknown_sni_warn_for_testing_in_shared,
};
use crate::proxy::middle_relay::{
    clear_desync_dedup_for_testing_in_shared,
    clear_relay_idle_pressure_state_for_testing_in_shared, mark_relay_idle_candidate_for_testing,
    oldest_relay_idle_candidate_for_testing, should_emit_full_desync_for_testing,
};
use crate::proxy::shared_state::ProxySharedState;
use rand::RngExt;
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Barrier;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_shared_state_50_concurrent_instances_no_counter_bleed() {
    let mut handles = Vec::new();
    for i in 0..50_u8 {
        handles.push(tokio::spawn(async move {
            let shared = ProxySharedState::new();
            clear_auth_probe_state_for_testing_in_shared(shared.as_ref());
            let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 200));
            auth_probe_record_failure_for_testing(shared.as_ref(), ip, Instant::now());
            auth_probe_fail_streak_for_testing_in_shared(shared.as_ref(), ip)
        }));
    }

    for handle in handles {
        let streak = handle.await.expect("task join failed");
        assert_eq!(streak, Some(1));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_shared_state_desync_rotation_concurrent_20_instances() {
    let now = Instant::now();
    let key = 0xD35E_D35E_u64;
    let mut handles = Vec::new();
    for _ in 0..20_u64 {
        handles.push(tokio::spawn(async move {
            let shared = ProxySharedState::new();
            clear_desync_dedup_for_testing_in_shared(shared.as_ref());
            should_emit_full_desync_for_testing(shared.as_ref(), key, false, now)
        }));
    }

    for handle in handles {
        let emitted = handle.await.expect("task join failed");
        assert!(emitted);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_shared_state_idle_registry_concurrent_10_instances() {
    let mut handles = Vec::new();
    let conn_id = 42_u64;
    for _ in 1..=10_u64 {
        handles.push(tokio::spawn(async move {
            let shared = ProxySharedState::new();
            clear_relay_idle_pressure_state_for_testing_in_shared(shared.as_ref());
            let marked = mark_relay_idle_candidate_for_testing(shared.as_ref(), conn_id);
            let oldest = oldest_relay_idle_candidate_for_testing(shared.as_ref());
            (marked, oldest)
        }));
    }

    for (i, handle) in handles.into_iter().enumerate() {
        let (marked, oldest) = handle.await.expect("task join failed");
        assert!(marked, "instance {} failed to mark", i);
        assert_eq!(oldest, Some(conn_id));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_shared_state_dual_instance_same_ip_high_contention_no_counter_bleed() {
    let a = ProxySharedState::new();
    let b = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(a.as_ref());
    clear_auth_probe_state_for_testing_in_shared(b.as_ref());

    let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 200));
    let mut handles = Vec::new();

    for _ in 0..64 {
        let a = a.clone();
        let b = b.clone();
        handles.push(tokio::spawn(async move {
            auth_probe_record_failure_for_testing(a.as_ref(), ip, Instant::now());
            auth_probe_record_failure_for_testing(b.as_ref(), ip, Instant::now());
        }));
    }

    for handle in handles {
        handle.await.expect("task join failed");
    }

    assert_eq!(
        auth_probe_fail_streak_for_testing_in_shared(a.as_ref(), ip),
        Some(64)
    );
    assert_eq!(
        auth_probe_fail_streak_for_testing_in_shared(b.as_ref(), ip),
        Some(64)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_shared_state_unknown_sni_parallel_instances_no_cross_cooldown() {
    let mut handles = Vec::new();
    let now = Instant::now();

    for _ in 0..32 {
        handles.push(tokio::spawn(async move {
            let shared = ProxySharedState::new();
            clear_unknown_sni_warn_state_for_testing_in_shared(shared.as_ref());
            let first = should_emit_unknown_sni_warn_for_testing_in_shared(shared.as_ref(), now);
            let second = should_emit_unknown_sni_warn_for_testing_in_shared(
                shared.as_ref(),
                now + std::time::Duration::from_millis(1),
            );
            (first, second)
        }));
    }

    for handle in handles {
        let (first, second) = handle.await.expect("task join failed");
        assert!(first);
        assert!(!second);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_shared_state_auth_probe_high_contention_increments_are_lossless() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 33));
    let workers = 128usize;
    let rounds = 20usize;

    for _ in 0..rounds {
        let start = Arc::new(Barrier::new(workers));
        let mut handles = Vec::with_capacity(workers);

        for _ in 0..workers {
            let shared = shared.clone();
            let start = start.clone();
            handles.push(tokio::spawn(async move {
                start.wait().await;
                auth_probe_record_failure_for_testing(shared.as_ref(), ip, Instant::now());
            }));
        }

        for handle in handles {
            handle.await.expect("task join failed");
        }
    }

    let expected = (workers * rounds) as u32;
    assert_eq!(
        auth_probe_fail_streak_for_testing_in_shared(shared.as_ref(), ip),
        Some(expected),
        "auth probe fail streak must account for every concurrent update"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_shared_state_seed_matrix_concurrency_isolation_no_counter_bleed() {
    let seeds: [u64; 8] = [
        0x0000_0000_0000_0001,
        0x1111_1111_1111_1111,
        0xA5A5_A5A5_A5A5_A5A5,
        0xDEAD_BEEF_CAFE_BABE,
        0x0123_4567_89AB_CDEF,
        0xFEDC_BA98_7654_3210,
        0x0F0F_F0F0_55AA_AA55,
        0x1357_9BDF_2468_ACE0,
    ];

    for seed in seeds {
        let mut rng = StdRng::seed_from_u64(seed);
        let shared_a = ProxySharedState::new();
        let shared_b = ProxySharedState::new();
        clear_auth_probe_state_for_testing_in_shared(shared_a.as_ref());
        clear_auth_probe_state_for_testing_in_shared(shared_b.as_ref());

        let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, rng.random_range(1_u8..=250_u8)));
        let workers = rng.random_range(16_usize..=48_usize);
        let rounds = rng.random_range(4_usize..=10_usize);

        let mut expected_a: u32 = 0;
        let mut expected_b: u32 = 0;

        for _ in 0..rounds {
            let start = Arc::new(Barrier::new(workers * 2));
            let mut handles = Vec::with_capacity(workers * 2);

            for _ in 0..workers {
                let a_ops = rng.random_range(1_u32..=3_u32);
                let b_ops = rng.random_range(1_u32..=3_u32);
                expected_a = expected_a.saturating_add(a_ops);
                expected_b = expected_b.saturating_add(b_ops);

                let shared_a = shared_a.clone();
                let start_a = start.clone();
                handles.push(tokio::spawn(async move {
                    start_a.wait().await;
                    for _ in 0..a_ops {
                        auth_probe_record_failure_for_testing(
                            shared_a.as_ref(),
                            ip,
                            Instant::now(),
                        );
                    }
                }));

                let shared_b = shared_b.clone();
                let start_b = start.clone();
                handles.push(tokio::spawn(async move {
                    start_b.wait().await;
                    for _ in 0..b_ops {
                        auth_probe_record_failure_for_testing(
                            shared_b.as_ref(),
                            ip,
                            Instant::now(),
                        );
                    }
                }));
            }

            for handle in handles {
                handle.await.expect("task join failed");
            }
        }

        assert_eq!(
            auth_probe_fail_streak_for_testing_in_shared(shared_a.as_ref(), ip),
            Some(expected_a),
            "seed {seed:#x}: instance A streak mismatch"
        );
        assert_eq!(
            auth_probe_fail_streak_for_testing_in_shared(shared_b.as_ref(), ip),
            Some(expected_b),
            "seed {seed:#x}: instance B streak mismatch"
        );

        clear_auth_probe_state_for_testing_in_shared(shared_a.as_ref());
        assert_eq!(
            auth_probe_fail_streak_for_testing_in_shared(shared_a.as_ref(), ip),
            None,
            "seed {seed:#x}: clearing A must reset only A"
        );
        assert_eq!(
            auth_probe_fail_streak_for_testing_in_shared(shared_b.as_ref(), ip),
            Some(expected_b),
            "seed {seed:#x}: clearing A must not mutate B"
        );
    }
}
