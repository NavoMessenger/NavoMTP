use super::*;
use crate::config::MeTelemetryLevel;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

#[test]
fn test_stats_shared_counters() {
    let stats = Arc::new(Stats::new());
    stats.increment_connects_all();
    stats.increment_connects_all();
    stats.increment_connects_all();
    assert_eq!(stats.get_connects_all(), 3);
}

#[test]
fn runtime_stats_share_process_connection_admission_authority() {
    let quota_store = Arc::new(QuotaStore::default());
    let authority = Arc::new(UserConnectionAuthority::default());
    let first = Stats::with_process_authorities(Arc::clone(&quota_store), Arc::clone(&authority));
    let second = Stats::with_process_authorities(quota_store, authority);

    let permit = first
        .connection_authority()
        .try_acquire("alice", Some(1))
        .unwrap();
    assert!(
        second
            .connection_authority()
            .try_acquire("alice", Some(1))
            .is_none()
    );

    drop(permit);
    assert!(
        second
            .connection_authority()
            .try_acquire("alice", Some(1))
            .is_some()
    );
}

#[test]
fn test_telemetry_policy_disables_core_and_user_counters() {
    let stats = Stats::new();
    stats.apply_telemetry_policy(TelemetryPolicy {
        core_enabled: false,
        user_enabled: false,
        me_level: MeTelemetryLevel::Normal,
    });

    stats.increment_connects_all();
    stats.increment_user_connects("alice");
    stats.add_user_octets_from("alice", 1024);
    assert_eq!(stats.get_connects_all(), 0);
    assert_eq!(stats.get_user_curr_connects("alice"), 0);
    assert_eq!(stats.get_user_total_octets("alice"), 0);
}

#[test]
fn test_telemetry_policy_me_silent_blocks_me_counters() {
    let stats = Stats::new();
    stats.apply_telemetry_policy(TelemetryPolicy {
        core_enabled: true,
        user_enabled: true,
        me_level: MeTelemetryLevel::Silent,
    });

    stats.increment_me_crc_mismatch();
    stats.increment_me_keepalive_sent();
    stats.increment_me_route_drop_queue_full();
    stats.increment_me_d2c_batches_total();
    stats.add_me_d2c_batch_frames_total(4);
    stats.add_me_d2c_batch_bytes_total(4096);
    stats.increment_me_d2c_flush_reason(MeD2cFlushReason::BatchBytes);
    stats.increment_me_d2c_write_mode(MeD2cWriteMode::Coalesced);
    stats.increment_me_d2c_quota_reject_total(MeD2cQuotaRejectStage::PreWrite);
    stats.observe_me_d2c_frame_buf_shrink(1024);
    stats.observe_me_d2c_batch_frames(4);
    stats.observe_me_d2c_batch_bytes(4096);
    stats.observe_me_d2c_flush_duration_us(120);
    stats.increment_me_d2c_batch_timeout_armed_total();
    stats.increment_me_d2c_batch_timeout_fired_total();
    assert_eq!(stats.get_me_crc_mismatch(), 0);
    assert_eq!(stats.get_me_keepalive_sent(), 0);
    assert_eq!(stats.get_me_route_drop_queue_full(), 0);
    assert_eq!(stats.get_me_d2c_batches_total(), 0);
    assert_eq!(stats.get_me_d2c_flush_reason_batch_bytes_total(), 0);
    assert_eq!(stats.get_me_d2c_write_mode_coalesced_total(), 0);
    assert_eq!(stats.get_me_d2c_quota_reject_pre_write_total(), 0);
    assert_eq!(stats.get_me_d2c_frame_buf_shrink_total(), 0);
    assert_eq!(stats.get_me_d2c_batch_frames_bucket_2_4(), 0);
    assert_eq!(stats.get_me_d2c_batch_bytes_bucket_1k_4k(), 0);
    assert_eq!(stats.get_me_d2c_flush_duration_us_bucket_51_200(), 0);
    assert_eq!(stats.get_me_d2c_batch_timeout_armed_total(), 0);
    assert_eq!(stats.get_me_d2c_batch_timeout_fired_total(), 0);
}

#[test]
fn test_telemetry_policy_me_normal_blocks_d2c_debug_metrics() {
    let stats = Stats::new();
    stats.apply_telemetry_policy(TelemetryPolicy {
        core_enabled: true,
        user_enabled: true,
        me_level: MeTelemetryLevel::Normal,
    });

    stats.increment_me_d2c_batches_total();
    stats.add_me_d2c_batch_frames_total(2);
    stats.add_me_d2c_batch_bytes_total(2048);
    stats.increment_me_d2c_flush_reason(MeD2cFlushReason::QueueDrain);
    stats.observe_me_d2c_batch_frames(2);
    stats.observe_me_d2c_batch_bytes(2048);
    stats.observe_me_d2c_flush_duration_us(100);
    stats.increment_me_d2c_batch_timeout_armed_total();
    stats.increment_me_d2c_batch_timeout_fired_total();

    assert_eq!(stats.get_me_d2c_batches_total(), 1);
    assert_eq!(stats.get_me_d2c_batch_frames_total(), 2);
    assert_eq!(stats.get_me_d2c_batch_bytes_total(), 2048);
    assert_eq!(stats.get_me_d2c_flush_reason_queue_drain_total(), 1);
    assert_eq!(stats.get_me_d2c_batch_frames_bucket_2_4(), 0);
    assert_eq!(stats.get_me_d2c_batch_bytes_bucket_1k_4k(), 0);
    assert_eq!(stats.get_me_d2c_flush_duration_us_bucket_51_200(), 0);
    assert_eq!(stats.get_me_d2c_batch_timeout_armed_total(), 0);
    assert_eq!(stats.get_me_d2c_batch_timeout_fired_total(), 0);
}

#[test]
fn test_telemetry_policy_me_debug_enables_d2c_debug_metrics() {
    let stats = Stats::new();
    stats.apply_telemetry_policy(TelemetryPolicy {
        core_enabled: true,
        user_enabled: true,
        me_level: MeTelemetryLevel::Debug,
    });

    stats.observe_me_d2c_batch_frames(7);
    stats.observe_me_d2c_batch_bytes(70_000);
    stats.observe_me_d2c_flush_duration_us(1400);
    stats.increment_me_d2c_batch_timeout_armed_total();
    stats.increment_me_d2c_batch_timeout_fired_total();

    assert_eq!(stats.get_me_d2c_batch_frames_bucket_5_8(), 1);
    assert_eq!(stats.get_me_d2c_batch_bytes_bucket_64k_128k(), 1);
    assert_eq!(stats.get_me_d2c_flush_duration_us_bucket_1001_5000(), 1);
    assert_eq!(stats.get_me_d2c_batch_timeout_armed_total(), 1);
    assert_eq!(stats.get_me_d2c_batch_timeout_fired_total(), 1);
}

#[test]
fn test_replay_checker_basic() {
    let checker = ReplayChecker::new(100, Duration::from_secs(60));
    assert!(!checker.check_handshake(b"test1")); // first time, inserts
    assert!(checker.check_handshake(b"test1")); // duplicate
    assert!(!checker.check_handshake(b"test2")); // new key inserts
}

#[test]
fn test_replay_checker_duplicate_add() {
    let checker = ReplayChecker::new(100, Duration::from_secs(60));
    checker.add_handshake(b"dup");
    checker.add_handshake(b"dup");
    assert!(checker.check_handshake(b"dup"));
}

#[test]
fn test_replay_checker_expiration() {
    let checker = ReplayChecker::new(100, Duration::from_millis(50));
    assert!(!checker.check_handshake(b"expire"));
    assert!(checker.check_handshake(b"expire"));
    std::thread::sleep(Duration::from_millis(100));
    assert!(!checker.check_handshake(b"expire"));
}

#[test]
fn test_replay_checker_zero_window_does_not_retain_entries() {
    let checker = ReplayChecker::new(100, Duration::ZERO);

    for _ in 0..1_000 {
        assert!(!checker.check_handshake(b"no-retain"));
        checker.add_handshake(b"no-retain");
    }

    let stats = checker.stats();
    assert_eq!(stats.total_entries, 0);
    assert_eq!(stats.total_queue_len, 0);
}

#[test]
fn test_replay_checker_stats() {
    let checker = ReplayChecker::new(100, Duration::from_secs(60));
    assert!(!checker.check_handshake(b"k1"));
    assert!(!checker.check_handshake(b"k2"));
    assert!(checker.check_handshake(b"k1"));
    assert!(!checker.check_handshake(b"k3"));
    let stats = checker.stats();
    assert_eq!(stats.total_additions, 3);
    assert_eq!(stats.total_checks, 4);
    assert_eq!(stats.total_hits, 1);
}

#[test]
fn test_replay_checker_many_keys() {
    let checker = ReplayChecker::new(10_000, Duration::from_secs(60));
    for i in 0..500u32 {
        checker.add_handshake(&i.to_le_bytes());
    }
    for i in 0..500u32 {
        assert!(checker.check_handshake(&i.to_le_bytes()));
    }
    assert_eq!(checker.stats().total_entries, 500);
}

#[test]
fn test_quota_reserve_under_contention_hits_limit_exactly() {
    let user_stats = Arc::new(UserStats::default());
    let successes = Arc::new(AtomicU64::new(0));
    let limit = 8_192u64;
    let mut workers = Vec::new();

    for _ in 0..8 {
        let user_stats = user_stats.clone();
        let successes = successes.clone();
        workers.push(std::thread::spawn(move || {
            loop {
                match user_stats.quota_try_reserve(1, limit) {
                    Ok(_) => {
                        successes.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(QuotaReserveError::Contended) => {
                        std::hint::spin_loop();
                    }
                    Err(QuotaReserveError::LimitExceeded) => {
                        break;
                    }
                }
            }
        }));
    }

    for worker in workers {
        worker.join().expect("worker thread must finish");
    }

    assert_eq!(
        successes.load(Ordering::Relaxed),
        limit,
        "successful reservations must stop exactly at limit"
    );
    assert_eq!(user_stats.quota_used(), limit);
}

#[test]
fn test_quota_reserve_200x_1k_reaches_100k_without_overshoot() {
    let user_stats = Arc::new(UserStats::default());
    let successes = Arc::new(AtomicU64::new(0));
    let failures = Arc::new(AtomicU64::new(0));
    let attempts = 200usize;
    let reserve_bytes = 1_024u64;
    let limit = 100 * 1_024u64;
    let mut workers = Vec::with_capacity(attempts);

    for _ in 0..attempts {
        let user_stats = user_stats.clone();
        let successes = successes.clone();
        let failures = failures.clone();
        workers.push(std::thread::spawn(move || {
            loop {
                match user_stats.quota_try_reserve(reserve_bytes, limit) {
                    Ok(_) => {
                        successes.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                    Err(QuotaReserveError::LimitExceeded) => {
                        failures.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                    Err(QuotaReserveError::Contended) => {
                        std::hint::spin_loop();
                    }
                }
            }
        }));
    }

    for worker in workers {
        worker.join().expect("reservation worker must finish");
    }

    assert_eq!(
        successes.load(Ordering::Relaxed),
        100,
        "exactly 100 reservations of 1 KiB must fit into a 100 KiB quota"
    );
    assert_eq!(
        failures.load(Ordering::Relaxed),
        100,
        "remaining workers must fail once quota is fully reserved"
    );
    assert_eq!(user_stats.quota_used(), limit);
}

#[test]
fn test_quota_used_is_authoritative_and_independent_from_octets_telemetry() {
    let stats = Stats::new();
    let user = "quota-authoritative-user";
    let user_stats = stats.get_or_create_user_stats_handle(user);

    stats.add_user_octets_to_handle(&user_stats, 5);
    assert_eq!(stats.get_user_total_octets(user), 5);
    assert_eq!(stats.get_user_quota_used(user), 0);

    stats.quota_charge_post_write(&user_stats, 7);
    assert_eq!(stats.get_user_total_octets(user), 5);
    assert_eq!(stats.get_user_quota_used(user), 7);
}

#[test]
fn old_quota_reservation_refund_does_not_reduce_post_reset_usage() {
    let stats = Stats::new();
    let user = "quota-reset-generation-user";
    let user_stats = stats.get_or_create_user_stats_handle(user);
    let reservation = user_stats.quota_reserve(80, 100).unwrap();

    stats.reset_user_quota(user);
    stats.quota_charge_post_write(user_stats.as_ref(), 40);
    drop(reservation);

    assert_eq!(stats.get_user_quota_used(user), 40);
}

#[test]
fn test_cached_handle_survives_map_cleanup_until_last_drop() {
    let stats = Stats::new();
    let user = "quota-handle-lifetime-user";
    let user_stats = stats.get_or_create_user_stats_handle(user);
    let weak = Arc::downgrade(&user_stats);

    stats.user_stats.remove(user);
    assert!(
        stats.user_stats.get(user).is_none(),
        "map cleanup should remove idle entry"
    );
    assert!(
        weak.upgrade().is_some(),
        "cached handle must keep user stats object alive after map removal"
    );

    stats.quota_charge_post_write(user_stats.as_ref(), 3);
    assert_eq!(user_stats.quota_used(), 3);

    drop(user_stats);
    assert!(
        weak.upgrade().is_none(),
        "user stats object must be dropped after the last cached handle is released"
    );
}
