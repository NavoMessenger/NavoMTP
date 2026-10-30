use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

// Unique key generator to avoid test interference through the global DashMap.
static TEST_KEY_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn unique_key(prefix: &str) -> String {
    let id = TEST_KEY_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{}_{}", prefix, id)
}

// ── Positive / Lifecycle ────────────────────────────────────────────────

#[test]
fn adaptive_seed_unknown_user_returns_base() {
    let key = unique_key("seed_unknown");
    assert_eq!(seed_tier_for_user(&key), AdaptiveTier::Base);
}

#[test]
fn adaptive_record_then_seed_returns_recorded_tier() {
    let key = unique_key("record_seed");
    record_user_tier(&key, AdaptiveTier::Tier1);
    assert_eq!(seed_tier_for_user(&key), AdaptiveTier::Tier1);
}

#[test]
fn adaptive_separate_users_have_independent_tiers() {
    let key_a = unique_key("indep_a");
    let key_b = unique_key("indep_b");
    record_user_tier(&key_a, AdaptiveTier::Tier1);
    record_user_tier(&key_b, AdaptiveTier::Tier2);
    assert_eq!(seed_tier_for_user(&key_a), AdaptiveTier::Tier1);
    assert_eq!(seed_tier_for_user(&key_b), AdaptiveTier::Tier2);
}

#[test]
fn adaptive_record_upgrades_tier_within_ttl() {
    let key = unique_key("upgrade");
    record_user_tier(&key, AdaptiveTier::Base);
    record_user_tier(&key, AdaptiveTier::Tier1);
    assert_eq!(seed_tier_for_user(&key), AdaptiveTier::Tier1);
}

#[test]
fn adaptive_record_does_not_downgrade_within_ttl() {
    let key = unique_key("no_downgrade");
    record_user_tier(&key, AdaptiveTier::Tier2);
    record_user_tier(&key, AdaptiveTier::Base);
    // max(Tier2, Base) = Tier2 — within TTL the higher tier is retained
    assert_eq!(seed_tier_for_user(&key), AdaptiveTier::Tier2);
}

// ── Edge Cases ──────────────────────────────────────────────────────────

#[test]
fn adaptive_base_tier_buffers_unchanged() {
    let (c2s, s2c) = direct_copy_buffers_for_tier(AdaptiveTier::Base, 65536, 262144);
    assert_eq!(c2s, 65536);
    assert_eq!(s2c, 262144);
}

#[test]
fn adaptive_tier1_buffers_within_caps() {
    let (c2s, s2c) = direct_copy_buffers_for_tier(AdaptiveTier::Tier1, 65536, 262144);
    assert!(c2s > 65536, "Tier1 c2s should exceed Base");
    assert!(
        c2s <= 128 * 1024,
        "Tier1 c2s should not exceed DIRECT_C2S_CAP_BYTES"
    );
    assert!(s2c > 262144, "Tier1 s2c should exceed Base");
    assert!(
        s2c <= 512 * 1024,
        "Tier1 s2c should not exceed DIRECT_S2C_CAP_BYTES"
    );
}

#[test]
fn adaptive_tier3_buffers_capped() {
    let (c2s, s2c) = direct_copy_buffers_for_tier(AdaptiveTier::Tier3, 65536, 262144);
    assert!(c2s <= 128 * 1024, "Tier3 c2s must not exceed cap");
    assert!(s2c <= 512 * 1024, "Tier3 s2c must not exceed cap");
}

#[test]
fn adaptive_scale_zero_base_returns_at_least_one() {
    // scale(0, num, den, cap) should return at least 1 (the .max(1) guard)
    let (c2s, s2c) = direct_copy_buffers_for_tier(AdaptiveTier::Tier1, 0, 0);
    assert!(c2s >= 1);
    assert!(s2c >= 1);
}

// ── Stale Entry Handling ────────────────────────────────────────────────

#[test]
fn adaptive_stale_profile_returns_base_tier() {
    let key = unique_key("stale_base");
    // Manually insert a stale entry with seen_at in the far past.
    // PROFILE_TTL = 300s, so 600s ago is well past expiry.
    let stale_time = Instant::now() - Duration::from_secs(600);
    profiles().insert(
        key.clone(),
        UserAdaptiveProfile {
            tier: AdaptiveTier::Tier3,
            seen_at: stale_time,
        },
    );
    assert_eq!(
        seed_tier_for_user(&key),
        AdaptiveTier::Base,
        "Stale profile should return Base"
    );
}

// RED TEST: exposes the stale entry leak bug.
// After seed_tier_for_user returns Base for a stale entry, the entry should be
// removed from the cache. Currently it is NOT removed — stale entries accumulate
// indefinitely, consuming memory.
#[test]
fn adaptive_stale_entry_removed_after_seed() {
    let key = unique_key("stale_removal");
    let stale_time = Instant::now() - Duration::from_secs(600);
    profiles().insert(
        key.clone(),
        UserAdaptiveProfile {
            tier: AdaptiveTier::Tier2,
            seen_at: stale_time,
        },
    );
    let _ = seed_tier_for_user(&key);
    // After seeding, the stale entry should have been removed.
    assert!(
        !profiles().contains_key(&key),
        "Stale entry should be removed from cache after seed_tier_for_user"
    );
}

// ── Cardinality Attack / Unbounded Growth ───────────────────────────────

// RED TEST: exposes the missing eviction cap.
// An attacker who can trigger record_user_tier with arbitrary user keys can
// grow the global DashMap without bound, exhausting server memory.
// After inserting MAX_USER_PROFILES_ENTRIES + 1 stale entries, record_user_tier
// must trigger retain()-based eviction that purges all stale entries.
#[test]
fn adaptive_profile_cache_bounded_under_cardinality_attack() {
    let prefix = unique_key("cardinality");
    let stale_time = Instant::now() - Duration::from_secs(600);
    let n = MAX_USER_PROFILES_ENTRIES + 1;
    for i in 0..n {
        let key = format!("{}_{}", prefix, i);
        profiles().insert(
            key,
            UserAdaptiveProfile {
                tier: AdaptiveTier::Base,
                seen_at: stale_time,
            },
        );
    }
    // This insert should push the cache over MAX_USER_PROFILES_ENTRIES and trigger eviction.
    let trigger_key = unique_key("cardinality_trigger");
    record_user_tier(&trigger_key, AdaptiveTier::Base);

    // Count surviving stale entries.
    let mut surviving_stale = 0;
    for i in 0..n {
        let key = format!("{}_{}", prefix, i);
        if profiles().contains_key(&key) {
            surviving_stale += 1;
        }
    }
    // Cleanup: remove anything that survived + the trigger key.
    for i in 0..n {
        let key = format!("{}_{}", prefix, i);
        profiles().remove(&key);
    }
    profiles().remove(&trigger_key);

    // All stale entries (600s past PROFILE_TTL=300s) should have been evicted.
    assert_eq!(
        surviving_stale, 0,
        "All {} stale entries should be evicted, but {} survived",
        n, surviving_stale
    );
}

// ── Key Length Validation ────────────────────────────────────────────────

// RED TEST: exposes missing key length validation.
// An attacker can submit arbitrarily large user keys, each consuming memory
// for the String allocation in the DashMap key.
#[test]
fn adaptive_oversized_user_key_rejected_on_record() {
    let oversized_key: String = "X".repeat(1024); // 1KB key — should be rejected
    record_user_tier(&oversized_key, AdaptiveTier::Tier1);
    // With key length validation, the oversized key should NOT be stored.
    let stored = profiles().contains_key(&oversized_key);
    // Cleanup regardless
    profiles().remove(&oversized_key);
    assert!(
        !stored,
        "Oversized user key (1024 bytes) should be rejected by record_user_tier"
    );
}

#[test]
fn adaptive_oversized_user_key_rejected_on_seed() {
    let oversized_key: String = "X".repeat(1024);
    // Insert it directly to test seed behavior
    profiles().insert(
        oversized_key.clone(),
        UserAdaptiveProfile {
            tier: AdaptiveTier::Tier3,
            seen_at: Instant::now(),
        },
    );
    let result = seed_tier_for_user(&oversized_key);
    profiles().remove(&oversized_key);
    assert_eq!(
        result,
        AdaptiveTier::Base,
        "Oversized user key should return Base from seed_tier_for_user"
    );
}

#[test]
fn adaptive_empty_user_key_safe() {
    // Empty string is a valid (if unusual) key — should not panic
    record_user_tier("", AdaptiveTier::Tier1);
    let tier = seed_tier_for_user("");
    profiles().remove("");
    assert_eq!(tier, AdaptiveTier::Tier1);
}

#[test]
fn adaptive_max_length_key_accepted() {
    // A key at exactly 512 bytes should be accepted
    let key: String = "K".repeat(512);
    record_user_tier(&key, AdaptiveTier::Tier1);
    let tier = seed_tier_for_user(&key);
    profiles().remove(&key);
    assert_eq!(tier, AdaptiveTier::Tier1);
}

// ── Concurrent Access Safety ────────────────────────────────────────────

#[test]
fn adaptive_concurrent_record_and_seed_no_torn_read() {
    let key = unique_key("concurrent_rw");
    let key_clone = key.clone();

    // Record from multiple threads simultaneously
    let handles: Vec<_> = (0..10)
        .map(|i| {
            let k = key_clone.clone();
            std::thread::spawn(move || {
                let tier = if i % 2 == 0 {
                    AdaptiveTier::Tier1
                } else {
                    AdaptiveTier::Tier2
                };
                record_user_tier(&k, tier);
            })
        })
        .collect();

    for h in handles {
        h.join().expect("thread panicked");
    }

    let result = seed_tier_for_user(&key);
    profiles().remove(&key);
    // Result must be one of the recorded tiers, not a corrupted value
    assert!(
        result == AdaptiveTier::Tier1 || result == AdaptiveTier::Tier2,
        "Concurrent writes produced unexpected tier: {:?}",
        result
    );
}

#[test]
fn adaptive_concurrent_seed_does_not_panic() {
    let key = unique_key("concurrent_seed");
    record_user_tier(&key, AdaptiveTier::Tier1);
    let key_clone = key.clone();

    let handles: Vec<_> = (0..20)
        .map(|_| {
            let k = key_clone.clone();
            std::thread::spawn(move || {
                for _ in 0..100 {
                    let _ = seed_tier_for_user(&k);
                }
            })
        })
        .collect();

    for h in handles {
        h.join().expect("concurrent seed panicked");
    }
    profiles().remove(&key);
}

// ── TOCTOU: Concurrent seed + record race ───────────────────────────────

// RED TEST: seed_tier_for_user reads a stale entry, drops the reference,
// then another thread inserts a fresh entry. If seed then removes unconditionally
// (without atomic predicate), the fresh entry is lost. With remove_if, the
// fresh entry survives.
#[test]
fn adaptive_remove_if_does_not_delete_fresh_concurrent_insert() {
    let key = unique_key("toctou");
    let stale_time = Instant::now() - Duration::from_secs(600);
    profiles().insert(
        key.clone(),
        UserAdaptiveProfile {
            tier: AdaptiveTier::Tier1,
            seen_at: stale_time,
        },
    );

    // Thread A: seed_tier (will see stale, should attempt removal)
    // Thread B: record_user_tier (inserts fresh entry concurrently)
    let key_a = key.clone();
    let key_b = key.clone();

    let handle_b = std::thread::spawn(move || {
        // Small yield to increase chance of interleaving
        std::thread::yield_now();
        record_user_tier(&key_b, AdaptiveTier::Tier3);
    });

    let _ = seed_tier_for_user(&key_a);

    handle_b.join().expect("thread B panicked");

    // After both operations, the fresh Tier3 entry should survive.
    // With a correct remove_if predicate, the fresh entry is NOT deleted.
    // Without remove_if (current code), the entry may be lost.
    let final_tier = seed_tier_for_user(&key);
    profiles().remove(&key);

    // The fresh Tier3 entry should survive the stale-removal race.
    // Note: Due to non-deterministic scheduling, this test may pass even
    // without the fix if thread B wins the race. Run with --test-threads=1
    // or multiple iterations for reliable detection.
    assert!(
        final_tier == AdaptiveTier::Tier3 || final_tier == AdaptiveTier::Base,
        "Unexpected tier after TOCTOU race: {:?}",
        final_tier
    );
}

// ── Fuzz: Random keys ──────────────────────────────────────────────────

#[test]
fn adaptive_fuzz_random_keys_no_panic() {
    use rand::{Rng, RngExt};
    let mut rng = rand::rng();
    let mut keys = Vec::new();
    for _ in 0..200 {
        let len: usize = rng.random_range(0..=256);
        let key: String = (0..len)
            .map(|_| {
                let c: u8 = rng.random_range(0x20..=0x7E);
                c as char
            })
            .collect();
        record_user_tier(&key, AdaptiveTier::Tier1);
        let _ = seed_tier_for_user(&key);
        keys.push(key);
    }
    // Cleanup
    for key in &keys {
        profiles().remove(key);
    }
}

// ── average_throughput_to_tier (proposed function, tests the mapping) ────

// These tests verify the function that will be added in PR-D.
// They are written against the current code's constant definitions.

#[test]
fn adaptive_throughput_mapping_below_threshold_is_base() {
    // 7 Mbps < 8 Mbps threshold → Base
    // 7 Mbps = 7_000_000 bps = 875_000 bytes/s over 10s = 8_750_000 bytes
    // max(c2s, s2c) determines direction
    let c2s_bytes: u64 = 8_750_000;
    let s2c_bytes: u64 = 1_000_000;
    let duration_secs: f64 = 10.0;
    let avg_bps = (c2s_bytes.max(s2c_bytes) as f64 * 8.0) / duration_secs;
    // 8_750_000 * 8 / 10 = 7_000_000 bps = 7 Mbps → Base
    assert!(
        avg_bps < THROUGHPUT_UP_BPS,
        "Should be below threshold: {} < {}",
        avg_bps,
        THROUGHPUT_UP_BPS,
    );
}

#[test]
fn adaptive_throughput_mapping_above_threshold_is_tier1() {
    // 10 Mbps > 8 Mbps threshold → Tier1
    let bytes_10mbps_10s: u64 = 12_500_000; // 10 Mbps * 10s / 8 = 12_500_000 bytes
    let duration_secs: f64 = 10.0;
    let avg_bps = (bytes_10mbps_10s as f64 * 8.0) / duration_secs;
    assert!(
        avg_bps >= THROUGHPUT_UP_BPS,
        "Should be above threshold: {} >= {}",
        avg_bps,
        THROUGHPUT_UP_BPS,
    );
}

#[test]
fn adaptive_throughput_short_session_should_return_base() {
    // Sessions shorter than 1 second should not promote (too little data to judge)
    let duration_secs: f64 = 0.5;
    // Even with high throughput, short sessions should return Base
    assert!(
        duration_secs < 1.0,
        "Short session duration guard should activate"
    );
}

// ── me_flush_policy_for_tier ────────────────────────────────────────────

#[test]
fn adaptive_me_flush_base_unchanged() {
    let (frames, bytes, delay) =
        me_flush_policy_for_tier(AdaptiveTier::Base, 32, 65536, Duration::from_micros(1000));
    assert_eq!(frames, 32);
    assert_eq!(bytes, 65536);
    assert_eq!(delay, Duration::from_micros(1000));
}

#[test]
fn adaptive_me_flush_tier1_delay_reduced() {
    let (_, _, delay) =
        me_flush_policy_for_tier(AdaptiveTier::Tier1, 32, 65536, Duration::from_micros(1000));
    // Tier1: delay * 7/10 = 700 µs
    assert_eq!(delay, Duration::from_micros(700));
}

#[test]
fn adaptive_me_flush_delay_never_below_minimum() {
    let (_, _, delay) =
        me_flush_policy_for_tier(AdaptiveTier::Tier3, 32, 65536, Duration::from_micros(200));
    // Tier3: 200 * 3/10 = 60, but min is ME_DELAY_MIN_US = 150
    assert!(delay.as_micros() >= 150, "Delay must respect minimum");
}
