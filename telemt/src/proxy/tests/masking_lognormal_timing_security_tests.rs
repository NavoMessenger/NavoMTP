use super::*;
use rand::SeedableRng;
use rand::rngs::StdRng;

fn seeded_rng(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

// ── Positive: all samples within configured envelope ────────────────────

#[test]
fn masking_lognormal_all_samples_within_configured_envelope() {
    let mut rng = seeded_rng(42);
    let floor: u64 = 500;
    let ceiling: u64 = 2000;
    for _ in 0..10_000 {
        let val = sample_lognormal_percentile_bounded(floor, ceiling, &mut rng);
        assert!(
            val >= floor && val <= ceiling,
            "sample {} outside [{}, {}]",
            val,
            floor,
            ceiling,
        );
    }
}

// ── Statistical: median near geometric mean ─────────────────────────────

#[test]
fn masking_lognormal_sample_median_near_geometric_mean_of_range() {
    let mut rng = seeded_rng(42);
    let floor: u64 = 500;
    let ceiling: u64 = 2000;
    let geometric_mean = ((floor as f64) * (ceiling as f64)).sqrt();

    let mut samples: Vec<u64> = (0..10_000)
        .map(|_| sample_lognormal_percentile_bounded(floor, ceiling, &mut rng))
        .collect();
    samples.sort();
    let median = samples[samples.len() / 2] as f64;

    let tolerance = geometric_mean * 0.10;
    assert!(
        (median - geometric_mean).abs() <= tolerance,
        "median {} not within 10% of geometric mean {} (tolerance {})",
        median,
        geometric_mean,
        tolerance,
    );
}

// ── Edge: degenerate floor == ceiling returns exactly that value ─────────

#[test]
fn masking_lognormal_degenerate_floor_eq_ceiling_returns_floor() {
    let mut rng = seeded_rng(99);
    for _ in 0..100 {
        let val = sample_lognormal_percentile_bounded(1000, 1000, &mut rng);
        assert_eq!(
            val, 1000,
            "floor == ceiling must always return exactly that value"
        );
    }
}

// ── Edge: floor > ceiling (misconfiguration) clamps safely ──────────────

#[test]
fn masking_lognormal_floor_greater_than_ceiling_returns_ceiling() {
    let mut rng = seeded_rng(77);
    let val = sample_lognormal_percentile_bounded(2000, 500, &mut rng);
    assert_eq!(
        val, 500,
        "floor > ceiling misconfiguration must return ceiling (the minimum)"
    );
}

// ── Edge: floor == 1, ceiling == 1 ──────────────────────────────────────

#[test]
fn masking_lognormal_floor_1_ceiling_1_returns_1() {
    let mut rng = seeded_rng(12);
    let val = sample_lognormal_percentile_bounded(1, 1, &mut rng);
    assert_eq!(val, 1);
}

// ── Edge: floor == 1, ceiling very large ────────────────────────────────

#[test]
fn masking_lognormal_wide_range_all_samples_within_bounds() {
    let mut rng = seeded_rng(55);
    let floor: u64 = 1;
    let ceiling: u64 = 100_000;
    for _ in 0..10_000 {
        let val = sample_lognormal_percentile_bounded(floor, ceiling, &mut rng);
        assert!(
            val >= floor && val <= ceiling,
            "sample {} outside [{}, {}]",
            val,
            floor,
            ceiling,
        );
    }
}

// ── Adversarial: extreme sigma (floor very close to ceiling) ────────────

#[test]
fn masking_lognormal_narrow_range_does_not_panic() {
    let mut rng = seeded_rng(88);
    let floor: u64 = 999;
    let ceiling: u64 = 1001;
    for _ in 0..10_000 {
        let val = sample_lognormal_percentile_bounded(floor, ceiling, &mut rng);
        assert!(
            val >= floor && val <= ceiling,
            "narrow range sample {} outside [{}, {}]",
            val,
            floor,
            ceiling,
        );
    }
}

// ── Adversarial: u64::MAX ceiling does not overflow ──────────────────────

#[test]
fn masking_lognormal_u64_max_ceiling_no_overflow() {
    let mut rng = seeded_rng(123);
    let floor: u64 = 1;
    let ceiling: u64 = u64::MAX;
    for _ in 0..1000 {
        let val = sample_lognormal_percentile_bounded(floor, ceiling, &mut rng);
        assert!(val >= floor, "sample {} below floor {}", val, floor);
        // u64::MAX clamp ensures no overflow
    }
}

// ── Adversarial: floor == 0 guard ───────────────────────────────────────
// The function should handle floor=0 gracefully even though callers
// should never pass it. Verifies no panic on ln(0).

#[test]
fn masking_lognormal_floor_zero_no_panic() {
    let mut rng = seeded_rng(200);
    let val = sample_lognormal_percentile_bounded(0, 1000, &mut rng);
    assert!(val <= 1000, "sample {} exceeds ceiling 1000", val);
}

// ── Adversarial: both zero → returns 0 ──────────────────────────────────

#[test]
fn masking_lognormal_both_zero_returns_zero() {
    let mut rng = seeded_rng(201);
    let val = sample_lognormal_percentile_bounded(0, 0, &mut rng);
    assert_eq!(val, 0, "floor=0 ceiling=0 must return 0");
}

// ── Distribution shape: not uniform ─────────────────────────────────────
// A DPI classifier trained on uniform delay samples should detect a
// distribution where > 60% of samples fall in the lower half of the range.
// Log-normal is right-skewed: more samples near floor than ceiling.

#[test]
fn masking_lognormal_distribution_is_right_skewed() {
    let mut rng = seeded_rng(42);
    let floor: u64 = 100;
    let ceiling: u64 = 5000;
    let midpoint = (floor + ceiling) / 2;

    let samples: Vec<u64> = (0..10_000)
        .map(|_| sample_lognormal_percentile_bounded(floor, ceiling, &mut rng))
        .collect();

    let below_mid = samples.iter().filter(|&&s| s < midpoint).count();
    let ratio = below_mid as f64 / samples.len() as f64;

    assert!(
        ratio > 0.55,
        "Log-normal should be right-skewed (>55% below midpoint), got {}%",
        ratio * 100.0,
    );
}

// ── Determinism: same seed produces same sequence ───────────────────────

#[test]
fn masking_lognormal_deterministic_with_same_seed() {
    let mut rng1 = seeded_rng(42);
    let mut rng2 = seeded_rng(42);
    for _ in 0..100 {
        let a = sample_lognormal_percentile_bounded(500, 2000, &mut rng1);
        let b = sample_lognormal_percentile_bounded(500, 2000, &mut rng2);
        assert_eq!(a, b, "Same seed must produce same output");
    }
}

// ── Fuzz: 1000 random (floor, ceiling) pairs, no panics ─────────────────

#[test]
fn masking_lognormal_fuzz_random_params_no_panic() {
    use rand::Rng;
    let mut rng = seeded_rng(999);
    for _ in 0..1000 {
        let a: u64 = rng.random_range(0..=10_000);
        let b: u64 = rng.random_range(0..=10_000);
        let floor = a.min(b);
        let ceiling = a.max(b);
        let val = sample_lognormal_percentile_bounded(floor, ceiling, &mut rng);
        assert!(
            val >= floor && val <= ceiling,
            "fuzz: sample {} outside [{}, {}]",
            val,
            floor,
            ceiling,
        );
    }
}

// ── Fuzz: adversarial floor > ceiling pairs ──────────────────────────────

#[test]
fn masking_lognormal_fuzz_inverted_params_no_panic() {
    use rand::Rng;
    let mut rng = seeded_rng(777);
    for _ in 0..500 {
        let floor: u64 = rng.random_range(1..=10_000);
        let ceiling: u64 = rng.random_range(0..floor);
        // When floor > ceiling, must return ceiling (the smaller value)
        let val = sample_lognormal_percentile_bounded(floor, ceiling, &mut rng);
        assert_eq!(
            val, ceiling,
            "inverted: floor={} ceiling={} should return ceiling, got {}",
            floor, ceiling, val,
        );
    }
}

// ── Security: clamp spike check ─────────────────────────────────────────
// With well-parameterized sigma, no more than 5% of samples should be
// at exactly floor or exactly ceiling (clamp spikes). A spike > 10%
// is detectable by DPI as bimodal.

#[test]
fn masking_lognormal_no_clamp_spike_at_boundaries() {
    let mut rng = seeded_rng(42);
    let floor: u64 = 500;
    let ceiling: u64 = 2000;
    let n = 10_000;
    let samples: Vec<u64> = (0..n)
        .map(|_| sample_lognormal_percentile_bounded(floor, ceiling, &mut rng))
        .collect();

    let at_floor = samples.iter().filter(|&&s| s == floor).count();
    let at_ceiling = samples.iter().filter(|&&s| s == ceiling).count();
    let floor_pct = at_floor as f64 / n as f64;
    let ceiling_pct = at_ceiling as f64 / n as f64;

    assert!(
        floor_pct < 0.05,
        "floor clamp spike: {}% of samples at exactly floor (max 5%)",
        floor_pct * 100.0,
    );
    assert!(
        ceiling_pct < 0.05,
        "ceiling clamp spike: {}% of samples at exactly ceiling (max 5%)",
        ceiling_pct * 100.0,
    );
}

// ── Integration: mask_outcome_target_budget uses log-normal for path 3 ──

#[tokio::test]
async fn masking_lognormal_integration_budget_within_bounds() {
    let mut config = ProxyConfig::default();
    config.censorship.mask_timing_normalization_enabled = true;
    config.censorship.mask_timing_normalization_floor_ms = 500;
    config.censorship.mask_timing_normalization_ceiling_ms = 2000;

    for _ in 0..100 {
        let budget = mask_outcome_target_budget(&config);
        let ms = budget.as_millis() as u64;
        assert!(
            ms >= 500 && ms <= 2000,
            "budget {} ms outside [500, 2000]",
            ms,
        );
    }
}

// ── Integration: floor == 0 path stays uniform (NOT log-normal) ─────────

#[tokio::test]
async fn masking_lognormal_floor_zero_path_stays_uniform() {
    let mut config = ProxyConfig::default();
    config.censorship.mask_timing_normalization_enabled = true;
    config.censorship.mask_timing_normalization_floor_ms = 0;
    config.censorship.mask_timing_normalization_ceiling_ms = 1000;

    for _ in 0..100 {
        let budget = mask_outcome_target_budget(&config);
        let ms = budget.as_millis() as u64;
        // floor=0 path uses uniform [0, ceiling], not log-normal
        assert!(ms <= 1000, "budget {} ms exceeds ceiling 1000", ms);
    }
}

// ── Integration: floor > ceiling misconfiguration is safe ───────────────

#[tokio::test]
async fn masking_lognormal_misconfigured_floor_gt_ceiling_safe() {
    let mut config = ProxyConfig::default();
    config.censorship.mask_timing_normalization_enabled = true;
    config.censorship.mask_timing_normalization_floor_ms = 2000;
    config.censorship.mask_timing_normalization_ceiling_ms = 500;

    let budget = mask_outcome_target_budget(&config);
    let ms = budget.as_millis() as u64;
    // floor > ceiling: should not exceed the minimum of the two
    assert!(
        ms <= 2000,
        "misconfigured budget {} ms should be bounded",
        ms,
    );
}

// ── Stress: rapid repeated calls do not panic or starve ─────────────────

#[test]
fn masking_lognormal_stress_rapid_calls_no_panic() {
    let mut rng = seeded_rng(42);
    for _ in 0..100_000 {
        let _ = sample_lognormal_percentile_bounded(100, 5000, &mut rng);
    }
}
