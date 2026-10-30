use super::*;
use crate::config::GeneralConfig;
use crate::transport::middle_proxy::pool_writer_security_tests::make_pool;

fn reload(pool: &MePool, cfg: &GeneralConfig) {
    pool.update_runtime_reinit_policy(
        cfg.hardswap,
        cfg.me_pool_drain_ttl_secs,
        cfg.me_instadrain,
        cfg.me_pool_drain_threshold,
        cfg.me_pool_drain_soft_evict_enabled,
        cfg.me_pool_drain_soft_evict_grace_secs,
        cfg.me_pool_drain_soft_evict_per_writer,
        cfg.me_pool_drain_soft_evict_budget_per_core,
        cfg.me_pool_drain_soft_evict_cooldown_ms,
        cfg.effective_me_pool_force_close_secs(),
        cfg.me_pool_min_fresh_ratio,
        cfg.me_hardswap_warmup_delay_min_ms,
        cfg.me_hardswap_warmup_delay_max_ms,
        cfg.me_hardswap_warmup_extra_passes,
        cfg.me_hardswap_warmup_pass_backoff_base_ms,
        cfg.me_bind_stale_mode,
        cfg.me_bind_stale_ttl_secs,
        cfg.me_secret_atomic_snapshot,
        cfg.me_deterministic_writer_sort,
        cfg.me_writer_pick_mode,
        cfg.me_writer_pick_sample_size,
        cfg.me_single_endpoint_shadow_writers,
        cfg.me_single_endpoint_outage_mode_enabled,
        cfg.me_single_endpoint_outage_disable_quarantine,
        cfg.me_single_endpoint_outage_backoff_min_ms,
        cfg.me_single_endpoint_outage_backoff_max_ms,
        cfg.me_single_endpoint_shadow_rotate_every_secs,
        cfg.me_floor_mode,
        cfg.me_adaptive_floor_idle_secs,
        cfg.me_adaptive_floor_min_writers_single_endpoint,
        cfg.me_adaptive_floor_min_writers_multi_endpoint,
        cfg.me_adaptive_floor_recover_grace_secs,
        cfg.me_adaptive_floor_writers_per_core_total,
        cfg.me_adaptive_floor_cpu_cores_override,
        cfg.me_adaptive_floor_max_extra_writers_single_per_core,
        cfg.me_adaptive_floor_max_extra_writers_multi_per_core,
        cfg.me_adaptive_floor_max_active_writers_per_core,
        cfg.me_adaptive_floor_max_warm_writers_per_core,
        cfg.me_adaptive_floor_max_active_writers_global,
        cfg.me_adaptive_floor_max_warm_writers_global,
        cfg.me_health_interval_ms_unhealthy,
        cfg.me_health_interval_ms_healthy,
        cfg.me_warn_rate_limit_ms,
    );
}

#[tokio::test]
async fn policy_reload_invalidates_old_caps_and_rejects_stale_plan_publication() {
    let pool = make_pool().await;
    let mut cfg = GeneralConfig::default();
    reload(&pool, &cfg);
    let authority = pool.floor_authority();
    pool.set_adaptive_floor_runtime_caps(authority, 10, 12, 10, 12, 6, 6, 0);
    assert_eq!(
        pool.floor_runtime
            .me_adaptive_floor_active_cap_effective
            .load(Ordering::Acquire),
        12
    );
    cfg.me_single_endpoint_shadow_writers += 1;
    reload(&pool, &cfg);
    assert_ne!(pool.floor_authority(), authority);
    assert_eq!(
        pool.floor_runtime
            .me_adaptive_floor_active_cap_effective
            .load(Ordering::Acquire),
        0
    );
    pool.set_adaptive_floor_runtime_caps(authority, 10, 128, 10, 128, 100, 6, 0);
    assert_eq!(
        pool.floor_runtime
            .me_adaptive_floor_active_cap_effective
            .load(Ordering::Acquire),
        0
    );
    let new_authority = pool.floor_authority();
    reload(&pool, &cfg);
    assert_eq!(
        pool.floor_authority(),
        new_authority,
        "unchanged reload must not supersede work"
    );
    pool.set_adaptive_floor_runtime_caps(new_authority, 10, 11, 10, 11, 6, 6, 0);
    assert_eq!(
        pool.floor_runtime
            .me_adaptive_floor_active_cap_effective
            .load(Ordering::Acquire),
        11
    );
}
