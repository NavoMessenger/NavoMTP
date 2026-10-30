//! ME pool runtime-state projection.

use std::collections::BTreeSet;

use serde::Serialize;

use super::{ApiShared, SOURCE_UNAVAILABLE_REASON, now_epoch_secs};

#[derive(Serialize)]
struct RuntimeMePoolStateGenerationData {
    active_generation: u64,
    warm_generation: u64,
    warm_generations: Vec<u64>,
    pending_hardswap_generation: u64,
    pending_hardswap_age_secs: Option<u64>,
    reinit_inflight: usize,
    reinit_max_concurrency_effective: usize,
    draining_generations: Vec<u64>,
}

#[derive(Serialize)]
struct RuntimeMePoolStateHardswapData {
    enabled: bool,
    pending: bool,
    pending_writers_current: usize,
    pending_writer_deficit: usize,
    pending_missing_dc_groups: usize,
    pending_map_current: Option<bool>,
    orphan_warm_writers_current: usize,
    replacement_preparing_current: usize,
    replacement_retiring_current: usize,
}

#[derive(Serialize)]
struct RuntimeMePoolStateWriterContourData {
    warm: usize,
    active: usize,
    draining: usize,
}

#[derive(Serialize)]
struct RuntimeMePoolStateWriterHealthData {
    healthy: usize,
    degraded: usize,
    draining: usize,
}

#[derive(Serialize)]
struct RuntimeMePoolStateWriterData {
    total: usize,
    alive_non_draining: usize,
    draining: usize,
    degraded: usize,
    contour: RuntimeMePoolStateWriterContourData,
    health: RuntimeMePoolStateWriterHealthData,
}

#[derive(Serialize)]
struct RuntimeMePoolStateRefillDcData {
    dc: i16,
    family: &'static str,
    inflight: usize,
}

#[derive(Serialize)]
struct RuntimeMePoolStateRefillData {
    inflight_endpoints_total: usize,
    inflight_dc_total: usize,
    running_dc_total: usize,
    pending_dc_total: usize,
    by_dc: Vec<RuntimeMePoolStateRefillDcData>,
}

#[derive(Serialize)]
struct RuntimeMePoolStatePayload {
    generations: RuntimeMePoolStateGenerationData,
    hardswap: RuntimeMePoolStateHardswapData,
    writers: RuntimeMePoolStateWriterData,
    refill: RuntimeMePoolStateRefillData,
}

#[derive(Serialize)]
struct RuntimeMePoolStateData {
    enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    generated_at_epoch_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<RuntimeMePoolStatePayload>,
}

/// Builds the bounded runtime ME pool response projection.
pub(in crate::api) async fn build_runtime_me_pool_state_data(shared: &ApiShared) -> impl Serialize {
    let now_epoch_secs = now_epoch_secs();
    let Some(pool) = shared.me_pool.read().await.clone() else {
        return RuntimeMePoolStateData {
            enabled: false,
            reason: Some(SOURCE_UNAVAILABLE_REASON),
            generated_at_epoch_secs: now_epoch_secs,
            data: None,
        };
    };

    let (status, runtime) = pool.api_coherent_snapshots().await;
    let refill = pool.api_refill_snapshot().await;

    let mut draining_generations = BTreeSet::<u64>::new();
    let mut contour_warm = 0usize;
    let mut contour_active = 0usize;
    let mut contour_draining = 0usize;
    let mut draining = 0usize;
    let mut degraded = 0usize;
    let mut healthy = 0usize;

    for writer in &status.writers {
        if writer.draining {
            draining_generations.insert(writer.generation);
            draining += 1;
        }
        if writer.degraded && !writer.draining {
            degraded += 1;
        }
        if !writer.degraded && !writer.draining {
            healthy += 1;
        }
        match writer.state {
            "warm" => contour_warm += 1,
            "active" => contour_active += 1,
            _ => contour_draining += 1,
        }
    }

    RuntimeMePoolStateData {
        enabled: true,
        reason: None,
        generated_at_epoch_secs: status.generated_at_epoch_secs,
        data: Some(RuntimeMePoolStatePayload {
            generations: RuntimeMePoolStateGenerationData {
                active_generation: runtime.active_generation,
                warm_generation: runtime.warm_generation,
                warm_generations: runtime.warm_generations,
                pending_hardswap_generation: runtime.pending_hardswap_generation,
                pending_hardswap_age_secs: runtime.pending_hardswap_age_secs,
                reinit_inflight: runtime.reinit_inflight,
                reinit_max_concurrency_effective: runtime.reinit_max_concurrency_effective,
                draining_generations: draining_generations.into_iter().collect(),
            },
            hardswap: RuntimeMePoolStateHardswapData {
                enabled: runtime.hardswap_enabled,
                pending: runtime.pending_hardswap_generation != 0,
                pending_writers_current: runtime.pending_writers_current,
                pending_writer_deficit: runtime.pending_writer_deficit,
                pending_missing_dc_groups: runtime.pending_missing_dc_groups,
                pending_map_current: runtime.pending_map_current,
                orphan_warm_writers_current: runtime.orphan_warm_writers_current,
                replacement_preparing_current: runtime.replacement_preparing_current,
                replacement_retiring_current: runtime.replacement_retiring_current,
            },
            writers: RuntimeMePoolStateWriterData {
                total: status.writers.len(),
                alive_non_draining: status.writers.len().saturating_sub(draining),
                draining,
                degraded,
                contour: RuntimeMePoolStateWriterContourData {
                    warm: contour_warm,
                    active: contour_active,
                    draining: contour_draining,
                },
                health: RuntimeMePoolStateWriterHealthData {
                    healthy,
                    degraded,
                    draining,
                },
            },
            refill: RuntimeMePoolStateRefillData {
                inflight_endpoints_total: refill.inflight_endpoints_total,
                inflight_dc_total: refill.inflight_dc_total,
                running_dc_total: refill.running_dc_total,
                pending_dc_total: refill.pending_dc_total,
                by_dc: refill
                    .by_dc
                    .into_iter()
                    .map(|entry| RuntimeMePoolStateRefillDcData {
                        dc: entry.dc,
                        family: entry.family,
                        inflight: entry.inflight,
                    })
                    .collect(),
            },
        }),
    }
}
