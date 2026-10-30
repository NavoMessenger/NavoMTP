use super::*;
#[cfg(test)]
mod tests;

impl MePool {
    /// Captures the two independent authorities used by a health plan.
    pub(in crate::transport::middle_proxy) fn floor_authority(&self) -> (u64, u64) {
        let coordinator = self.reinit.coordinator.lock();
        (
            coordinator.endpoint_revision,
            coordinator.floor_policy_revision,
        )
    }

    /// Captures floor-affecting values under the coordinator without recursively acquiring it.
    pub(super) fn floor_policy_values(&self) -> [u64; 14] {
        let floor = &self.floor_runtime;
        [
            self.single_endpoint_runtime
                .me_single_endpoint_shadow_writers
                .load(Ordering::Relaxed) as u64,
            floor.me_floor_mode.load(Ordering::Relaxed) as u64,
            floor.me_adaptive_floor_idle_secs.load(Ordering::Relaxed),
            floor
                .me_adaptive_floor_min_writers_single_endpoint
                .load(Ordering::Relaxed) as u64,
            floor
                .me_adaptive_floor_min_writers_multi_endpoint
                .load(Ordering::Relaxed) as u64,
            floor
                .me_adaptive_floor_recover_grace_secs
                .load(Ordering::Relaxed),
            floor
                .me_adaptive_floor_writers_per_core_total
                .load(Ordering::Relaxed) as u64,
            floor
                .me_adaptive_floor_cpu_cores_override
                .load(Ordering::Relaxed) as u64,
            floor
                .me_adaptive_floor_max_extra_writers_single_per_core
                .load(Ordering::Relaxed) as u64,
            floor
                .me_adaptive_floor_max_extra_writers_multi_per_core
                .load(Ordering::Relaxed) as u64,
            floor
                .me_adaptive_floor_max_active_writers_per_core
                .load(Ordering::Relaxed) as u64,
            floor
                .me_adaptive_floor_max_warm_writers_per_core
                .load(Ordering::Relaxed) as u64,
            floor
                .me_adaptive_floor_max_active_writers_global
                .load(Ordering::Relaxed) as u64,
            floor
                .me_adaptive_floor_max_warm_writers_global
                .load(Ordering::Relaxed) as u64,
        ]
    }
}
