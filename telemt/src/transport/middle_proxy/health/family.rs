use super::scheduler::HealthObservation;
use super::*;

/// Takes a control-plane observation without awaiting any network operation.
pub(super) async fn check_family(family: IpFamily, pool: &Arc<MePool>) -> HealthObservation {
    let authority = pool.floor_authority();
    let generation = pool.current_generation();
    let snapshot = pool.endpoint_snapshot.load_full();
    let enabled = if family == IpFamily::V4 {
        pool.decision.ipv4_me
    } else {
        pool.decision.ipv6_me
    };
    let source = if family == IpFamily::V4 {
        &snapshot.map_v4
    } else {
        &snapshot.map_v6
    };
    let mut endpoints = HashMap::new();
    if enabled {
        for (dc, addresses) in source {
            let mut addresses: Vec<_> = addresses
                .iter()
                .map(|(ip, port)| SocketAddr::new(*ip, *port))
                .collect();
            addresses.sort_unstable();
            addresses.dedup();
            endpoints.insert(*dc, addresses);
        }
    }
    let mut counts = HashMap::new();
    let mut ids = HashMap::<_, Vec<_>>::new();
    for writer in pool.writers.read().await.iter() {
        if !writer.draining.load(std::sync::atomic::Ordering::Acquire)
            && writer.generation == generation
            && WriterContour::from_u8(writer.contour.load(std::sync::atomic::Ordering::Acquire))
                == WriterContour::Active
            && endpoints
                .get(&writer.writer_dc)
                .is_some_and(|addresses| addresses.contains(&writer.addr))
        {
            *counts
                .entry((writer.writer_dc, writer.addr))
                .or_insert(0usize) += 1;
            ids.entry((writer.writer_dc, writer.addr))
                .or_default()
                .push(writer.id);
        }
    }
    let idle = pool.registry.writer_idle_since_snapshot().await;
    let bound = pool
        .registry
        .writer_activity_snapshot()
        .await
        .bound_clients_by_writer;
    let floor = build_family_floor_plan(pool, family, &endpoints, &counts, &ids, &bound).await;
    HealthObservation {
        authority,
        generation,
        floor,
        ids,
        idle,
        bound,
    }
}

pub(super) fn health_reconnect_budget(pool: &Arc<MePool>, dc_groups: usize) -> usize {
    let cpu_cores = pool.adaptive_floor_effective_cpu_cores().max(1);
    let by_cpu = cpu_cores.saturating_mul(HEALTH_RECONNECT_BUDGET_PER_CORE);
    let by_dc = dc_groups.saturating_mul(HEALTH_RECONNECT_BUDGET_PER_DC);
    by_cpu
        .saturating_add(by_dc)
        .clamp(HEALTH_RECONNECT_BUDGET_MIN, HEALTH_RECONNECT_BUDGET_MAX)
}

pub(super) fn update_family_runtime_state(pool: &Arc<MePool>, family: IpFamily, degraded: bool) {
    let now_epoch_secs = MePool::now_epoch_secs();
    let previous_state = pool.family_runtime_state(family);
    let mut state_since_epoch_secs = pool.family_runtime_state_since_epoch_secs(family);
    let previous_suppressed_until_epoch_secs = pool.family_suppressed_until_epoch_secs(family);
    let previous_fail_streak = pool.family_fail_streak(family);
    let previous_recover_success_streak = pool.family_recover_success_streak(family);

    let (next_state, suppressed_until_epoch_secs, fail_streak, recover_success_streak) =
        if previous_suppressed_until_epoch_secs > now_epoch_secs {
            let fail_streak = if degraded {
                previous_fail_streak.saturating_add(1)
            } else {
                previous_fail_streak
            };
            (
                MeFamilyRuntimeState::Suppressed,
                previous_suppressed_until_epoch_secs,
                fail_streak,
                0,
            )
        } else if degraded {
            let fail_streak = previous_fail_streak.saturating_add(1);
            if fail_streak >= FAMILY_SUPPRESS_FAIL_STREAK_THRESHOLD {
                (
                    MeFamilyRuntimeState::Suppressed,
                    now_epoch_secs.saturating_add(FAMILY_SUPPRESS_DURATION_SECS),
                    fail_streak,
                    0,
                )
            } else {
                (MeFamilyRuntimeState::Degraded, 0, fail_streak, 0)
            }
        } else if matches!(previous_state, MeFamilyRuntimeState::Healthy) {
            (MeFamilyRuntimeState::Healthy, 0, 0, 0)
        } else {
            let recover_success_streak = previous_recover_success_streak.saturating_add(1);
            if recover_success_streak >= FAMILY_RECOVER_SUCCESS_STREAK_TARGET {
                (MeFamilyRuntimeState::Healthy, 0, 0, 0)
            } else {
                (
                    MeFamilyRuntimeState::Recovering,
                    0,
                    0,
                    recover_success_streak,
                )
            }
        };

    if next_state != previous_state || state_since_epoch_secs == 0 {
        state_since_epoch_secs = now_epoch_secs;
    }
    pool.set_family_runtime_state(
        family,
        next_state,
        state_since_epoch_secs,
        suppressed_until_epoch_secs,
        fail_streak,
        recover_success_streak,
    );
}
