use std::sync::Arc;

use tokio::sync::Semaphore;

use super::*;
use crate::proxy::shared_state::ProxySharedState;
use crate::stats::Stats;
use crate::stream::BufferPool;

/// Resolves the startup hard ceiling from config, cgroup, and host memory.
pub(crate) async fn resolve_direct_buffer_hard_limit(configured: usize) -> usize {
    if configured != 0 {
        return align_down(configured);
    }
    let sample = read_system_memory_sample().await;
    if sample.total_bytes == 0 {
        return AUTO_HARD_FALLBACK_BYTES;
    }
    let derived = (sample.total_bytes / 4)
        .clamp(AUTO_HARD_MIN_BYTES as u64, AUTO_HARD_MAX_BYTES as u64)
        .min(sample.total_bytes);
    align_down(derived as usize).max(DIRECT_BUFFER_UNIT_BYTES)
}

/// Runs the control-plane loop for Direct budget and shared pool pressure.
pub(crate) async fn run_direct_buffer_budget_controller(
    source_generation: u64,
    budget: Arc<DirectBufferBudget>,
    buffer_pool: Arc<BufferPool>,
    stats: Arc<Stats>,
    shared: Arc<ProxySharedState>,
    connection_slots: Arc<Semaphore>,
    max_connections: u32,
) {
    let mut interval = tokio::time::interval(CONTROL_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut healthy_streak = 0u8;
    let mut previous_denied = 0u64;
    let mut previous_fallback = 0u64;
    let mut previous_rejected = 0u64;
    let pool_trim_low = buffer_pool
        .max_buffers()
        .min(BUFFER_POOL_TRIM_LOW_WATERMARK);
    let pool_trim_high = buffer_pool
        .max_buffers()
        .min(BUFFER_POOL_TRIM_HIGH_WATERMARK);
    let mut pool_trim_armed = true;

    loop {
        interval.tick().await;
        if budget.active_controller_generation.load(Ordering::Acquire) != source_generation {
            continue;
        }
        let sample = read_system_memory_sample().await;
        let Some(_controller_update) = budget.begin_controller_update(source_generation) else {
            continue;
        };
        budget.update_system_sample(sample);

        let snapshot = budget.snapshot();
        let denied_delta = snapshot
            .promotion_denied_total
            .saturating_sub(previous_denied);
        previous_denied = snapshot.promotion_denied_total;
        let fallback_delta = snapshot
            .minimum_fallback_total
            .saturating_sub(previous_fallback);
        previous_fallback = snapshot.minimum_fallback_total;
        let rejected_delta = snapshot
            .admission_rejected_total
            .saturating_sub(previous_rejected);
        previous_rejected = snapshot.admission_rejected_total;

        let connection_pct = connection_fill_pct(connection_slots.as_ref(), max_connections);
        let memory_available_pct = percentage(sample.available_bytes, sample.total_bytes);
        let target_utilization_pct = percentage(snapshot.reserved_bytes, snapshot.target_bytes);
        let pressure = shared.conntrack_pressure_active()
            || connection_pct.is_some_and(|value| value >= 85)
            || memory_available_pct.is_some_and(|value| value <= 15)
            || target_utilization_pct.is_some_and(|value| value >= 90)
            || denied_delta > 0
            || fallback_delta > 0
            || rejected_delta > 0;

        if !pressure {
            pool_trim_armed = true;
        } else if pool_trim_armed && buffer_pool.pooled() > pool_trim_high {
            buffer_pool.trim_to(pool_trim_low);
            pool_trim_armed = false;
        }

        let pool_snapshot = buffer_pool.stats();
        stats.set_buffer_pool_gauges(
            pool_snapshot.pooled,
            pool_snapshot.allocated,
            pool_snapshot.allocated.saturating_sub(pool_snapshot.pooled),
        );
        stats.set_buffer_pool_replaced_nonstandard_total(pool_snapshot.replaced_nonstandard);

        let headroom_target = if sample.total_bytes == 0 {
            snapshot.hard_limit_bytes
        } else {
            snapshot
                .reserved_bytes
                .saturating_add(sample.available_bytes / 4)
                .min(snapshot.hard_limit_bytes)
        };

        if pressure {
            healthy_streak = 0;
            let reduced = snapshot.target_bytes.saturating_mul(3) / 4;
            budget.set_target_bytes(reduced.min(headroom_target));
            continue;
        }

        let healthy = memory_available_pct.is_none_or(|value| value >= 30)
            && connection_pct.is_none_or(|value| value <= 70);
        if !healthy {
            healthy_streak = 0;
            if headroom_target < snapshot.target_bytes {
                budget.set_target_bytes(headroom_target);
            }
            continue;
        }

        healthy_streak = healthy_streak.saturating_add(1);
        if healthy_streak >= HEALTHY_RECOVERY_SAMPLES {
            healthy_streak = 0;
            let increment = (snapshot.target_bytes / 16).max(4 * 1024 * 1024);
            budget.set_target_bytes(
                snapshot
                    .target_bytes
                    .saturating_add(increment)
                    .min(headroom_target),
            );
        }
    }
}

pub(super) fn connection_fill_pct(
    connection_slots: &Semaphore,
    max_connections: u32,
) -> Option<u8> {
    if max_connections == 0 {
        return None;
    }
    let max_connections = max_connections as usize;
    let active =
        max_connections.saturating_sub(connection_slots.available_permits().min(max_connections));
    Some((active.saturating_mul(100) / max_connections).min(100) as u8)
}

fn percentage(value: u64, total: u64) -> Option<u8> {
    if total == 0 {
        return None;
    }
    Some(((value.saturating_mul(100)) / total).min(100) as u8)
}

async fn read_system_memory_sample() -> SystemMemorySample {
    #[cfg(target_os = "linux")]
    {
        let meminfo = tokio::fs::read_to_string("/proc/meminfo")
            .await
            .unwrap_or_default();
        let status = tokio::fs::read_to_string("/proc/self/status")
            .await
            .unwrap_or_default();
        let host_total = parse_kib_field(&meminfo, "MemTotal:");
        let host_available = parse_kib_field(&meminfo, "MemAvailable:");
        let process_rss = parse_kib_field(&status, "VmRSS:");

        let cgroup_v2_max = read_cgroup_limit("/sys/fs/cgroup/memory.max").await;
        let cgroup_v2_current = read_u64_file("/sys/fs/cgroup/memory.current").await;
        let cgroup_v1_max = read_cgroup_limit("/sys/fs/cgroup/memory/memory.limit_in_bytes").await;
        let cgroup_v1_current = read_u64_file("/sys/fs/cgroup/memory/memory.usage_in_bytes").await;
        let cgroup_max = cgroup_v2_max.or(cgroup_v1_max);
        let cgroup_current = cgroup_v2_current.or(cgroup_v1_current);

        let total = match (host_total, cgroup_max) {
            (0, Some(limit)) => limit,
            (host, Some(limit)) => host.min(limit),
            (host, None) => host,
        };
        let cgroup_available = cgroup_max
            .zip(cgroup_current)
            .map(|(limit, current)| limit.saturating_sub(current));
        let available = match (host_available, cgroup_available) {
            (0, Some(value)) => value,
            (host, Some(value)) => host.min(value),
            (host, None) => host,
        };
        return SystemMemorySample {
            total_bytes: total,
            available_bytes: available,
            process_rss_bytes: process_rss,
        };
    }
    #[cfg(not(target_os = "linux"))]
    {
        SystemMemorySample::default()
    }
}

#[cfg(target_os = "linux")]
async fn read_cgroup_limit(path: &str) -> Option<u64> {
    let raw = tokio::fs::read_to_string(path).await.ok()?;
    let raw = raw.trim();
    if raw == "max" {
        return None;
    }
    let value = raw.parse::<u64>().ok()?;
    (value < (1u64 << 60)).then_some(value)
}

#[cfg(target_os = "linux")]
async fn read_u64_file(path: &str) -> Option<u64> {
    tokio::fs::read_to_string(path)
        .await
        .ok()?
        .trim()
        .parse()
        .ok()
}

#[cfg(target_os = "linux")]
fn parse_kib_field(raw: &str, key: &str) -> u64 {
    raw.lines()
        .find_map(|line| {
            let value = line.strip_prefix(key)?.split_whitespace().next()?;
            value.parse::<u64>().ok()
        })
        .unwrap_or(0)
        .saturating_mul(1024)
}
