use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::config::ProxyConfig;
use crate::proxy::middle_relay::note_global_relay_pressure;
use crate::proxy::shared_state::{ConntrackCloseEvent, ConntrackCloseReason, ProxySharedState};
use crate::stats::Stats;

// Privileged netfilter rule and conntrack helper execution.
mod firewall;

pub(crate) use firewall::FirewallAuthority;
use firewall::{
    DeleteOutcome, delete_conntrack_entry, effective_conntrack_enabled, probe_runtime_support,
};

const CONNTRACK_EVENT_QUEUE_CAPACITY: usize = 32_768;
const PRESSURE_RELEASE_TICKS: u8 = 3;
const PRESSURE_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NetfilterBackend {
    Nftables,
    Iptables,
}

#[derive(Clone, Copy)]
struct ConntrackRuntimeSupport {
    netfilter_backend: Option<NetfilterBackend>,
    has_cap_net_admin: bool,
    has_conntrack_binary: bool,
}

#[derive(Clone, Copy)]
struct PressureSample {
    conn_pct: Option<u8>,
    fd_pct: Option<u8>,
    accept_timeout_delta: u64,
    me_queue_pressure_delta: u64,
}

struct PressureState {
    active: bool,
    low_streak: u8,
    prev_accept_timeout_total: u64,
    prev_me_queue_pressure_total: u64,
}

impl PressureState {
    fn new(stats: &Stats) -> Self {
        Self {
            active: false,
            low_streak: 0,
            prev_accept_timeout_total: stats.get_accept_permit_timeout_total(),
            prev_me_queue_pressure_total: stats.get_me_c2me_send_full_total(),
        }
    }
}

pub(crate) async fn run_conntrack_controller(
    config_rx: watch::Receiver<Arc<ProxyConfig>>,
    stats: Arc<Stats>,
    shared: Arc<ProxySharedState>,
    cancellation: CancellationToken,
) {
    if !cfg!(target_os = "linux") {
        let cfg = config_rx.borrow();
        let enabled = cfg.server.conntrack_control.inline_conntrack_control;
        stats.set_conntrack_control_enabled(enabled);
        stats.set_conntrack_control_available(false);
        stats.set_conntrack_pressure_active(false);
        stats.set_conntrack_event_queue_depth(0);
        stats.set_conntrack_rule_apply_ok(false);
        shared.disable_conntrack_close_sender();
        shared.set_conntrack_pressure_active(false);
        if enabled
            && cfg
                .server
                .conntrack_control
                .inline_conntrack_control_explicit
        {
            warn!(
                "conntrack control explicitly enabled but unsupported on this OS; disabling runtime worker"
            );
        }
        return;
    }

    let (tx, rx) = mpsc::channel(CONNTRACK_EVENT_QUEUE_CAPACITY);
    shared.set_conntrack_close_sender(tx);
    run_conntrack_controller_worker(config_rx, stats, shared, rx, cancellation).await;
}

async fn run_conntrack_controller_worker(
    mut config_rx: watch::Receiver<Arc<ProxyConfig>>,
    stats: Arc<Stats>,
    shared: Arc<ProxySharedState>,
    mut close_rx: mpsc::Receiver<ConntrackCloseEvent>,
    cancellation: CancellationToken,
) {
    let mut cfg = config_rx.borrow().clone();
    let mut pressure_state = PressureState::new(stats.as_ref());
    let mut delete_budget_tokens = cfg.server.conntrack_control.delete_budget_per_sec;
    let mut runtime_support = probe_runtime_support(cfg.server.conntrack_control.backend);
    let mut effective_enabled = effective_conntrack_enabled(&cfg, runtime_support);

    apply_runtime_state(
        stats.as_ref(),
        shared.as_ref(),
        &cfg,
        runtime_support,
        false,
    );

    loop {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            changed = config_rx.changed() => {
                if changed.is_err() {
                    break;
                }
                cfg = config_rx.borrow_and_update().clone();
                runtime_support = probe_runtime_support(cfg.server.conntrack_control.backend);
                effective_enabled = effective_conntrack_enabled(&cfg, runtime_support);
                delete_budget_tokens = cfg.server.conntrack_control.delete_budget_per_sec;
                apply_runtime_state(stats.as_ref(), shared.as_ref(), &cfg, runtime_support, pressure_state.active);
            }
            event = close_rx.recv() => {
                let Some(event) = event else {
                    break;
                };
                stats.set_conntrack_event_queue_depth(close_rx.len() as u64);
                if !effective_enabled {
                    continue;
                }
                if !pressure_state.active {
                    continue;
                }
                if !matches!(event.reason, ConntrackCloseReason::Timeout | ConntrackCloseReason::Pressure | ConntrackCloseReason::Reset) {
                    continue;
                }
                if delete_budget_tokens == 0 {
                    continue;
                }
                stats.increment_conntrack_delete_attempt_total();
                match delete_conntrack_entry(event).await {
                    DeleteOutcome::Deleted => {
                        delete_budget_tokens = delete_budget_tokens.saturating_sub(1);
                        stats.increment_conntrack_delete_success_total();
                    }
                    DeleteOutcome::NotFound => {
                        delete_budget_tokens = delete_budget_tokens.saturating_sub(1);
                        stats.increment_conntrack_delete_not_found_total();
                    }
                    DeleteOutcome::Error => {
                        delete_budget_tokens = delete_budget_tokens.saturating_sub(1);
                        stats.increment_conntrack_delete_error_total();
                    }
                }
            }
            _ = tokio::time::sleep(PRESSURE_SAMPLE_INTERVAL) => {
                delete_budget_tokens = cfg.server.conntrack_control.delete_budget_per_sec;
                stats.set_conntrack_event_queue_depth(close_rx.len() as u64);
                let sample = collect_pressure_sample(stats.as_ref(), &cfg, &mut pressure_state);
                update_pressure_state(
                    stats.as_ref(),
                    shared.as_ref(),
                    &cfg,
                    effective_enabled,
                    &sample,
                    &mut pressure_state,
                );
                if pressure_state.active {
                    note_global_relay_pressure(shared.as_ref());
                }
            }
        }
    }

    shared.disable_conntrack_close_sender();
    shared.set_conntrack_pressure_active(false);
    stats.set_conntrack_pressure_active(false);
}

fn apply_runtime_state(
    stats: &Stats,
    shared: &ProxySharedState,
    cfg: &ProxyConfig,
    runtime_support: ConntrackRuntimeSupport,
    pressure_active: bool,
) {
    let enabled = cfg.server.conntrack_control.inline_conntrack_control;
    let available = effective_conntrack_enabled(cfg, runtime_support);
    if enabled
        && !available
        && cfg
            .server
            .conntrack_control
            .inline_conntrack_control_explicit
    {
        warn!(
            has_cap_net_admin = runtime_support.has_cap_net_admin,
            backend_available = runtime_support.netfilter_backend.is_some(),
            conntrack_binary_available = runtime_support.has_conntrack_binary,
            configured_backend = ?cfg.server.conntrack_control.backend,
            "conntrack control explicitly enabled but unavailable; disabling runtime features"
        );
    }
    stats.set_conntrack_control_enabled(enabled);
    stats.set_conntrack_control_available(available);
    shared.set_conntrack_pressure_active(available && pressure_active);
    stats.set_conntrack_pressure_active(available && pressure_active);
}

fn collect_pressure_sample(
    stats: &Stats,
    cfg: &ProxyConfig,
    state: &mut PressureState,
) -> PressureSample {
    let current_connections = stats.get_current_connections_total();
    let conn_pct = if cfg.server.max_connections == 0 {
        None
    } else {
        Some(
            ((current_connections.saturating_mul(100)) / u64::from(cfg.server.max_connections))
                .min(100) as u8,
        )
    };

    let fd_pct = fd_usage_pct();

    let accept_total = stats.get_accept_permit_timeout_total();
    let accept_delta = accept_total.saturating_sub(state.prev_accept_timeout_total);
    state.prev_accept_timeout_total = accept_total;

    let me_total = stats.get_me_c2me_send_full_total();
    let me_delta = me_total.saturating_sub(state.prev_me_queue_pressure_total);
    state.prev_me_queue_pressure_total = me_total;

    PressureSample {
        conn_pct,
        fd_pct,
        accept_timeout_delta: accept_delta,
        me_queue_pressure_delta: me_delta,
    }
}

fn update_pressure_state(
    stats: &Stats,
    shared: &ProxySharedState,
    cfg: &ProxyConfig,
    effective_enabled: bool,
    sample: &PressureSample,
    state: &mut PressureState,
) {
    if !effective_enabled {
        if state.active {
            state.active = false;
            state.low_streak = 0;
            shared.set_conntrack_pressure_active(false);
            stats.set_conntrack_pressure_active(false);
            info!("Conntrack pressure mode deactivated (feature disabled)");
        }
        return;
    }

    let high = cfg.server.conntrack_control.pressure_high_watermark_pct;
    let low = cfg.server.conntrack_control.pressure_low_watermark_pct;

    let high_hit = sample.conn_pct.is_some_and(|v| v >= high)
        || sample.fd_pct.is_some_and(|v| v >= high)
        || sample.accept_timeout_delta > 0
        || sample.me_queue_pressure_delta > 0;

    let low_clear = sample.conn_pct.is_none_or(|v| v <= low)
        && sample.fd_pct.is_none_or(|v| v <= low)
        && sample.accept_timeout_delta == 0
        && sample.me_queue_pressure_delta == 0;

    if !state.active && high_hit {
        state.active = true;
        state.low_streak = 0;
        shared.set_conntrack_pressure_active(true);
        stats.set_conntrack_pressure_active(true);
        info!(
            conn_pct = ?sample.conn_pct,
            fd_pct = ?sample.fd_pct,
            accept_timeout_delta = sample.accept_timeout_delta,
            me_queue_pressure_delta = sample.me_queue_pressure_delta,
            "Conntrack pressure mode activated"
        );
        return;
    }

    if state.active && low_clear {
        state.low_streak = state.low_streak.saturating_add(1);
        if state.low_streak >= PRESSURE_RELEASE_TICKS {
            state.active = false;
            state.low_streak = 0;
            shared.set_conntrack_pressure_active(false);
            stats.set_conntrack_pressure_active(false);
            info!("Conntrack pressure mode deactivated");
        }
        return;
    }

    state.low_streak = 0;
}

fn fd_usage_pct() -> Option<u8> {
    let soft_limit = nofile_soft_limit()?;
    if soft_limit == 0 {
        return None;
    }
    let fd_count = std::fs::read_dir("/proc/self/fd").ok()?.count() as u64;
    Some(((fd_count.saturating_mul(100)) / soft_limit).min(100) as u8)
}

fn nofile_soft_limit() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) };
        if rc != 0 {
            return None;
        }
        return Some(lim.rlim_cur.into());
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ProxyConfig;

    #[test]
    fn pressure_activates_on_accept_timeout_spike() {
        let stats = Stats::new();
        let shared = ProxySharedState::new();
        let mut cfg = ProxyConfig::default();
        cfg.server.conntrack_control.inline_conntrack_control = true;
        let mut state = PressureState::new(&stats);
        let sample = PressureSample {
            conn_pct: Some(10),
            fd_pct: Some(10),
            accept_timeout_delta: 1,
            me_queue_pressure_delta: 0,
        };

        update_pressure_state(&stats, shared.as_ref(), &cfg, true, &sample, &mut state);

        assert!(state.active);
        assert!(shared.conntrack_pressure_active());
        assert!(stats.get_conntrack_pressure_active());
    }

    #[test]
    fn pressure_releases_after_hysteresis_window() {
        let stats = Stats::new();
        let shared = ProxySharedState::new();
        let mut cfg = ProxyConfig::default();
        cfg.server.conntrack_control.inline_conntrack_control = true;
        let mut state = PressureState::new(&stats);

        let high_sample = PressureSample {
            conn_pct: Some(95),
            fd_pct: Some(95),
            accept_timeout_delta: 0,
            me_queue_pressure_delta: 0,
        };
        update_pressure_state(
            &stats,
            shared.as_ref(),
            &cfg,
            true,
            &high_sample,
            &mut state,
        );
        assert!(state.active);

        let low_sample = PressureSample {
            conn_pct: Some(10),
            fd_pct: Some(10),
            accept_timeout_delta: 0,
            me_queue_pressure_delta: 0,
        };
        update_pressure_state(&stats, shared.as_ref(), &cfg, true, &low_sample, &mut state);
        assert!(state.active);
        update_pressure_state(&stats, shared.as_ref(), &cfg, true, &low_sample, &mut state);
        assert!(state.active);
        update_pressure_state(&stats, shared.as_ref(), &cfg, true, &low_sample, &mut state);

        assert!(!state.active);
        assert!(!shared.conntrack_pressure_active());
        assert!(!stats.get_conntrack_pressure_active());
    }

    #[test]
    fn pressure_does_not_activate_when_disabled() {
        let stats = Stats::new();
        let shared = ProxySharedState::new();
        let mut cfg = ProxyConfig::default();
        cfg.server.conntrack_control.inline_conntrack_control = false;
        let mut state = PressureState::new(&stats);
        let sample = PressureSample {
            conn_pct: Some(100),
            fd_pct: Some(100),
            accept_timeout_delta: 10,
            me_queue_pressure_delta: 10,
        };

        update_pressure_state(&stats, shared.as_ref(), &cfg, false, &sample, &mut state);

        assert!(!state.active);
        assert!(!shared.conntrack_pressure_active());
        assert!(!stats.get_conntrack_pressure_active());
    }
}
