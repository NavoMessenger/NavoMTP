use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{mpsc, watch};
use tokio::task::JoinSet;
use tracing::{debug, info, warn};

use crate::config::ProxyConfig;
use crate::crypto::SecureRandom;

use super::MePool;
// Durable scheduler intent is independent of pending generation creation.
mod objective;
#[cfg(test)]
mod retry_tests;

/// External causes that request generation reconciliation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeReinitTrigger {
    /// The configured rotation interval elapsed.
    Periodic,
    /// Endpoint authority changed.
    MapChanged,
}

impl MeReinitTrigger {
    fn as_str(self) -> &'static str {
        match self {
            MeReinitTrigger::Periodic => "periodic",
            MeReinitTrigger::MapChanged => "map-change",
        }
    }
}

/// Coalesces an external request; endpoint epochs independently preserve map-change intent.
pub fn enqueue_reinit_trigger(tx: &mpsc::Sender<MeReinitTrigger>, trigger: MeReinitTrigger) {
    match tx.try_send(trigger) {
        Ok(()) => {}
        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
            debug!(
                trigger = trigger.as_str(),
                "ME reinit trigger dropped (queue full)"
            );
        }
        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
            warn!(
                trigger = trigger.as_str(),
                "ME reinit trigger dropped (scheduler closed)"
            );
        }
    }
}

const REINIT_TRIGGER_PERIODIC: u8 = 1;
const REINIT_TRIGGER_MAP_CHANGED: u8 = 2;

struct ReinitInflightGuard {
    pool: Arc<MePool>,
}

impl Drop for ReinitInflightGuard {
    fn drop(&mut self) {
        self.pool
            .reinit
            .scheduler_inflight
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
    }
}

fn effective_reinit_concurrency(config: &ProxyConfig) -> usize {
    if config.general.me_reinit_singleflight {
        1
    } else {
        config.general.me_reinit_max_concurrency.clamp(1, 8)
    }
}

fn trigger_bit(trigger: MeReinitTrigger) -> u8 {
    match trigger {
        MeReinitTrigger::Periodic => REINIT_TRIGGER_PERIODIC,
        MeReinitTrigger::MapChanged => REINIT_TRIGGER_MAP_CHANGED,
    }
}

fn trigger_reason(pending: u8) -> &'static str {
    match pending {
        REINIT_TRIGGER_PERIODIC => "periodic",
        REINIT_TRIGGER_MAP_CHANGED => "map-change",
        _ => "map-change+periodic",
    }
}

/// Retries durable reinitialization objectives until their exact endpoint revision converges.
pub async fn me_reinit_scheduler(
    pool: Arc<MePool>,
    rng: Arc<SecureRandom>,
    config_rx: watch::Receiver<Arc<ProxyConfig>>,
    mut trigger_rx: mpsc::Receiver<MeReinitTrigger>,
    me_ready_tx: watch::Sender<u64>,
) {
    info!("ME reinit scheduler started");
    let mut tasks = JoinSet::<Option<bool>>::new();
    let mut owners = std::collections::HashMap::new();
    let mut objective: Option<objective::RetryObjective> = None;
    let mut next_id = 1u64;
    let mut epochs = pool.writer_epoch.subscribe();
    let mut epoch_open = true;
    let mut observed_revision = pool.endpoint_snapshot.load().revision;
    let mut completed_revision = None;
    let mut trigger_channel_open = true;

    loop {
        let cfg = config_rx.borrow().clone();
        let max_concurrency = effective_reinit_concurrency(&cfg);
        pool.reinit
            .max_concurrency_effective
            .store(max_concurrency, std::sync::atomic::Ordering::Release);
        let snapshot = pool.endpoint_snapshot.load_full();
        if snapshot.revision != observed_revision {
            observed_revision = snapshot.revision;
            objective = Some(objective::RetryObjective::new(
                next_id,
                observed_revision,
                REINIT_TRIGGER_MAP_CHANGED,
                Duration::from_millis(cfg.general.me_reinit_coalesce_window_ms),
            ));
            next_id = next_id.wrapping_add(1);
        }
        let owned = objective
            .as_ref()
            .is_some_and(|current| owners.values().any(|identity| current.matches(*identity)));
        if let Some(current) = objective.as_mut()
            && !owned
            && current.attempt > 0
        {
            let status = pool.reinit.status.load_full();
            let authority = pool.floor_authority();
            let readiness = pool.api_hardswap_snapshot().await;
            // An API projection is usable only while its exact publication and policy survive
            // the await. A changed snapshot is unknown, not a not-ready transition.
            if Arc::ptr_eq(&status, &pool.reinit.status.load_full())
                && authority == pool.floor_authority()
            {
                if status.pending_hardswap_endpoint_revision == current.revision
                    && readiness.pending_map_current == Some(true)
                    && readiness.pending_writer_deficit == 0
                {
                    current.ready((
                        status.pending_hardswap_generation,
                        status.pending_hardswap_map_hash,
                        status.pending_hardswap_endpoint_revision,
                    ));
                } else {
                    current.not_ready();
                }
            }
        }
        let can_launch = !owned
            && tasks.len() < max_concurrency
            && objective
                .as_ref()
                .is_some_and(|current| current.attempt == 0 || tasks.is_empty());
        if can_launch
            && objective.as_ref().is_some_and(|current| {
                current
                    .deadline
                    .is_some_and(|deadline| deadline <= tokio::time::Instant::now())
            })
        {
            if pool.endpoint_snapshot.load().revision != snapshot.revision {
                continue;
            }
            let Some(current) = objective.as_mut() else {
                continue;
            };
            let identity = (current.id, current.revision);
            current.deadline = None;
            debug!(
                reason = trigger_reason(current.triggers),
                attempt = current.attempt,
                endpoint_revision = current.revision,
                "ME reinit scheduled"
            );
            let pool_clone = pool.clone();
            let rng_clone = rng.clone();
            pool.reinit
                .scheduler_inflight
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            let inflight = ReinitInflightGuard {
                pool: pool_clone.clone(),
            };
            let future = async move {
                let _inflight = inflight;
                pool_clone
                    .reinit_endpoint_snapshot(rng_clone.as_ref(), snapshot)
                    .await
            };
            // Pool shutdown joins destruction of attempts as well as their writer transports.
            let Ok(tracked) = pool.lifecycle.track_producer(future) else {
                return;
            };
            let task = tasks.spawn(tracked);
            owners.insert(task.id(), identity);
            continue;
        }
        if !trigger_channel_open && objective.is_none() && tasks.is_empty() {
            return;
        }
        let deadline = objective.as_ref().and_then(|current| current.deadline);
        tokio::select! {
            trigger = trigger_rx.recv(), if trigger_channel_open => {
                match trigger {
                    Some(trigger) => {
                        let revision = pool.endpoint_snapshot.load().revision;
                        if trigger == MeReinitTrigger::MapChanged && completed_revision == Some(revision) {
                            continue;
                        }
                        if let Some(current) = objective.as_mut()
                            && current.revision == revision
                            && (trigger == MeReinitTrigger::MapChanged
                                || !owners.values().any(|identity| current.matches(*identity))) {
                            // Endpoint epochs and updater notifications describe the same objective.
                            current.triggers |= trigger_bit(trigger);
                        } else {
                            objective = Some(objective::RetryObjective::new(next_id, revision,
                                trigger_bit(trigger), Duration::from_millis(cfg.general.me_reinit_coalesce_window_ms)));
                            next_id = next_id.wrapping_add(1);
                        }
                        observed_revision = revision;
                    }
                    None => trigger_channel_open = false,
                }
            }
            changed = epochs.changed(), if epoch_open => {
                if changed.is_err() { epoch_open = false; }
            }
            joined = tasks.join_next_with_id(), if !tasks.is_empty() => {
                let Some(joined) = joined else { continue; };
                let (id, succeeded) = match joined {
                    Ok((id, Some(succeeded))) => (id, succeeded),
                    Ok((_, None)) => return,
                    Err(error) => {
                        warn!(error = %error, "ME reinit task failed");
                        (error.id(), false)
                    }
                };
                let Some(identity) = owners.remove(&id) else { continue; };
                if succeeded {
                    me_ready_tx.send_modify(|version| *version = version.saturating_add(1));
                }
                if let Some(current) = objective.as_mut()
                    && current.matches(identity) {
                    if succeeded {
                        completed_revision = Some(current.revision);
                        objective = None;
                    } else {
                        current.failed(Duration::from_millis(pool.hardswap_warmup_backoff_ms(current.attempt)));
                    }
                }
            }
            _ = async {
                if let Some(deadline) = deadline { tokio::time::sleep_until(deadline).await; }
            }, if can_launch && deadline.is_some() => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::config::ProxyConfig;

    #[test]
    fn effective_concurrency_is_one_for_singleflight_and_bounded_otherwise() {
        let mut config = ProxyConfig::default();
        config.general.me_reinit_singleflight = true;
        config.general.me_reinit_max_concurrency = 8;
        assert_eq!(super::effective_reinit_concurrency(&config), 1);

        config.general.me_reinit_singleflight = false;
        config.general.me_reinit_max_concurrency = 2;
        assert_eq!(super::effective_reinit_concurrency(&config), 2);
        config.general.me_reinit_max_concurrency = usize::MAX;
        assert_eq!(super::effective_reinit_concurrency(&config), 8);
    }
}

/// Periodically enqueue reinitialization triggers for ME generations.
pub async fn me_rotation_task(
    mut config_rx: watch::Receiver<Arc<ProxyConfig>>,
    reinit_tx: mpsc::Sender<MeReinitTrigger>,
) {
    let mut interval_secs = config_rx
        .borrow()
        .general
        .effective_me_reinit_every_secs()
        .max(1);
    let mut interval = Duration::from_secs(interval_secs);
    let mut next_tick = tokio::time::Instant::now() + interval;

    info!(interval_secs, "ME periodic reinit task started");

    loop {
        let sleep = tokio::time::sleep_until(next_tick);
        tokio::pin!(sleep);

        tokio::select! {
            _ = &mut sleep => {
                enqueue_reinit_trigger(&reinit_tx, MeReinitTrigger::Periodic);
                let refreshed_secs = config_rx
                    .borrow()
                    .general
                    .effective_me_reinit_every_secs()
                    .max(1);
                if refreshed_secs != interval_secs {
                    info!(
                        old_me_reinit_every_secs = interval_secs,
                        new_me_reinit_every_secs = refreshed_secs,
                        "ME periodic reinit interval changed"
                    );
                    interval_secs = refreshed_secs;
                    interval = Duration::from_secs(interval_secs);
                }
                next_tick = tokio::time::Instant::now() + interval;
            }
            changed = config_rx.changed() => {
                if changed.is_err() {
                    warn!("ME periodic reinit task stopped: config channel closed");
                    break;
                }
                let new_secs = config_rx
                    .borrow()
                    .general
                    .effective_me_reinit_every_secs()
                    .max(1);
                if new_secs == interval_secs {
                    continue;
                }

                if new_secs < interval_secs {
                    info!(
                        old_me_reinit_every_secs = interval_secs,
                        new_me_reinit_every_secs = new_secs,
                        "ME periodic reinit interval decreased, running immediate reinit"
                    );
                    interval_secs = new_secs;
                    interval = Duration::from_secs(interval_secs);
                    enqueue_reinit_trigger(&reinit_tx, MeReinitTrigger::Periodic);
                    next_tick = tokio::time::Instant::now() + interval;
                } else {
                    info!(
                        old_me_reinit_every_secs = interval_secs,
                        new_me_reinit_every_secs = new_secs,
                        "ME periodic reinit interval increased"
                    );
                    interval_secs = new_secs;
                    interval = Duration::from_secs(interval_secs);
                    next_tick = tokio::time::Instant::now() + interval;
                }
            }
        }
    }
}
