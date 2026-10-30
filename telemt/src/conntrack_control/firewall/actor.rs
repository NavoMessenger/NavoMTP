use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::{Notify, watch};
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::config::ProxyConfig;
use crate::maestro::control_plane::ProcessControlPlane;
use crate::stats::Stats;

use super::command::{CommandError, FirewallCommandRunner, SystemCommandRunner};
use super::model::{AppliedPlan, AppliedState, DesiredPolicy, DesiredState};
use super::transaction::{InterruptibleRunner, reconcile_once, recover_to_empty};

const SHUTDOWN_CLEANUP_TIMEOUT: Duration = Duration::from_secs(30);
const SHUTDOWN_WAIT_TIMEOUT: Duration = Duration::from_secs(35);
const INITIAL_RECONCILE_TIMEOUT: Duration = Duration::from_secs(65);
const RETRY_DELAYS: [Duration; 6] = [
    Duration::from_secs(1),
    Duration::from_secs(2),
    Duration::from_secs(4),
    Duration::from_secs(8),
    Duration::from_secs(16),
    Duration::from_secs(30),
];

/// Reports whether a generation's desired firewall policy was confirmed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ReconcileOutcome {
    /// The applied policy matches the accepted generation's desired policy.
    Applied,
    /// The attempt failed without confirming the desired policy.
    Failed,
}

/// Associates a reconciliation result with its accepted runtime generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ReconcileStatus {
    /// Runtime generation whose desired policy was attempted.
    pub(super) generation: u64,
    /// Result of the latest completed attempt for this generation.
    pub(super) outcome: ReconcileOutcome,
}

/// Process-owned publisher and shutdown owner for conntrack firewall policy.
#[derive(Clone)]
pub(crate) struct FirewallAuthority {
    desired_tx: watch::Sender<Option<DesiredState>>,
    status_rx: watch::Receiver<Option<ReconcileStatus>>,
    terminal: CancellationToken,
    closed: Arc<AtomicBool>,
    completed_flag: Arc<AtomicBool>,
    cleanup_succeeded: Arc<AtomicBool>,
    completed: Arc<Notify>,
}

impl FirewallAuthority {
    /// Starts reconciliation only when enabled and CAP_NET_ADMIN is available.
    pub(crate) fn spawn(
        control_plane: &ProcessControlPlane,
        config: &ProxyConfig,
    ) -> Result<Option<Self>, String> {
        let Some((authority, actor)) = Self::prepare(config, SystemCommandRunner) else {
            return Ok(None);
        };
        control_plane
            .spawn_cooperative(move |process_cancellation| async move {
                actor.run(process_cancellation).await;
            })
            .map_err(|_| {
                "process control-plane admission closed before conntrack firewall startup"
                    .to_string()
            })?;
        Ok(Some(authority))
    }

    // Admission precedes allocation so an opted-out process never owns firewall cleanup.
    // Keeping construction separate permits fake runners without changing async Send bounds.
    fn prepare<R>(config: &ProxyConfig, runner: R) -> Option<(Self, FirewallReconciler<R>)>
    where
        R: FirewallCommandRunner + 'static,
    {
        if !config.server.conntrack_control.inline_conntrack_control || !runner.has_cap_net_admin()
        {
            return None;
        }
        let (desired_tx, desired_rx) = watch::channel(None);
        let (status_tx, status_rx) = watch::channel(None);
        let terminal = CancellationToken::new();
        let closed = Arc::new(AtomicBool::new(false));
        let completed_flag = Arc::new(AtomicBool::new(false));
        let cleanup_succeeded = Arc::new(AtomicBool::new(false));
        let completed = Arc::new(Notify::new());
        let actor = FirewallReconciler::new(
            runner,
            desired_rx,
            status_tx,
            terminal.clone(),
            Arc::clone(&closed),
            Arc::clone(&completed_flag),
            Arc::clone(&cleanup_succeeded),
            Arc::clone(&completed),
        );
        let authority = Self {
            desired_tx,
            status_rx,
            terminal,
            closed,
            completed_flag,
            cleanup_succeeded,
            completed,
        };
        Some((authority, actor))
    }

    /// Publishes policy only after its runtime generation becomes active.
    pub(crate) fn publish(
        &self,
        generation: u64,
        config: Arc<ProxyConfig>,
        stats: Arc<Stats>,
    ) -> bool {
        if self.closed.load(Ordering::Acquire) {
            stats.set_conntrack_rule_apply_ok(false);
            return false;
        }
        stats.set_conntrack_rule_apply_ok(false);
        self.desired_tx.send_replace(Some(DesiredState {
            generation,
            policy: DesiredPolicy::from_config(config.as_ref()),
            stats,
        }));
        true
    }

    /// Publishes startup policy and waits for its first bounded attempt.
    pub(crate) async fn publish_initial(
        &self,
        generation: u64,
        config: Arc<ProxyConfig>,
        stats: Arc<Stats>,
    ) -> bool {
        let mut status_rx = self.status_rx.clone();
        if !self.publish(generation, config, stats) {
            return false;
        }
        tokio::time::timeout(INITIAL_RECONCILE_TIMEOUT, async move {
            loop {
                if let Some(status) = *status_rx.borrow_and_update()
                    && status.generation == generation
                {
                    return status.outcome == ReconcileOutcome::Applied;
                }
                if status_rx.changed().await.is_err() {
                    return false;
                }
            }
        })
        .await
        .unwrap_or(false)
    }

    /// Stops policy admission and waits for bounded terminal cleanup.
    pub(crate) async fn shutdown_and_clear(&self) -> bool {
        let completed = self.completed.notified();
        tokio::pin!(completed);
        completed.as_mut().enable();
        if !self.closed.swap(true, Ordering::AcqRel) {
            if let Some(desired) = self.desired_tx.borrow().as_ref() {
                desired.stats.set_conntrack_rule_apply_ok(false);
            }
            self.terminal.cancel();
        }
        let finished = self.completed_flag.load(Ordering::Acquire)
            || tokio::time::timeout(SHUTDOWN_WAIT_TIMEOUT, completed)
                .await
                .is_ok();
        finished && self.cleanup_succeeded.load(Ordering::Acquire)
    }
}

struct CompletionGuard {
    closed: Arc<AtomicBool>,
    completed_flag: Arc<AtomicBool>,
    completed: Arc<Notify>,
}

impl Drop for CompletionGuard {
    fn drop(&mut self) {
        self.closed.store(true, Ordering::Release);
        self.completed_flag.store(true, Ordering::Release);
        self.completed.notify_waiters();
    }
}

/// Serializes confirmed-state transitions and retains cleanup ownership until shutdown.
pub(super) struct FirewallReconciler<R> {
    runner: R,
    desired_rx: watch::Receiver<Option<DesiredState>>,
    status_tx: watch::Sender<Option<ReconcileStatus>>,
    terminal: CancellationToken,
    completion: CompletionGuard,
    cleanup_succeeded: Arc<AtomicBool>,
    applied: AppliedState,
    last_generation: u64,
    last_policy: Option<DesiredPolicy>,
    last_stats: Option<Arc<Stats>>,
}

impl<R> FirewallReconciler<R>
where
    R: FirewallCommandRunner + 'static,
{
    /// Constructs an admitted actor with unknown state pending startup recovery.
    pub(super) fn new(
        runner: R,
        desired_rx: watch::Receiver<Option<DesiredState>>,
        status_tx: watch::Sender<Option<ReconcileStatus>>,
        terminal: CancellationToken,
        closed: Arc<AtomicBool>,
        completed_flag: Arc<AtomicBool>,
        cleanup_succeeded: Arc<AtomicBool>,
        completed: Arc<Notify>,
    ) -> Self {
        Self {
            runner,
            desired_rx,
            status_tx,
            terminal,
            completion: CompletionGuard {
                closed,
                completed_flag,
                completed,
            },
            cleanup_succeeded,
            applied: AppliedState::Unknown,
            last_generation: 0,
            last_policy: None,
            last_stats: None,
        }
    }

    /// Reconciles accepted generations and completes bounded cleanup on cancellation.
    pub(super) async fn run(mut self, process_cancellation: CancellationToken) {
        let mut current = None;
        let mut retry_index = 0usize;
        'run: loop {
            if current.is_none() {
                let changed = tokio::select! {
                    biased;
                    _ = self.terminal.cancelled() => false,
                    _ = process_cancellation.cancelled() => false,
                    changed = self.desired_rx.changed() => changed.is_ok(),
                };
                if !changed {
                    break;
                }
                current = self.take_latest_desired();
                retry_index = 0;
                if current.is_none() {
                    continue;
                }
            }

            let desired = current.as_ref().expect("desired state is present").clone();
            let interruptible =
                InterruptibleRunner::new(&self.runner, &self.terminal, &process_cancellation);
            let result =
                reconcile_once(&interruptible, &interruptible, &mut self.applied, &desired).await;
            match result {
                Ok(()) => {
                    desired
                        .stats
                        .increment_conntrack_rule_reconcile_success_total();
                    desired.stats.set_conntrack_rule_apply_ok(true);
                    self.status_tx.send_replace(Some(ReconcileStatus {
                        generation: desired.generation,
                        outcome: ReconcileOutcome::Applied,
                    }));
                    if self.terminal.is_cancelled() || process_cancellation.is_cancelled() {
                        desired.stats.set_conntrack_rule_apply_ok(false);
                        break;
                    }
                    current = None;
                    retry_index = 0;
                }
                Err(failure) if failure.cancelled => break,
                Err(failure) => {
                    desired
                        .stats
                        .increment_conntrack_rule_reconcile_error_total();
                    desired.stats.set_conntrack_rule_apply_ok(false);
                    if let Some(rollback_succeeded) = failure.rollback_succeeded {
                        if rollback_succeeded {
                            desired
                                .stats
                                .increment_conntrack_rule_rollback_success_total();
                        } else {
                            desired
                                .stats
                                .increment_conntrack_rule_rollback_error_total();
                        }
                    }
                    self.status_tx.send_replace(Some(ReconcileStatus {
                        generation: desired.generation,
                        outcome: ReconcileOutcome::Failed,
                    }));
                    warn!(
                        generation = desired.generation,
                        error = %failure.message,
                        "Failed to reconcile conntrack firewall policy"
                    );

                    let delay = RETRY_DELAYS[retry_index.min(RETRY_DELAYS.len() - 1)];
                    retry_index = retry_index.saturating_add(1);
                    let retry_deadline = tokio::time::Instant::now() + delay;
                    loop {
                        tokio::select! {
                            biased;
                            _ = self.terminal.cancelled() => break 'run,
                            _ = process_cancellation.cancelled() => break 'run,
                            changed = self.desired_rx.changed() => {
                                if changed.is_err() {
                                    break 'run;
                                }
                                if let Some(next) = self.take_latest_desired() {
                                    current = Some(next);
                                    retry_index = 0;
                                    break;
                                }
                            }
                            _ = tokio::time::sleep_until(retry_deadline) => break,
                        }
                    }
                }
            }

            if self.terminal.is_cancelled() || process_cancellation.is_cancelled() {
                break;
            }
            if self.desired_rx.has_changed().unwrap_or(false) {
                if let Some(next) = self.take_latest_desired() {
                    current = Some(next);
                    retry_index = 0;
                }
            }
        }

        if let Some(stats) = &self.last_stats {
            stats.set_conntrack_rule_apply_ok(false);
        }
        if let Err(error) =
            tokio::time::timeout(SHUTDOWN_CLEANUP_TIMEOUT, recover_to_empty(&self.runner))
                .await
                .unwrap_or_else(|_| {
                    Err(CommandError::failed("firewall shutdown cleanup timed out"))
                })
        {
            warn!(error = %error, "Failed to clear conntrack firewall policy during shutdown");
        } else {
            self.applied = AppliedState::Known(AppliedPlan::Empty);
            self.cleanup_succeeded.store(true, Ordering::Release);
        }
        let _completion = &self.completion;
    }

    /// Accepts fenced publications without replacing telemetry with stale desired state.
    pub(super) fn take_latest_desired(&mut self) -> Option<DesiredState> {
        let next = self.desired_rx.borrow_and_update().clone()?;
        if next.generation < self.last_generation {
            warn!(
                generation = next.generation,
                active_generation = self.last_generation,
                "Ignored stale conntrack firewall policy publication"
            );
            return None;
        }
        if next.generation == self.last_generation {
            if self.last_policy.as_ref() != Some(&next.policy) {
                warn!(
                    generation = next.generation,
                    "Ignored conflicting conntrack firewall policy for active generation"
                );
                return None;
            }
            self.last_stats = Some(next.stats.clone());
            if let AppliedState::Known(applied) = &self.applied
                && applied.matches_policy(&next.policy)
            {
                next.stats.set_conntrack_rule_apply_ok(true);
            }
            return Some(next);
        }
        self.last_generation = next.generation;
        self.last_policy = Some(next.policy.clone());
        self.last_stats = Some(next.stats.clone());
        Some(next)
    }
}

// Exercises startup admission and cleanup ownership with fake helper processes.
#[cfg(test)]
#[path = "tests/startup_admission.rs"]
mod startup_admission_tests;
