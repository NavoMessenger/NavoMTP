use std::time::Duration;

use tokio_util::sync::CancellationToken;

use crate::config::ConntrackBackend;

use super::command::{CommandError, CommandErrorKind, CommandSpec, FirewallCommandRunner};
use super::iptables::{self, IpFamily};
use super::model::{AppliedPlan, AppliedState, DesiredPolicy, DesiredState, ShadowSlot};
use super::nftables;

const TRANSACTION_TIMEOUT: Duration = Duration::from_secs(30);

pub(super) struct InterruptibleRunner<'a, R> {
    inner: &'a R,
    terminal: &'a CancellationToken,
    process_cancellation: &'a CancellationToken,
}

impl<'a, R> InterruptibleRunner<'a, R> {
    pub(super) fn new(
        inner: &'a R,
        terminal: &'a CancellationToken,
        process_cancellation: &'a CancellationToken,
    ) -> Self {
        Self {
            inner,
            terminal,
            process_cancellation,
        }
    }
}

impl<R: FirewallCommandRunner> FirewallCommandRunner for InterruptibleRunner<'_, R> {
    fn available(&self, binary: &str) -> bool {
        self.inner.available(binary)
    }

    fn has_cap_net_admin(&self) -> bool {
        self.inner.has_cap_net_admin()
    }

    async fn run(&self, spec: CommandSpec) -> Result<(), CommandError> {
        tokio::select! {
            biased;
            _ = self.terminal.cancelled() => Err(CommandError::cancelled()),
            _ = self.process_cancellation.cancelled() => Err(CommandError::cancelled()),
            result = self.inner.run(spec) => result,
        }
    }
}

#[derive(Debug)]
pub(super) struct ReconcileFailure {
    pub(super) message: String,
    pub(super) rollback_succeeded: Option<bool>,
    pub(super) cancelled: bool,
}

pub(super) async fn reconcile_once<I, R>(
    interruptible: &I,
    recovery_runner: &R,
    applied: &mut AppliedState,
    desired: &DesiredState,
) -> Result<(), ReconcileFailure>
where
    I: FirewallCommandRunner,
    R: FirewallCommandRunner,
{
    if let AppliedState::Known(current) = applied
        && current.matches_policy(&desired.policy)
    {
        return Ok(());
    }

    if matches!(applied, AppliedState::Unknown) {
        match tokio::time::timeout(TRANSACTION_TIMEOUT, recover_to_empty(interruptible)).await {
            Ok(Ok(())) => *applied = AppliedState::Known(AppliedPlan::Empty),
            Ok(Err(error)) if error.kind == CommandErrorKind::Cancelled => {
                return Err(cancelled_failure());
            }
            Ok(Err(error)) => {
                return Err(ReconcileFailure {
                    message: format!("startup recovery failed: {error}"),
                    rollback_succeeded: None,
                    cancelled: false,
                });
            }
            Err(_) => {
                return Err(ReconcileFailure {
                    message: "startup recovery timed out".to_string(),
                    rollback_succeeded: None,
                    cancelled: false,
                });
            }
        }
    }

    let previous = match applied {
        AppliedState::Known(plan) => plan.clone(),
        AppliedState::Unknown => unreachable!("unknown state was recovered above"),
    };
    let target = match resolve_target(interruptible, &desired.policy, &previous) {
        Ok(target) => target,
        Err(error) => {
            return Err(ReconcileFailure {
                message: error.message,
                rollback_succeeded: None,
                cancelled: false,
            });
        }
    };

    let transition = tokio::time::timeout(
        TRANSACTION_TIMEOUT,
        transition_plan(interruptible, &previous, &target),
    )
    .await;
    match transition {
        Ok(Ok(())) => {
            *applied = AppliedState::Known(target);
            Ok(())
        }
        Ok(Err(error)) if error.kind == CommandErrorKind::Cancelled => Err(cancelled_failure()),
        Ok(Err(error)) => {
            rollback_after_failure(recovery_runner, applied, previous, error.message).await
        }
        Err(_) => {
            rollback_after_failure(
                recovery_runner,
                applied,
                previous,
                "firewall apply transaction timed out".to_string(),
            )
            .await
        }
    }
}

async fn rollback_after_failure<R: FirewallCommandRunner>(
    runner: &R,
    applied: &mut AppliedState,
    previous: AppliedPlan,
    apply_error: String,
) -> Result<(), ReconcileFailure> {
    let rollback = tokio::time::timeout(TRANSACTION_TIMEOUT, restore_plan(runner, &previous)).await;
    let rollback_result = match rollback {
        Ok(result) => result,
        Err(_) => Err(CommandError::failed("firewall rollback timed out")),
    };
    match rollback_result {
        Ok(()) => {
            *applied = AppliedState::Known(previous);
            Err(ReconcileFailure {
                message: apply_error,
                rollback_succeeded: Some(true),
                cancelled: false,
            })
        }
        Err(rollback_error) => {
            *applied = AppliedState::Unknown;
            if rollback_error.kind == CommandErrorKind::Cancelled {
                return Err(cancelled_failure());
            }
            Err(ReconcileFailure {
                message: format!("{apply_error}; rollback failed: {rollback_error}"),
                rollback_succeeded: Some(false),
                cancelled: false,
            })
        }
    }
}

fn cancelled_failure() -> ReconcileFailure {
    ReconcileFailure {
        message: "firewall transaction cancelled for process shutdown".to_string(),
        rollback_succeeded: None,
        cancelled: true,
    }
}

pub(super) fn resolve_target<R: FirewallCommandRunner>(
    runner: &R,
    desired: &DesiredPolicy,
    previous: &AppliedPlan,
) -> Result<AppliedPlan, CommandError> {
    let DesiredPolicy::Rules {
        configured_backend,
        v4,
        v6,
    } = desired
    else {
        return Ok(AppliedPlan::Empty);
    };
    if !runner.has_cap_net_admin() {
        return Err(CommandError::failed(
            "CAP_NET_ADMIN is required for conntrack firewall reconciliation",
        ));
    }
    let next_slot = previous.slot().map_or(ShadowSlot::A, ShadowSlot::other);
    let iptables_available = (v4.is_empty() || iptables::family_available(runner, IpFamily::V4))
        && (v6.is_empty() || iptables::family_available(runner, IpFamily::V6));
    match configured_backend {
        ConntrackBackend::Nftables if nftables::available(runner) => Ok(AppliedPlan::Nftables {
            slot: next_slot,
            v4: v4.clone(),
            v6: v6.clone(),
        }),
        ConntrackBackend::Iptables if iptables_available => Ok(AppliedPlan::Iptables {
            slot: next_slot,
            v4: v4.clone(),
            v6: v6.clone(),
        }),
        ConntrackBackend::Auto if nftables::available(runner) => Ok(AppliedPlan::Nftables {
            slot: next_slot,
            v4: v4.clone(),
            v6: v6.clone(),
        }),
        ConntrackBackend::Auto if iptables_available => Ok(AppliedPlan::Iptables {
            slot: next_slot,
            v4: v4.clone(),
            v6: v6.clone(),
        }),
        backend => Err(CommandError::failed(format!(
            "configured conntrack firewall backend {backend:?} is unavailable"
        ))),
    }
}

pub(super) async fn transition_plan<R: FirewallCommandRunner>(
    runner: &R,
    previous: &AppliedPlan,
    target: &AppliedPlan,
) -> Result<(), CommandError> {
    install_plan(runner, target).await?;
    match (previous, target) {
        (
            AppliedPlan::Iptables {
                v4: previous_v4,
                v6: previous_v6,
                ..
            },
            AppliedPlan::Iptables { v4, v6, .. },
        ) => {
            if !previous_v4.is_empty() && v4.is_empty() {
                iptables::activate_family(runner, IpFamily::V4, None).await?;
            }
            if !previous_v6.is_empty() && v6.is_empty() {
                iptables::activate_family(runner, IpFamily::V6, None).await?;
            }
        }
        (
            AppliedPlan::Nftables {
                slot: previous_slot,
                ..
            },
            AppliedPlan::Nftables { slot, .. },
        ) if previous_slot != slot => {
            nftables::deactivate(runner, *previous_slot).await?;
        }
        (_, _) if previous != target => clear_plan(runner, previous).await?,
        _ => {}
    }
    Ok(())
}

async fn install_plan<R: FirewallCommandRunner>(
    runner: &R,
    plan: &AppliedPlan,
) -> Result<(), CommandError> {
    match plan {
        AppliedPlan::Empty => Ok(()),
        AppliedPlan::Iptables { slot, v4, v6 } => {
            if !v4.is_empty() {
                iptables::stage_family(runner, IpFamily::V4, *slot, v4).await?;
            }
            if !v6.is_empty() {
                iptables::stage_family(runner, IpFamily::V6, *slot, v6).await?;
            }
            if !v4.is_empty() {
                iptables::activate_family(runner, IpFamily::V4, Some(*slot)).await?;
            }
            if !v6.is_empty() {
                iptables::activate_family(runner, IpFamily::V6, Some(*slot)).await?;
            }
            Ok(())
        }
        AppliedPlan::Nftables { slot, v4, v6 } => {
            nftables::stage(runner, *slot, v4, v6).await?;
            nftables::activate(runner, *slot).await
        }
    }
}

async fn clear_plan<R: FirewallCommandRunner>(
    runner: &R,
    plan: &AppliedPlan,
) -> Result<(), CommandError> {
    match plan {
        AppliedPlan::Empty => Ok(()),
        AppliedPlan::Iptables { v4, v6, .. } => {
            if !v4.is_empty() {
                iptables::activate_family(runner, IpFamily::V4, None).await?;
            }
            if !v6.is_empty() {
                iptables::activate_family(runner, IpFamily::V6, None).await?;
            }
            Ok(())
        }
        AppliedPlan::Nftables { slot, .. } => nftables::deactivate(runner, *slot).await,
    }
}

async fn restore_plan<R: FirewallCommandRunner>(
    runner: &R,
    plan: &AppliedPlan,
) -> Result<(), CommandError> {
    recover_to_empty(runner).await?;
    install_plan(runner, plan).await
}

pub(super) async fn recover_to_empty<R: FirewallCommandRunner>(
    runner: &R,
) -> Result<(), CommandError> {
    let nft_result = nftables::cleanup_all(runner).await;
    let iptables_result = iptables::cleanup_all(runner).await;
    match (nft_result, iptables_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(first), Ok(())) | (Ok(()), Err(first)) => Err(first),
        (Err(first), Err(second)) => Err(CommandError::failed(format!(
            "{}; {}",
            first.message, second.message
        ))),
    }
}
