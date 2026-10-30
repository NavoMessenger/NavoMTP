use std::collections::{BTreeMap, BTreeSet};
use std::future::pending;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::{Notify, watch};
use tokio_util::sync::CancellationToken;

use crate::config::ConntrackBackend;
use crate::stats::Stats;

use super::actor::{FirewallReconciler, ReconcileOutcome};
use super::command::{CommandError, CommandErrorKind, CommandSpec, FirewallCommandRunner};
use super::model::{
    AppliedPlan, AppliedState, DesiredPolicy, DesiredState, NotrackTarget, ShadowSlot,
};
use super::transaction::{InterruptibleRunner, reconcile_once};

#[path = "tests/model_tests.rs"]
mod model_tests;

// Replays helper diagnostics through command classification and recovery.
#[path = "tests/recovery_errors.rs"]
mod recovery_errors;

#[derive(Clone)]
struct FailureRule {
    binary: &'static str,
    occurrence: usize,
}

#[derive(Default)]
struct FakeState {
    calls: Vec<CommandSpec>,
    binary_calls: BTreeMap<&'static str, usize>,
    failures: Vec<FailureRule>,
}

#[derive(Clone)]
struct FakeRunner {
    available: Arc<BTreeSet<&'static str>>,
    has_cap_net_admin: bool,
    state: Arc<Mutex<FakeState>>,
}

impl FakeRunner {
    fn all_available() -> Self {
        Self {
            available: Arc::new(BTreeSet::from([
                "conntrack",
                "ip6tables",
                "ip6tables-restore",
                "iptables",
                "iptables-restore",
                "nft",
            ])),
            has_cap_net_admin: true,
            state: Arc::new(Mutex::new(FakeState::default())),
        }
    }

    fn with_failure(self, binary: &'static str, occurrence: usize) -> Self {
        self.state
            .lock()
            .unwrap()
            .failures
            .push(FailureRule { binary, occurrence });
        self
    }

    fn calls(&self) -> Vec<CommandSpec> {
        self.state.lock().unwrap().calls.clone()
    }
}

impl FirewallCommandRunner for FakeRunner {
    fn available(&self, binary: &str) -> bool {
        self.available.contains(binary)
    }

    fn has_cap_net_admin(&self) -> bool {
        self.has_cap_net_admin
    }

    async fn run(&self, spec: CommandSpec) -> Result<(), CommandError> {
        let mut state = self.state.lock().unwrap();
        let occurrence = {
            let count = state.binary_calls.entry(spec.binary).or_default();
            *count += 1;
            *count
        };
        state.calls.push(spec.clone());
        if state
            .failures
            .iter()
            .any(|failure| failure.binary == spec.binary && failure.occurrence == occurrence)
        {
            return Err(CommandError::failed(format!(
                "injected {} failure at occurrence {}",
                spec.binary, occurrence
            )));
        }
        drop(state);

        let operation = spec.args.get(2).map(String::as_str);
        if (matches!(spec.binary, "iptables" | "ip6tables")
            && matches!(operation, Some("-C" | "-D" | "-F" | "-X")))
            || (spec.binary == "nft" && spec.args.first().map(String::as_str) == Some("delete"))
        {
            return Err(CommandError {
                kind: CommandErrorKind::NotFound,
                message: "injected object not found".to_string(),
            });
        }
        Ok(())
    }
}

struct BlockingRunner {
    entered: Arc<Notify>,
}

impl FirewallCommandRunner for BlockingRunner {
    fn available(&self, _binary: &str) -> bool {
        true
    }

    fn has_cap_net_admin(&self) -> bool {
        true
    }

    async fn run(&self, _spec: CommandSpec) -> Result<(), CommandError> {
        self.entered.notify_one();
        pending().await
    }
}

fn target(ip: Option<&str>, port: u16) -> NotrackTarget {
    NotrackTarget {
        ip: ip.map(|value| value.parse().unwrap()),
        port,
    }
}

fn desired(generation: u64, policy: DesiredPolicy) -> DesiredState {
    DesiredState {
        generation,
        policy,
        stats: Arc::new(Stats::new()),
    }
}

fn dual_stack_policy(port: u16) -> DesiredPolicy {
    DesiredPolicy::Rules {
        configured_backend: ConntrackBackend::Iptables,
        v4: vec![target(Some("192.0.2.10"), port)],
        v6: vec![target(Some("2001:db8::10"), port)],
    }
}

fn nft_dual_stack_policy(port: u16) -> DesiredPolicy {
    DesiredPolicy::Rules {
        configured_backend: ConntrackBackend::Nftables,
        v4: vec![target(Some("192.0.2.10"), port)],
        v6: vec![target(Some("2001:db8::10"), port)],
    }
}

#[tokio::test]
async fn successful_reconcile_flips_between_shadow_slots() {
    let runner = FakeRunner::all_available();
    let mut applied = AppliedState::Known(AppliedPlan::Empty);
    let first = desired(1, dual_stack_policy(443));

    reconcile_once(&runner, &runner, &mut applied, &first)
        .await
        .unwrap();
    assert!(matches!(
        applied,
        AppliedState::Known(AppliedPlan::Iptables {
            slot: ShadowSlot::A,
            ..
        })
    ));

    let second = desired(2, dual_stack_policy(8443));
    reconcile_once(&runner, &runner, &mut applied, &second)
        .await
        .unwrap();
    assert!(matches!(
        applied,
        AppliedState::Known(AppliedPlan::Iptables {
            slot: ShadowSlot::B,
            ..
        })
    ));
    assert!(runner.calls().iter().any(|call| {
        call.stdin
            .as_deref()
            .is_some_and(|script| script.contains("-A TELEMT_NOTRACK -j TELEMT_NT_B"))
    }));
}

#[tokio::test]
async fn identical_policy_is_command_free_after_convergence() {
    let runner = FakeRunner::all_available();
    let mut applied = AppliedState::Known(AppliedPlan::Empty);
    reconcile_once(
        &runner,
        &runner,
        &mut applied,
        &desired(1, dual_stack_policy(443)),
    )
    .await
    .unwrap();
    let calls_after_convergence = runner.calls().len();

    reconcile_once(
        &runner,
        &runner,
        &mut applied,
        &desired(2, dual_stack_policy(443)),
    )
    .await
    .unwrap();

    assert_eq!(runner.calls().len(), calls_after_convergence);
}

#[tokio::test]
async fn backend_migration_failure_restores_previous_backend() {
    let runner = FakeRunner::all_available().with_failure("ip6tables-restore", 3);
    let mut applied = AppliedState::Known(AppliedPlan::Empty);
    reconcile_once(
        &runner,
        &runner,
        &mut applied,
        &desired(1, dual_stack_policy(443)),
    )
    .await
    .unwrap();
    let previous = applied.clone();

    let failure = reconcile_once(
        &runner,
        &runner,
        &mut applied,
        &desired(2, nft_dual_stack_policy(8443)),
    )
    .await
    .unwrap_err();

    assert_eq!(failure.rollback_succeeded, Some(true));
    assert_eq!(applied, previous);
}

#[tokio::test]
async fn unavailable_target_does_not_clear_confirmed_applied_policy() {
    let runner = FakeRunner::all_available();
    let mut applied = AppliedState::Known(AppliedPlan::Empty);
    reconcile_once(
        &runner,
        &runner,
        &mut applied,
        &desired(1, dual_stack_policy(443)),
    )
    .await
    .unwrap();
    let previous = applied.clone();
    let unavailable = FakeRunner {
        available: Arc::new(BTreeSet::new()),
        has_cap_net_admin: false,
        state: Arc::new(Mutex::new(FakeState::default())),
    };

    let failure = reconcile_once(
        &unavailable,
        &unavailable,
        &mut applied,
        &desired(2, nft_dual_stack_policy(8443)),
    )
    .await
    .unwrap_err();

    assert_eq!(failure.rollback_succeeded, None);
    assert_eq!(applied, previous);
    assert!(unavailable.calls().is_empty());
}

#[tokio::test]
async fn partial_dual_stack_failure_restores_previous_applied_plan() {
    let runner = FakeRunner::all_available().with_failure("ip6tables-restore", 4);
    let mut applied = AppliedState::Known(AppliedPlan::Empty);
    let first = desired(1, dual_stack_policy(443));
    reconcile_once(&runner, &runner, &mut applied, &first)
        .await
        .unwrap();
    let previous = applied.clone();

    let failure = reconcile_once(
        &runner,
        &runner,
        &mut applied,
        &desired(2, dual_stack_policy(8443)),
    )
    .await
    .unwrap_err();

    assert_eq!(failure.rollback_succeeded, Some(true));
    assert_eq!(applied, previous);
}

#[tokio::test]
async fn rollback_failure_marks_applied_state_unknown() {
    let runner = FakeRunner::all_available()
        .with_failure("ip6tables-restore", 4)
        .with_failure("nft", 2);
    let mut applied = AppliedState::Known(AppliedPlan::Empty);
    reconcile_once(
        &runner,
        &runner,
        &mut applied,
        &desired(1, dual_stack_policy(443)),
    )
    .await
    .unwrap();

    let failure = reconcile_once(
        &runner,
        &runner,
        &mut applied,
        &desired(2, dual_stack_policy(8443)),
    )
    .await
    .unwrap_err();

    assert_eq!(failure.rollback_succeeded, Some(false));
    assert_eq!(applied, AppliedState::Unknown);
}

#[tokio::test]
async fn transaction_cancellation_does_not_claim_a_new_applied_plan() {
    let entered = Arc::new(Notify::new());
    let runner = BlockingRunner {
        entered: entered.clone(),
    };
    let terminal = CancellationToken::new();
    let process_cancellation = CancellationToken::new();
    let interruptible = InterruptibleRunner::new(&runner, &terminal, &process_cancellation);
    let mut applied = AppliedState::Known(AppliedPlan::Empty);
    let desired = desired(1, dual_stack_policy(443));
    let failure = {
        let transaction = reconcile_once(&interruptible, &runner, &mut applied, &desired);
        tokio::pin!(transaction);

        tokio::select! {
            _ = entered.notified() => terminal.cancel(),
            _ = &mut transaction => panic!("transaction completed before injected cancellation"),
        }
        transaction.await.unwrap_err()
    };

    assert!(failure.cancelled);
    assert_eq!(applied, AppliedState::Known(AppliedPlan::Empty));
}

#[test]
fn desired_watch_coalesces_and_rejects_stale_or_conflicting_generations() {
    let runner = FakeRunner::all_available();
    let (desired_tx, desired_rx) = watch::channel(None);
    let (status_tx, _status_rx) = watch::channel(None);
    let terminal = CancellationToken::new();
    let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let completed = Arc::new(Notify::new());
    let mut reconciler = FirewallReconciler::new(
        runner,
        desired_rx,
        status_tx,
        terminal,
        closed,
        Arc::new(std::sync::atomic::AtomicBool::new(false)),
        Arc::new(std::sync::atomic::AtomicBool::new(false)),
        completed,
    );

    desired_tx.send_replace(Some(desired(1, dual_stack_policy(443))));
    desired_tx.send_replace(Some(desired(2, dual_stack_policy(8443))));
    assert_eq!(reconciler.take_latest_desired().unwrap().generation, 2);

    desired_tx.send_replace(Some(desired(1, dual_stack_policy(443))));
    assert!(reconciler.take_latest_desired().is_none());

    desired_tx.send_replace(Some(desired(2, dual_stack_policy(9443))));
    assert!(reconciler.take_latest_desired().is_none());
}

#[tokio::test(start_paused = true)]
async fn actor_retries_with_backoff_and_cleans_owned_rules_on_shutdown() {
    let runner = FakeRunner::all_available().with_failure("iptables-restore", 1);
    let observed_runner = runner.clone();
    let (desired_tx, desired_rx) = watch::channel(None);
    let (status_tx, mut status_rx) = watch::channel(None);
    let terminal = CancellationToken::new();
    let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let completed_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let cleanup_succeeded = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let completed = Arc::new(Notify::new());
    let reconciler = FirewallReconciler::new(
        runner,
        desired_rx,
        status_tx,
        terminal.clone(),
        closed.clone(),
        completed_flag.clone(),
        cleanup_succeeded.clone(),
        completed,
    );
    let process_cancellation = CancellationToken::new();
    let task = tokio::spawn(reconciler.run(process_cancellation));

    let initial_desired = desired(2, dual_stack_policy(443));
    let desired_stats = initial_desired.stats.clone();
    desired_tx.send_replace(Some(initial_desired));
    status_rx.changed().await.unwrap();
    assert_eq!(
        status_rx.borrow().as_ref().unwrap().outcome,
        ReconcileOutcome::Failed
    );
    let calls_after_failure = observed_runner.calls().len();

    desired_tx.send_replace(Some(desired(1, dual_stack_policy(7443))));
    tokio::task::yield_now().await;
    desired_tx.send_replace(Some(desired(2, dual_stack_policy(9443))));
    tokio::task::yield_now().await;
    tokio::time::advance(Duration::from_millis(999)).await;
    tokio::task::yield_now().await;
    assert_eq!(observed_runner.calls().len(), calls_after_failure);

    tokio::time::advance(Duration::from_millis(1)).await;
    status_rx.changed().await.unwrap();
    assert_eq!(
        status_rx.borrow().as_ref().unwrap().outcome,
        ReconcileOutcome::Applied
    );
    assert_eq!(status_rx.borrow().as_ref().unwrap().generation, 2);
    assert!(observed_runner.calls().iter().all(|call| {
        call.stdin
            .as_ref()
            .is_none_or(|script| !script.contains("7443") && !script.contains("9443"))
    }));
    let calls_before_shutdown = observed_runner.calls().len();

    terminal.cancel();
    tokio::time::timeout(Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap();
    assert!(closed.load(Ordering::Acquire));
    assert!(completed_flag.load(Ordering::Acquire));
    assert!(cleanup_succeeded.load(Ordering::Acquire));
    assert!(!desired_stats.get_conntrack_rule_apply_ok());
    assert!(observed_runner.calls().len() > calls_before_shutdown);
}

#[tokio::test]
async fn actor_reports_terminal_cleanup_failure_separately_from_completion() {
    let runner = FakeRunner::all_available().with_failure("nft", 1);
    let (_desired_tx, desired_rx) = watch::channel(None);
    let (status_tx, _status_rx) = watch::channel(None);
    let terminal = CancellationToken::new();
    terminal.cancel();
    let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let completed_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let cleanup_succeeded = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let reconciler = FirewallReconciler::new(
        runner,
        desired_rx,
        status_tx,
        terminal,
        closed.clone(),
        completed_flag.clone(),
        cleanup_succeeded.clone(),
        Arc::new(Notify::new()),
    );

    reconciler.run(CancellationToken::new()).await;

    assert!(closed.load(Ordering::Acquire));
    assert!(completed_flag.load(Ordering::Acquire));
    assert!(!cleanup_succeeded.load(Ordering::Acquire));
}
