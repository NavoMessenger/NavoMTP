use std::sync::Mutex;
use std::sync::atomic::AtomicUsize;

use crate::config::{ConntrackBackend, ConntrackMode};

use super::super::command::{CommandErrorKind, CommandSpec, classify_command_error};
use super::super::transaction::reconcile_once;
use super::*;

const NETLINK_ERROR: &str =
    "src/mnl.c:68: Unable to initialize Netlink socket: Address family not supported by protocol";
const PERMISSION_ERROR: &str = "iptables v1.8.11 (nf_tables): Could not fetch rule set generation id: Permission denied (you must be root)";

#[derive(Clone)]
struct StartupRunner {
    has_cap_net_admin: bool,
    cap_probes: Arc<AtomicUsize>,
    calls: Arc<Mutex<Vec<CommandSpec>>>,
    failure: Option<&'static str>,
}

impl StartupRunner {
    fn new(has_cap_net_admin: bool, failure: Option<&'static str>) -> Self {
        Self {
            has_cap_net_admin,
            cap_probes: Arc::new(AtomicUsize::new(0)),
            calls: Arc::new(Mutex::new(Vec::new())),
            failure,
        }
    }

    fn calls(&self) -> Vec<CommandSpec> {
        self.calls.lock().unwrap().clone()
    }
}

impl FirewallCommandRunner for StartupRunner {
    fn available(&self, _binary: &str) -> bool {
        true
    }

    fn has_cap_net_admin(&self) -> bool {
        self.cap_probes.fetch_add(1, Ordering::Relaxed);
        self.has_cap_net_admin
    }

    async fn run(&self, spec: CommandSpec) -> Result<(), CommandError> {
        self.calls.lock().unwrap().push(spec.clone());
        if let Some(message) = self.failure {
            return Err(CommandError {
                kind: classify_command_error(spec.binary, &spec.args, message),
                message: message.to_string(),
            });
        }
        if (spec.binary == "nft" && spec.args.first().map(String::as_str) == Some("delete"))
            || (matches!(spec.binary, "iptables" | "ip6tables")
                && matches!(
                    spec.args.get(2).map(String::as_str),
                    Some("-C" | "-D" | "-F" | "-X")
                ))
        {
            return Err(CommandError {
                kind: CommandErrorKind::NotFound,
                message: "injected absent owned object".to_string(),
            });
        }
        Ok(())
    }
}

fn start_with_runner(
    config: &ProxyConfig,
    runner: StartupRunner,
    scope: &ProcessControlPlane,
) -> Option<FirewallAuthority> {
    let (authority, actor) = FirewallAuthority::prepare(config, runner)?;
    assert!(
        scope
            .spawn_cooperative(move |cancellation| actor.run(cancellation))
            .is_ok()
    );
    Some(authority)
}

#[tokio::test(start_paused = true)]
async fn disabled_startup_never_acquires_cleanup_ownership() {
    for explicit in [false, true] {
        for has_cap in [true, false] {
            for backend in [
                ConntrackBackend::Auto,
                ConntrackBackend::Nftables,
                ConntrackBackend::Iptables,
            ] {
                for mode in [
                    ConntrackMode::Tracked,
                    ConntrackMode::Notrack,
                    ConntrackMode::Hybrid,
                ] {
                    for message in [NETLINK_ERROR, PERMISSION_ERROR] {
                        let mut config = ProxyConfig::default();
                        if explicit {
                            config.server.conntrack_control.inline_conntrack_control = false;
                            config
                                .server
                                .conntrack_control
                                .inline_conntrack_control_explicit = true;
                        }
                        config.server.conntrack_control.backend = backend;
                        config.server.conntrack_control.mode = mode;
                        let runner = StartupRunner::new(has_cap, Some(message));
                        let scope = ProcessControlPlane::new();
                        let authority = start_with_runner(&config, runner.clone(), &scope);
                        assert!(
                            authority.is_none(),
                            "{explicit} {has_cap} {backend:?} {mode:?}"
                        );
                        assert_eq!(runner.cap_probes.load(Ordering::Relaxed), 0);
                        tokio::time::advance(Duration::from_secs(90)).await;
                        assert!(scope.shutdown(Duration::from_secs(1)).await);
                        assert!(runner.calls().is_empty());
                    }
                }
            }
        }
    }
}

#[tokio::test(start_paused = true)]
async fn enabled_startup_without_capability_creates_no_firewall_work() {
    let mut config = ProxyConfig::default();
    config.server.conntrack_control.inline_conntrack_control = true;
    for mode in [ConntrackMode::Tracked, ConntrackMode::Notrack] {
        config.server.conntrack_control.mode = mode;
        let runner = StartupRunner::new(false, Some(PERMISSION_ERROR));
        let scope = ProcessControlPlane::new();
        assert!(start_with_runner(&config, runner.clone(), &scope).is_none());
        assert_eq!(runner.cap_probes.load(Ordering::Relaxed), 1);
        tokio::time::advance(Duration::from_secs(90)).await;
        assert!(scope.shutdown(Duration::from_secs(1)).await);
        assert!(runner.calls().is_empty());
    }
}

#[tokio::test(start_paused = true)]
async fn admitted_startup_preserves_recovery_idle_and_shutdown_cleanup() {
    for mode in [ConntrackMode::Tracked, ConntrackMode::Notrack] {
        let mut config = ProxyConfig::default();
        config.server.conntrack_control.inline_conntrack_control = true;
        config.server.conntrack_control.mode = mode;
        config.server.conntrack_control.backend = ConntrackBackend::Nftables;
        let runner = StartupRunner::new(true, None);
        let scope = ProcessControlPlane::new();
        let authority = start_with_runner(&config, runner.clone(), &scope).unwrap();
        let stats = Arc::new(Stats::new());
        assert!(
            authority
                .publish_initial(1, Arc::new(config), stats.clone())
                .await
        );
        assert!(stats.get_conntrack_rule_apply_ok());
        for binary in ["nft", "iptables", "ip6tables"] {
            assert!(runner.calls().iter().any(|call| call.binary == binary));
        }
        let calls = runner.calls().len();
        tokio::time::advance(Duration::from_secs(90)).await;
        tokio::task::yield_now().await;
        assert_eq!(runner.calls().len(), calls);
        assert!(authority.shutdown_and_clear().await);
        assert!(!stats.get_conntrack_rule_apply_ok());
        assert!(runner.calls().len() > calls);
        assert!(scope.shutdown(Duration::from_secs(1)).await);
    }
}

#[tokio::test(start_paused = true)]
async fn admitted_process_cancellation_preserves_cleanup() {
    let mut config = ProxyConfig::default();
    config.server.conntrack_control.inline_conntrack_control = true;
    let runner = StartupRunner::new(true, None);
    let scope = ProcessControlPlane::new();
    let authority = start_with_runner(&config, runner.clone(), &scope).unwrap();
    assert!(scope.shutdown(Duration::from_secs(1)).await);
    assert!(authority.shutdown_and_clear().await);
    assert!(!runner.calls().is_empty());
}

#[test]
fn netlink_and_permission_errors_are_not_classified_as_absence() {
    for spec in [
        CommandSpec::new("nft", ["delete", "table", "inet", "telemt_conntrack"]),
        CommandSpec::new("nft", ["-f", "-"]),
        CommandSpec::new(
            "iptables",
            ["-t", "raw", "-D", "PREROUTING", "-j", "TELEMT_NOTRACK"],
        ),
        CommandSpec::new("iptables", ["-t", "raw", "-F", "TELEMT_NT_A"]),
        CommandSpec::new("ip6tables", ["-t", "raw", "-X", "TELEMT_NT_B"]),
        CommandSpec::new("iptables-restore", ["--noflush"]),
        CommandSpec::new("ip6tables-restore", ["--noflush"]),
    ] {
        for message in [
            NETLINK_ERROR,
            PERMISSION_ERROR,
            "iptables: Failed to initialize nft: Address family not supported by protocol",
        ] {
            assert_eq!(
                classify_command_error(spec.binary, &spec.args, message),
                CommandErrorKind::Failed,
                "{spec:?} {message}",
            );
        }
    }
}

#[tokio::test(start_paused = true)]
async fn admitted_genuine_failures_remain_unknown_and_retry() {
    for message in [NETLINK_ERROR, PERMISSION_ERROR] {
        let mut config = ProxyConfig::default();
        config.server.conntrack_control.inline_conntrack_control = true;
        config.server.conntrack_control.mode = ConntrackMode::Notrack;
        config.server.conntrack_control.backend = ConntrackBackend::Nftables;
        let runner = StartupRunner::new(true, Some(message));
        let mut applied = AppliedState::Unknown;
        let requested = DesiredState {
            generation: 1,
            policy: DesiredPolicy::from_config(&config),
            stats: Arc::new(Stats::new()),
        };
        let error = reconcile_once(&runner, &runner, &mut applied, &requested)
            .await
            .unwrap_err();
        assert!(error.message.contains(message));
        assert_eq!(applied, AppliedState::Unknown);
        assert!(runner.calls().iter().all(|call| call.stdin.is_none()));

        let scope = ProcessControlPlane::new();
        let authority = start_with_runner(&config, runner.clone(), &scope).unwrap();
        let stats = Arc::new(Stats::new());
        assert!(
            !authority
                .publish_initial(1, Arc::new(config), stats.clone())
                .await
        );
        assert!(!stats.get_conntrack_rule_apply_ok());
        assert_eq!(stats.get_conntrack_rule_reconcile_error_total(), 1);
        let mut status = authority.status_rx.clone();
        assert_eq!(
            status.borrow_and_update().as_ref().unwrap().outcome,
            ReconcileOutcome::Failed,
        );
        let calls = runner.calls().len();
        tokio::time::advance(Duration::from_millis(999)).await;
        tokio::task::yield_now().await;
        assert_eq!(runner.calls().len(), calls);
        tokio::time::advance(Duration::from_millis(1)).await;
        status.changed().await.unwrap();
        assert_eq!(
            status.borrow().as_ref().unwrap().outcome,
            ReconcileOutcome::Failed,
        );
        assert_eq!(stats.get_conntrack_rule_reconcile_error_total(), 2);
        assert!(!authority.shutdown_and_clear().await);
        assert!(authority.completed_flag.load(Ordering::Acquire));
        assert!(scope.shutdown(Duration::from_secs(1)).await);
        assert!(runner.calls().iter().all(|call| call.stdin.is_none()));
    }
}
