use super::super::command::classify_command_error;
use super::super::transaction::recover_to_empty;
use super::*;

const OWNED_CHAINS: [&str; 3] = ["TELEMT_NOTRACK", "TELEMT_NT_A", "TELEMT_NT_B"];
type ChainKey = (&'static str, String, String);
type ChainRules = BTreeMap<ChainKey, BTreeSet<String>>;

fn missing_chain(binary: &str, chain: &str) -> String {
    format!(
        "{binary} v1.8.10 (nf_tables): Chain '{chain}' does not exist\n\
         Try `{binary} -h' or '{binary} --help' for more information."
    )
}

fn classified_error(spec: &CommandSpec, message: &str) -> CommandError {
    CommandError {
        kind: classify_command_error(spec.binary, &spec.args, message),
        message: message.to_string(),
    }
}

#[derive(Default)]
struct FixtureState {
    calls: Vec<CommandSpec>,
    chains: ChainRules,
    nft_tables: BTreeSet<String>,
    failure: Option<&'static str>,
}

#[derive(Clone)]
struct FixtureRunner {
    state: Arc<Mutex<FixtureState>>,
}

impl FixtureRunner {
    fn new(failure: Option<&'static str>) -> Self {
        let mut state = FixtureState {
            failure,
            ..FixtureState::default()
        };
        for binary in ["iptables", "ip6tables"] {
            for (table, chain, rules) in [
                ("raw", "PREROUTING", vec!["-j FOREIGN_RAW"]),
                ("raw", "FOREIGN_RAW", vec!["-j ACCEPT"]),
                ("filter", "INPUT", vec!["-j MTPR_SYNFIX", "-j TMT_SYN_TEST"]),
                ("filter", "MTPR_SYNFIX", vec!["-p tcp --syn -j DROP"]),
                ("filter", "TMT_SYN_TEST", vec!["-p tcp --syn -j DROP"]),
            ] {
                state.chains.insert(
                    (binary, table.to_string(), chain.to_string()),
                    rules.into_iter().map(str::to_string).collect(),
                );
            }
        }
        state.nft_tables.extend([
            "mtpr_synfix".to_string(),
            "telemt_synlimit_test".to_string(),
            "foreign_table".to_string(),
        ]);
        Self {
            state: Arc::new(Mutex::new(state)),
        }
    }

    fn calls(&self) -> Vec<CommandSpec> {
        self.state.lock().unwrap().calls.clone()
    }

    fn foreign_snapshot(&self) -> (ChainRules, BTreeSet<String>) {
        let state = self.state.lock().unwrap();
        let mut chains = state.chains.clone();
        chains.retain(|(_, table, chain), _| {
            table != "raw" || !OWNED_CHAINS.contains(&chain.as_str())
        });
        for ((_, table, chain), rules) in &mut chains {
            if table == "raw" && chain == "PREROUTING" {
                rules.remove("-j TELEMT_NOTRACK");
            }
        }
        (chains, state.nft_tables.clone())
    }

    fn assert_owned_policy(&self, enabled: bool) {
        let state = self.state.lock().unwrap();
        for (binary, ip) in [("iptables", "192.0.2.10"), ("ip6tables", "2001:db8::10")] {
            for chain in OWNED_CHAINS {
                let key = (binary, "raw".to_string(), chain.to_string());
                if !enabled {
                    assert!(!state.chains.contains_key(&key));
                    continue;
                }
                let expected = match chain {
                    "TELEMT_NOTRACK" => BTreeSet::from(["-j TELEMT_NT_A".to_string()]),
                    "TELEMT_NT_A" => {
                        BTreeSet::from([format!("-p tcp --dport 443 -d {ip} -j CT --notrack")])
                    }
                    "TELEMT_NT_B" => BTreeSet::new(),
                    _ => unreachable!(),
                };
                assert_eq!(state.chains.get(&key), Some(&expected));
            }
            let prerouting = (binary, "raw".to_string(), "PREROUTING".to_string());
            assert_eq!(
                state.chains[&prerouting].contains("-j TELEMT_NOTRACK"),
                enabled
            );
        }
    }
}

impl FirewallCommandRunner for FixtureRunner {
    fn available(&self, _binary: &str) -> bool {
        true
    }

    fn has_cap_net_admin(&self) -> bool {
        true
    }

    async fn run(&self, spec: CommandSpec) -> Result<(), CommandError> {
        let mut state = self.state.lock().unwrap();
        state.calls.push(spec.clone());
        if spec.binary == "nft" {
            assert_eq!(&spec.args[..3], ["delete", "table", "inet"]);
            return if state.nft_tables.remove(&spec.args[3]) {
                Ok(())
            } else {
                Err(classified_error(
                    &spec,
                    "Error: Could not process rule: No such file or directory",
                ))
            };
        }
        if let Some(script) = &spec.stdin {
            let binary = match spec.binary {
                "iptables-restore" => "iptables",
                "ip6tables-restore" => "ip6tables",
                _ => panic!("unexpected restore helper"),
            };
            assert_eq!(spec.args, ["--noflush"]);
            for line in script.lines().filter(|line| line.starts_with('-')) {
                let fields = line.split_whitespace().collect::<Vec<_>>();
                let key = (binary, "raw".to_string(), fields[1].to_string());
                let rules = state.chains.get_mut(&key).expect("restore target exists");
                match fields[0] {
                    "-F" => rules.clear(),
                    "-A" => {
                        rules.insert(fields[2..].join(" "));
                    }
                    _ => panic!("unexpected restore operation"),
                }
            }
            return Ok(());
        }
        assert!(matches!(spec.binary, "iptables" | "ip6tables"));
        assert_eq!(spec.args[0], "-t");
        let operation = spec.args[2].as_str();
        let key = (spec.binary, spec.args[1].clone(), spec.args[3].clone());
        match operation {
            "-N" => {
                if state.chains.contains_key(&key) {
                    Err(classified_error(&spec, "iptables: Chain already exists."))
                } else {
                    state.chains.insert(key, BTreeSet::new());
                    Ok(())
                }
            }
            "-C" | "-D" => {
                if operation == "-D"
                    && let Some(message) = state.failure.take()
                {
                    return Err(classified_error(&spec, message));
                }
                let target = (spec.binary, spec.args[1].clone(), spec.args[5].clone());
                if !state.chains.contains_key(&target) {
                    return Err(classified_error(
                        &spec,
                        &missing_chain(spec.binary, &spec.args[5]),
                    ));
                }
                let rules = state.chains.get_mut(&key).expect("builtin chain exists");
                let rule = spec.args[4..].join(" ");
                if !rules.contains(&rule) {
                    return Err(classified_error(
                        &spec,
                        "Bad rule (does a matching rule exist in that chain?).",
                    ));
                }
                if operation == "-D" {
                    rules.remove(&rule);
                }
                Ok(())
            }
            "-I" => {
                let target = (spec.binary, spec.args[1].clone(), spec.args[6].clone());
                if !state.chains.contains_key(&target) {
                    return Err(classified_error(
                        &spec,
                        &missing_chain(spec.binary, &spec.args[6]),
                    ));
                }
                state
                    .chains
                    .get_mut(&key)
                    .unwrap()
                    .insert(spec.args[5..].join(" "));
                Ok(())
            }
            "-F" | "-X" => {
                let Some(rules) = state.chains.get_mut(&key) else {
                    return Err(classified_error(
                        &spec,
                        "iptables: No chain/target/match by that name.",
                    ));
                };
                if operation == "-F" {
                    rules.clear();
                } else {
                    assert!(rules.is_empty());
                    state.chains.remove(&key);
                }
                Ok(())
            }
            _ => panic!("unexpected iptables operation"),
        }
    }
}

#[test]
fn quoted_missing_chains_are_scoped_to_owned_commands() {
    for binary in ["iptables", "ip6tables"] {
        for operation in ["-C", "-D"] {
            let spec = CommandSpec::new(
                binary,
                ["-t", "raw", operation, "PREROUTING", "-j", "TELEMT_NOTRACK"],
            );
            let message = missing_chain(binary, "TELEMT_NOTRACK");
            let error = classified_error(&spec, &message);
            assert_eq!(error.kind, CommandErrorKind::NotFound, "{spec:?}");
            assert_eq!(error.message, message);
        }
        for operation in ["-F", "-X"] {
            for chain in OWNED_CHAINS {
                let spec = CommandSpec::new(binary, ["-t", "raw", operation, chain]);
                assert_eq!(
                    classified_error(&spec, &missing_chain(binary, chain)).kind,
                    CommandErrorKind::NotFound,
                );
            }
        }
        let spec = CommandSpec::new(binary, ["-t", "raw", "-F", "TELEMT_NOTRACK"]);
        for message in [
            "Chain 'TELEMT_NOTRACK' does not exist".to_string(),
            format!("{binary} v1.8.11 (nf_tables): Chain 'TELEMT_NOTRACK' does not exist"),
        ] {
            assert_eq!(
                classified_error(&spec, &message).kind,
                CommandErrorKind::NotFound
            );
        }
    }
}

#[test]
fn unrelated_commands_and_diagnostics_remain_failures() {
    let message = missing_chain("iptables", "TELEMT_NOTRACK");
    for spec in [
        CommandSpec::new("iptables", ["-t", "raw", "-N", "TELEMT_NOTRACK"]),
        CommandSpec::new(
            "iptables",
            ["-t", "raw", "-A", "PREROUTING", "-j", "TELEMT_NOTRACK"],
        ),
        CommandSpec::new(
            "iptables",
            ["-t", "raw", "-I", "PREROUTING", "1", "-j", "TELEMT_NOTRACK"],
        ),
        CommandSpec::new("iptables", ["-t", "filter", "-F", "TELEMT_NOTRACK"]),
        CommandSpec::new("iptables", ["-t", "raw", "-F", "TELEMT_NT_A"]),
        CommandSpec::new(
            "iptables",
            ["-t", "raw", "-D", "PREROUTING", "-j", "TELEMT_NT_A"],
        ),
        CommandSpec::new(
            "iptables",
            ["-t", "raw", "-D", "INPUT", "-j", "TELEMT_NOTRACK"],
        ),
        CommandSpec::new(
            "iptables",
            ["-t", "raw", "-D", "PREROUTING", "-g", "TELEMT_NOTRACK"],
        ),
        CommandSpec::new("iptables", ["-F", "TELEMT_NOTRACK"]),
        CommandSpec::new(
            "iptables",
            ["-t", "raw", "-F", "TELEMT_NOTRACK", "--invalid"],
        ),
        CommandSpec::new("iptables-restore", ["--noflush"]),
        CommandSpec::new("ip6tables-restore", ["--noflush"]),
        CommandSpec::new("nft", ["delete", "table", "inet", "telemt_conntrack"]),
        CommandSpec::new("conntrack", ["-D"]),
    ] {
        assert_eq!(
            classified_error(&spec, &message).kind,
            CommandErrorKind::Failed,
            "{spec:?}",
        );
    }
    for chain in [
        "TELEMT_NT_C",
        "TELEMT_NOTRACK_EXTRA",
        "MTPR_SYNFIX",
        "PREROUTING",
    ] {
        let spec = CommandSpec::new("iptables", ["-t", "raw", "-F", chain]);
        assert_eq!(
            classified_error(&spec, &missing_chain("iptables", chain)).kind,
            CommandErrorKind::Failed,
        );
    }
    let spec = CommandSpec::new(
        "iptables",
        ["-t", "raw", "-D", "PREROUTING", "-j", "TELEMT_NOTRACK"],
    );
    for message in [
        "Permission denied",
        "can't initialize iptables table `raw': Table does not exist",
        "Another app is currently holding the xtables lock",
        "Chain is not empty",
        "Directory not empty",
        "Can't delete chain with references left",
        "unknown option --invalid",
        "command timed out",
    ] {
        assert_eq!(
            classified_error(&spec, message).kind,
            CommandErrorKind::Failed
        );
    }
    for message in [
        format!("{message}\nPermission denied"),
        format!("Permission denied\n{message}"),
        "Chain 'TELEMT_NOTRACK' does not exist\nPermission denied".to_string(),
        "Chain 'TELEMT_NOTRACK' does not exist\n\
         Try `ip6tables -h' or 'ip6tables --help' for more information."
            .to_string(),
        "iptables v1.8.10 (legacy): Chain 'TELEMT_NOTRACK' does not exist".to_string(),
        "iptables v (nf_tables): Chain 'TELEMT_NOTRACK' does not exist".to_string(),
        missing_chain("ip6tables", "TELEMT_NOTRACK"),
        missing_chain("iptables", "TELEMT_NT_A"),
    ] {
        assert_eq!(
            classified_error(&spec, &message).kind,
            CommandErrorKind::Failed
        );
    }
    for binary in ["nft", "conntrack", "iptables-restore", "ip6tables-restore"] {
        let spec = CommandSpec::new(binary, ["-t", "raw", "-F", "TELEMT_NOTRACK"]);
        assert_eq!(
            classified_error(&spec, "Chain 'TELEMT_NOTRACK' does not exist").kind,
            CommandErrorKind::Failed,
        );
    }
}

#[tokio::test]
async fn unknown_recovery_converges_without_touching_foreign_rules() {
    for policy in [DesiredPolicy::Empty, dual_stack_policy(443)] {
        let runner = FixtureRunner::new(None);
        let foreign = runner.foreign_snapshot();
        let mut applied = AppliedState::Unknown;
        let requested = desired(1, policy);
        reconcile_once(&runner, &runner, &mut applied, &requested)
            .await
            .unwrap();
        assert!(matches!(
            &applied,
            AppliedState::Known(plan) if plan.matches_policy(&requested.policy)
        ));
        runner.assert_owned_policy(matches!(requested.policy, DesiredPolicy::Rules { .. }));
        assert_eq!(runner.foreign_snapshot(), foreign);
        for binary in ["iptables", "ip6tables"] {
            let calls = runner.calls();
            assert_eq!(
                calls
                    .iter()
                    .filter(|call| call.binary == binary && call.args[2] == "-D")
                    .count(),
                1,
            );
            assert_eq!(
                calls
                    .iter()
                    .filter(|call| {
                        call.binary == binary && matches!(call.args[2].as_str(), "-F" | "-X")
                    })
                    .count(),
                6,
            );
        }
        let calls = runner.calls().len();
        reconcile_once(
            &runner,
            &runner,
            &mut applied,
            &desired(2, requested.policy.clone()),
        )
        .await
        .unwrap();
        assert_eq!(runner.calls().len(), calls);
        recover_to_empty(&runner).await.unwrap();
        recover_to_empty(&runner).await.unwrap();
        runner.assert_owned_policy(false);
        assert_eq!(runner.foreign_snapshot(), foreign);
    }
}

#[tokio::test]
async fn genuine_recovery_failures_leave_state_unknown_and_do_not_install() {
    for message in [
        "Permission denied",
        "can't initialize iptables table `raw': Table does not exist",
        "Another app is currently holding the xtables lock",
        "unknown firewall failure",
    ] {
        let runner = FixtureRunner::new(Some(message));
        let mut applied = AppliedState::Unknown;
        let error = reconcile_once(
            &runner,
            &runner,
            &mut applied,
            &desired(1, dual_stack_policy(443)),
        )
        .await
        .unwrap_err();
        assert!(error.message.contains(message));
        assert_eq!(applied, AppliedState::Unknown);
        assert!(runner.calls().iter().all(|call| call.stdin.is_none()));
    }
}

#[tokio::test(start_paused = true)]
async fn actor_converges_then_idles_and_preserves_foreign_rules_on_shutdown() {
    for failure in [None, Some("Permission denied")] {
        let runner = FixtureRunner::new(failure);
        let observed = runner.clone();
        let foreign = observed.foreign_snapshot();
        let (desired_tx, desired_rx) = watch::channel(None);
        let (status_tx, mut status_rx) = watch::channel(None);
        let terminal = CancellationToken::new();
        let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let completed = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cleanup = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reconciler = FirewallReconciler::new(
            runner,
            desired_rx,
            status_tx,
            terminal.clone(),
            closed.clone(),
            completed.clone(),
            cleanup.clone(),
            Arc::new(Notify::new()),
        );
        let task = tokio::spawn(reconciler.run(CancellationToken::new()));
        let requested = desired(1, dual_stack_policy(443));
        let stats = requested.stats.clone();
        desired_tx.send_replace(Some(requested));
        status_rx.changed().await.unwrap();
        if failure.is_some() {
            assert_eq!(
                status_rx.borrow().as_ref().unwrap().outcome,
                ReconcileOutcome::Failed,
            );
            assert!(!stats.get_conntrack_rule_apply_ok());
            assert_eq!(stats.get_conntrack_rule_reconcile_error_total(), 1);
            let calls = observed.calls().len();
            tokio::time::advance(Duration::from_millis(999)).await;
            tokio::task::yield_now().await;
            assert_eq!(observed.calls().len(), calls);
            tokio::time::advance(Duration::from_millis(1)).await;
            status_rx.changed().await.unwrap();
        }
        assert_eq!(
            status_rx.borrow().as_ref().unwrap().outcome,
            ReconcileOutcome::Applied,
        );
        assert_eq!(status_rx.borrow().as_ref().unwrap().generation, 1);
        assert!(stats.get_conntrack_rule_apply_ok());
        assert_eq!(stats.get_conntrack_rule_reconcile_success_total(), 1);
        assert_eq!(
            stats.get_conntrack_rule_reconcile_error_total(),
            u64::from(failure.is_some()),
        );
        let calls = observed.calls().len();
        tokio::time::advance(Duration::from_secs(90)).await;
        tokio::task::yield_now().await;
        assert_eq!(observed.calls().len(), calls);
        assert!(!status_rx.has_changed().unwrap());
        observed.assert_owned_policy(true);
        assert_eq!(observed.foreign_snapshot(), foreign);
        terminal.cancel();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        assert!(closed.load(Ordering::Acquire));
        assert!(completed.load(Ordering::Acquire));
        assert!(cleanup.load(Ordering::Acquire));
        assert!(!stats.get_conntrack_rule_apply_ok());
        observed.assert_owned_policy(false);
        assert_eq!(observed.foreign_snapshot(), foreign);
    }
}
