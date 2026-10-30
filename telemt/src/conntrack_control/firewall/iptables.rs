use super::command::{CommandError, CommandErrorKind, CommandSpec, FirewallCommandRunner};
use super::model::{NotrackTarget, ShadowSlot};

const DISPATCH_CHAIN: &str = "TELEMT_NOTRACK";
const SHADOW_CHAIN_A: &str = "TELEMT_NT_A";
const SHADOW_CHAIN_B: &str = "TELEMT_NT_B";
const MAX_OWNED_JUMPS: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum IpFamily {
    V4,
    V6,
}

impl IpFamily {
    fn command_binary(self) -> &'static str {
        match self {
            Self::V4 => "iptables",
            Self::V6 => "ip6tables",
        }
    }

    fn restore_binary(self) -> &'static str {
        match self {
            Self::V4 => "iptables-restore",
            Self::V6 => "ip6tables-restore",
        }
    }
}

pub(super) fn family_available<R: FirewallCommandRunner>(runner: &R, family: IpFamily) -> bool {
    runner.available(family.command_binary()) && runner.available(family.restore_binary())
}

fn shadow_chain(slot: ShadowSlot) -> &'static str {
    match slot {
        ShadowSlot::A => SHADOW_CHAIN_A,
        ShadowSlot::B => SHADOW_CHAIN_B,
    }
}

pub(super) async fn stage_family<R: FirewallCommandRunner>(
    runner: &R,
    family: IpFamily,
    slot: ShadowSlot,
    targets: &[NotrackTarget],
) -> Result<(), CommandError> {
    if targets.is_empty() {
        return Ok(());
    }
    require_family(runner, family)?;
    ensure_owned_chains(runner, family).await?;
    let script = render_stage_script(slot, targets);
    runner
        .run(CommandSpec::with_stdin(
            family.restore_binary(),
            ["--noflush"],
            script,
        ))
        .await
}

pub(super) async fn activate_family<R: FirewallCommandRunner>(
    runner: &R,
    family: IpFamily,
    slot: Option<ShadowSlot>,
) -> Result<(), CommandError> {
    require_family(runner, family)?;
    if slot.is_some() {
        ensure_prerouting_jump(runner, family).await?;
    }
    runner
        .run(CommandSpec::with_stdin(
            family.restore_binary(),
            ["--noflush"],
            render_dispatch_script(slot),
        ))
        .await
}

pub(super) async fn cleanup_all<R: FirewallCommandRunner>(runner: &R) -> Result<(), CommandError> {
    let mut errors = Vec::new();
    for family in [IpFamily::V4, IpFamily::V6] {
        if !runner.available(family.command_binary()) {
            continue;
        }
        if let Err(error) = cleanup_family(runner, family).await {
            errors.push(error.message);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(CommandError::failed(errors.join("; ")))
    }
}

async fn cleanup_family<R: FirewallCommandRunner>(
    runner: &R,
    family: IpFamily,
) -> Result<(), CommandError> {
    let binary = family.command_binary();
    let mut errors = Vec::new();
    for _ in 0..MAX_OWNED_JUMPS {
        let result = runner
            .run(CommandSpec::new(
                binary,
                ["-t", "raw", "-D", "PREROUTING", "-j", DISPATCH_CHAIN],
            ))
            .await;
        match result {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.kind,
                    CommandErrorKind::NotFound | CommandErrorKind::Missing
                ) =>
            {
                break;
            }
            Err(error) => {
                errors.push(error.message);
                break;
            }
        }
    }
    for chain in [DISPATCH_CHAIN, SHADOW_CHAIN_A, SHADOW_CHAIN_B] {
        for operation in ["-F", "-X"] {
            let result = runner
                .run(CommandSpec::new(binary, ["-t", "raw", operation, chain]))
                .await;
            if let Err(error) = result
                && !matches!(
                    error.kind,
                    CommandErrorKind::NotFound | CommandErrorKind::Missing
                )
            {
                errors.push(error.message);
            }
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(CommandError::failed(errors.join("; ")))
    }
}

async fn ensure_prerouting_jump<R: FirewallCommandRunner>(
    runner: &R,
    family: IpFamily,
) -> Result<(), CommandError> {
    let binary = family.command_binary();
    match runner
        .run(CommandSpec::new(
            binary,
            ["-t", "raw", "-C", "PREROUTING", "-j", DISPATCH_CHAIN],
        ))
        .await
    {
        Ok(()) => Ok(()),
        Err(error) if error.kind == CommandErrorKind::NotFound => {
            runner
                .run(CommandSpec::new(
                    binary,
                    ["-t", "raw", "-I", "PREROUTING", "1", "-j", DISPATCH_CHAIN],
                ))
                .await
        }
        Err(error) => Err(error),
    }
}

async fn ensure_owned_chains<R: FirewallCommandRunner>(
    runner: &R,
    family: IpFamily,
) -> Result<(), CommandError> {
    let binary = family.command_binary();
    for chain in [DISPATCH_CHAIN, SHADOW_CHAIN_A, SHADOW_CHAIN_B] {
        match runner
            .run(CommandSpec::new(binary, ["-t", "raw", "-N", chain]))
            .await
        {
            Ok(()) => {}
            Err(error) if is_chain_exists_error(&error.message) => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

pub(super) fn is_chain_exists_error(message: &str) -> bool {
    message.contains("Chain already exists")
}

fn require_family<R: FirewallCommandRunner>(
    runner: &R,
    family: IpFamily,
) -> Result<(), CommandError> {
    for binary in [family.command_binary(), family.restore_binary()] {
        if !runner.available(binary) {
            return Err(CommandError {
                kind: CommandErrorKind::Missing,
                message: format!("{binary} is required for conntrack firewall reconciliation"),
            });
        }
    }
    Ok(())
}

pub(super) fn render_stage_script(slot: ShadowSlot, targets: &[NotrackTarget]) -> String {
    let chain = shadow_chain(slot);
    let mut script = format!("*raw\n-F {chain}\n");
    for target in targets {
        script.push_str("-A ");
        script.push_str(chain);
        script.push_str(" -p tcp --dport ");
        script.push_str(&target.port.to_string());
        if let Some(ip) = target.ip {
            script.push_str(" -d ");
            script.push_str(&ip.to_string());
        }
        script.push_str(" -j CT --notrack\n");
    }
    script.push_str("COMMIT\n");
    script
}

pub(super) fn render_dispatch_script(slot: Option<ShadowSlot>) -> String {
    let mut script = format!("*raw\n-F {DISPATCH_CHAIN}\n");
    if let Some(slot) = slot {
        script.push_str("-A ");
        script.push_str(DISPATCH_CHAIN);
        script.push_str(" -j ");
        script.push_str(shadow_chain(slot));
        script.push('\n');
    }
    script.push_str("COMMIT\n");
    script
}
