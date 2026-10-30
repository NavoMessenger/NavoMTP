use super::command::{CommandError, CommandErrorKind, CommandSpec, FirewallCommandRunner};
use super::model::{NotrackTarget, ShadowSlot};

const LEGACY_TABLE: &str = "telemt_conntrack";
const TABLE_A: &str = "telemt_conntrack_a";
const TABLE_B: &str = "telemt_conntrack_b";

pub(super) fn available<R: FirewallCommandRunner>(runner: &R) -> bool {
    runner.available("nft")
}

fn table(slot: ShadowSlot) -> &'static str {
    match slot {
        ShadowSlot::A => TABLE_A,
        ShadowSlot::B => TABLE_B,
    }
}

pub(super) async fn stage<R: FirewallCommandRunner>(
    runner: &R,
    slot: ShadowSlot,
    v4: &[NotrackTarget],
    v6: &[NotrackTarget],
) -> Result<(), CommandError> {
    require_nft(runner)?;
    delete_table_if_present(runner, table(slot)).await?;
    runner
        .run(CommandSpec::with_stdin(
            "nft",
            ["-f", "-"],
            render_stage_script(slot, v4, v6),
        ))
        .await
}

pub(super) async fn activate<R: FirewallCommandRunner>(
    runner: &R,
    slot: ShadowSlot,
) -> Result<(), CommandError> {
    require_nft(runner)?;
    runner
        .run(CommandSpec::with_stdin(
            "nft",
            ["-f", "-"],
            render_activate_script(slot),
        ))
        .await
}

pub(super) async fn deactivate<R: FirewallCommandRunner>(
    runner: &R,
    slot: ShadowSlot,
) -> Result<(), CommandError> {
    delete_table_if_present(runner, table(slot)).await
}

pub(super) async fn cleanup_all<R: FirewallCommandRunner>(runner: &R) -> Result<(), CommandError> {
    if !runner.available("nft") {
        return Ok(());
    }
    let mut errors = Vec::new();
    for table_name in [LEGACY_TABLE, TABLE_A, TABLE_B] {
        if let Err(error) = delete_table_if_present(runner, table_name).await {
            errors.push(error.message);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(CommandError::failed(errors.join("; ")))
    }
}

async fn delete_table_if_present<R: FirewallCommandRunner>(
    runner: &R,
    table_name: &'static str,
) -> Result<(), CommandError> {
    match runner
        .run(CommandSpec::new(
            "nft",
            ["delete", "table", "inet", table_name],
        ))
        .await
    {
        Ok(()) => Ok(()),
        Err(error)
            if matches!(
                error.kind,
                CommandErrorKind::NotFound | CommandErrorKind::Missing
            ) =>
        {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn require_nft<R: FirewallCommandRunner>(runner: &R) -> Result<(), CommandError> {
    if runner.available("nft") {
        Ok(())
    } else {
        Err(CommandError {
            kind: CommandErrorKind::Missing,
            message: "nft is required for conntrack firewall reconciliation".to_string(),
        })
    }
}

pub(super) fn render_stage_script(
    slot: ShadowSlot,
    v4: &[NotrackTarget],
    v6: &[NotrackTarget],
) -> String {
    let table = table(slot);
    let mut script = format!("add table inet {table}\nadd chain inet {table} rules\n");
    for target in v4 {
        script.push_str("add rule inet ");
        script.push_str(table);
        script.push_str(" rules tcp dport ");
        script.push_str(&target.port.to_string());
        if let Some(ip) = target.ip {
            script.push_str(" ip daddr ");
            script.push_str(&ip.to_string());
        }
        script.push_str(" notrack\n");
    }
    for target in v6 {
        script.push_str("add rule inet ");
        script.push_str(table);
        script.push_str(" rules tcp dport ");
        script.push_str(&target.port.to_string());
        if let Some(ip) = target.ip {
            script.push_str(" ip6 daddr ");
            script.push_str(&ip.to_string());
        }
        script.push_str(" notrack\n");
    }
    script
}

pub(super) fn render_activate_script(slot: ShadowSlot) -> String {
    let table = table(slot);
    format!(
        "add chain inet {table} preraw {{ type filter hook prerouting priority raw; policy accept; }}\nadd rule inet {table} preraw jump rules\n"
    )
}
