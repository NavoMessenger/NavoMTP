use std::sync::Mutex;

use tracing::warn;

use crate::config::ProxyConfig;

mod command;
mod iptables;
mod model;
mod nftables;
mod pf;

use self::command::has_firewall_privileges;
use self::model::{SynLimitNamespace, synlimit_namespace, synlimit_targets};

static ACTIVE_SYNLIMIT_NAMESPACE: Mutex<Option<SynLimitNamespace>> = Mutex::new(None);

/// Installs the complete startup SYN-limiter ruleset before accept loops start.
pub(crate) async fn reconcile_synlimit_rules(cfg: &ProxyConfig) -> Result<(), String> {
    let targets = synlimit_targets(cfg);
    if targets.is_empty() {
        return Ok(());
    }
    if !has_firewall_privileges() {
        return Err(
            "SYN limiter requires root or CAP_NET_ADMIN for startup and shutdown".to_string(),
        );
    }
    let namespace = synlimit_namespace(&targets)
        .ok_or_else(|| "SYN limiter namespace could not be derived".to_string())?;

    if clear_synlimit_rules_for_namespace(&namespace).await? {
        warn!("Removed stale SYN limiter rules left by a previous run before startup");
    }

    let apply_result = async {
        if targets.has_iptables_targets() {
            iptables::apply_synlimit_rules(&targets, &namespace).await?;
        }
        if targets.has_nft_targets() {
            nftables::apply_synlimit_rules(&targets, &namespace).await?;
        }
        if targets.has_pf_targets() {
            pf::apply_synlimit_rules(&targets, &namespace).await?;
        }
        Ok::<(), String>(())
    }
    .await;
    if let Err(apply_error) = apply_result {
        return match clear_synlimit_rules_for_namespace(&namespace).await {
            Ok(_) => Err(apply_error),
            Err(cleanup_error) => Err(format!(
                "{apply_error}; candidate cleanup failed: {cleanup_error}"
            )),
        };
    }

    if let Err(error) = set_active_synlimit_namespace(namespace.clone()) {
        return match clear_synlimit_rules_for_namespace(&namespace).await {
            Ok(_) => Err(error),
            Err(cleanup_error) => Err(format!(
                "{error}; candidate cleanup failed: {cleanup_error}"
            )),
        };
    }
    Ok(())
}

/// Removes the ruleset installed by the current process, if any.
pub(crate) async fn clear_synlimit_rules_all_backends() -> Result<bool, String> {
    let Some(namespace) = active_synlimit_namespace()? else {
        return Ok(false);
    };
    let removed = clear_synlimit_rules_for_namespace(&namespace).await?;
    clear_active_synlimit_namespace(&namespace)?;
    Ok(removed)
}

async fn clear_synlimit_rules_for_namespace(namespace: &SynLimitNamespace) -> Result<bool, String> {
    if !has_firewall_privileges() {
        return Err("SYN limiter cleanup requires root or CAP_NET_ADMIN privileges".to_string());
    }

    let mut errors = Vec::new();
    let mut removed = false;
    match nftables::clear_rules_all_families(namespace).await {
        Ok(value) => removed |= value,
        Err(error) => errors.push(error),
    }
    match iptables::clear_rules_for_binary("iptables", namespace).await {
        Ok(value) => removed |= value,
        Err(error) => errors.push(error),
    }
    match iptables::clear_rules_for_binary("ip6tables", namespace).await {
        Ok(value) => removed |= value,
        Err(error) => errors.push(error),
    }
    match pf::clear_rules(namespace).await {
        Ok(value) => removed |= value,
        Err(error) => errors.push(error),
    }

    if errors.is_empty() {
        Ok(removed)
    } else {
        Err(errors.join("; "))
    }
}

fn set_active_synlimit_namespace(next: SynLimitNamespace) -> Result<(), String> {
    match ACTIVE_SYNLIMIT_NAMESPACE.lock() {
        Ok(mut active) => {
            if active.is_some() {
                return Err("SYN limiter namespace is already active".to_string());
            }
            *active = Some(next);
            Ok(())
        }
        Err(error) => Err(format!(
            "failed to update active SYN limiter namespace: {error}"
        )),
    }
}

fn active_synlimit_namespace() -> Result<Option<SynLimitNamespace>, String> {
    match ACTIVE_SYNLIMIT_NAMESPACE.lock() {
        Ok(active) => Ok(active.clone()),
        Err(error) => Err(format!(
            "failed to read active SYN limiter namespace: {error}"
        )),
    }
}

fn clear_active_synlimit_namespace(expected: &SynLimitNamespace) -> Result<(), String> {
    match ACTIVE_SYNLIMIT_NAMESPACE.lock() {
        Ok(mut active) => {
            if active.as_ref() == Some(expected) {
                *active = None;
            }
            Ok(())
        }
        Err(error) => Err(format!(
            "failed to update active SYN limiter namespace: {error}"
        )),
    }
}
