use tracing::debug;

use crate::config::{ConntrackBackend, ProxyConfig};
use crate::conntrack_control::{ConntrackRuntimeSupport, NetfilterBackend};
use crate::proxy::shared_state::ConntrackCloseEvent;

use super::command::{CommandSpec, FirewallCommandRunner, SystemCommandRunner};
use super::nftables;

/// Probes the effective firewall backend and conntrack deletion capability.
pub(in crate::conntrack_control) fn probe_runtime_support(
    configured_backend: ConntrackBackend,
) -> ConntrackRuntimeSupport {
    let runner = SystemCommandRunner;
    let iptables_available = runner.available("iptables");
    let netfilter_backend = match configured_backend {
        ConntrackBackend::Auto if nftables::available(&runner) => Some(NetfilterBackend::Nftables),
        ConntrackBackend::Auto if iptables_available => Some(NetfilterBackend::Iptables),
        ConntrackBackend::Nftables if nftables::available(&runner) => {
            Some(NetfilterBackend::Nftables)
        }
        ConntrackBackend::Iptables if iptables_available => Some(NetfilterBackend::Iptables),
        _ => None,
    };
    ConntrackRuntimeSupport {
        netfilter_backend,
        has_cap_net_admin: runner.has_cap_net_admin(),
        has_conntrack_binary: runner.available("conntrack"),
    }
}

/// Resolves whether conntrack close publication is usable for this runtime.
pub(in crate::conntrack_control) fn effective_conntrack_enabled(
    cfg: &ProxyConfig,
    runtime_support: ConntrackRuntimeSupport,
) -> bool {
    cfg.server.conntrack_control.inline_conntrack_control
        && runtime_support.has_cap_net_admin
        && runtime_support.netfilter_backend.is_some()
        && runtime_support.has_conntrack_binary
}

/// Result of one best-effort kernel conntrack deletion.
pub(in crate::conntrack_control) enum DeleteOutcome {
    /// The kernel reported successful deletion.
    Deleted,
    /// No matching conntrack entry existed.
    NotFound,
    /// The helper was unavailable or returned an unexpected failure.
    Error,
}

/// Deletes the exact TCP tuple represented by one close event.
pub(in crate::conntrack_control) async fn delete_conntrack_entry(
    event: ConntrackCloseEvent,
) -> DeleteOutcome {
    let runner = SystemCommandRunner;
    if !runner.available("conntrack") {
        return DeleteOutcome::Error;
    }
    let args = vec![
        "-D".to_string(),
        "-p".to_string(),
        "tcp".to_string(),
        "-s".to_string(),
        event.src.ip().to_string(),
        "--sport".to_string(),
        event.src.port().to_string(),
        "-d".to_string(),
        event.dst.ip().to_string(),
        "--dport".to_string(),
        event.dst.port().to_string(),
    ];
    match runner
        .run(CommandSpec {
            binary: "conntrack",
            args,
            stdin: None,
        })
        .await
    {
        Ok(()) => DeleteOutcome::Deleted,
        Err(error) if error.message.contains("0 flow entries have been deleted") => {
            DeleteOutcome::NotFound
        }
        Err(error) => {
            debug!(error = %error, "conntrack delete failed");
            DeleteOutcome::Error
        }
    }
}
