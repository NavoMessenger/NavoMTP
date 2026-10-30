use std::collections::BTreeSet;
use std::net::IpAddr;
use std::sync::Arc;

use crate::config::{ConntrackBackend, ConntrackMode, ProxyConfig};
use crate::stats::Stats;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ShadowSlot {
    A,
    B,
}

impl ShadowSlot {
    pub(super) fn other(self) -> Self {
        match self {
            Self::A => Self::B,
            Self::B => Self::A,
        }
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct NotrackTarget {
    pub(super) ip: Option<IpAddr>,
    pub(super) port: u16,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum DesiredPolicy {
    Empty,
    Rules {
        configured_backend: ConntrackBackend,
        v4: Vec<NotrackTarget>,
        v6: Vec<NotrackTarget>,
    },
}

impl DesiredPolicy {
    pub(super) fn from_config(cfg: &ProxyConfig) -> Self {
        if !cfg.server.conntrack_control.inline_conntrack_control
            || matches!(cfg.server.conntrack_control.mode, ConntrackMode::Tracked)
        {
            return Self::Empty;
        }
        let (v4, v6) = notrack_targets(cfg);
        if v4.is_empty() && v6.is_empty() {
            Self::Empty
        } else {
            Self::Rules {
                configured_backend: cfg.server.conntrack_control.backend,
                v4,
                v6,
            }
        }
    }
}

#[derive(Clone)]
pub(super) struct DesiredState {
    pub(super) generation: u64,
    pub(super) policy: DesiredPolicy,
    pub(super) stats: Arc<Stats>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum AppliedPlan {
    Empty,
    Iptables {
        slot: ShadowSlot,
        v4: Vec<NotrackTarget>,
        v6: Vec<NotrackTarget>,
    },
    Nftables {
        slot: ShadowSlot,
        v4: Vec<NotrackTarget>,
        v6: Vec<NotrackTarget>,
    },
}

impl AppliedPlan {
    pub(super) fn slot(&self) -> Option<ShadowSlot> {
        match self {
            Self::Empty => None,
            Self::Iptables { slot, .. } | Self::Nftables { slot, .. } => Some(*slot),
        }
    }

    pub(super) fn matches_policy(&self, policy: &DesiredPolicy) -> bool {
        match (self, policy) {
            (Self::Empty, DesiredPolicy::Empty) => true,
            (
                Self::Iptables { v4, v6, .. },
                DesiredPolicy::Rules {
                    configured_backend,
                    v4: desired_v4,
                    v6: desired_v6,
                },
            ) => {
                matches!(
                    configured_backend,
                    ConntrackBackend::Auto | ConntrackBackend::Iptables
                ) && v4 == desired_v4
                    && v6 == desired_v6
            }
            (
                Self::Nftables { v4, v6, .. },
                DesiredPolicy::Rules {
                    configured_backend,
                    v4: desired_v4,
                    v6: desired_v6,
                },
            ) => {
                matches!(
                    configured_backend,
                    ConntrackBackend::Auto | ConntrackBackend::Nftables
                ) && v4 == desired_v4
                    && v6 == desired_v6
            }
            _ => false,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum AppliedState {
    Known(AppliedPlan),
    Unknown,
}

fn listener_port_set(cfg: &ProxyConfig) -> Vec<u16> {
    let mut ports = BTreeSet::new();
    if cfg.server.listeners.is_empty() {
        ports.insert(cfg.server.port);
    } else {
        for listener in &cfg.server.listeners {
            ports.insert(listener.port.unwrap_or(cfg.server.port));
        }
    }
    ports.into_iter().collect()
}

fn notrack_targets(cfg: &ProxyConfig) -> (Vec<NotrackTarget>, Vec<NotrackTarget>) {
    let mut v4_targets = BTreeSet::new();
    let mut v6_targets = BTreeSet::new();
    match cfg.server.conntrack_control.mode {
        ConntrackMode::Tracked => {}
        ConntrackMode::Notrack => {
            if cfg.server.listeners.is_empty() {
                let port = cfg.server.port;
                for raw in [
                    cfg.server.listen_addr_ipv4.as_deref(),
                    cfg.server.listen_addr_ipv6.as_deref(),
                ]
                .into_iter()
                .flatten()
                {
                    if let Ok(ip) = raw.parse::<IpAddr>() {
                        let target = NotrackTarget {
                            ip: (!ip.is_unspecified()).then_some(ip),
                            port,
                        };
                        if ip.is_ipv4() {
                            v4_targets.insert(target);
                        } else {
                            v6_targets.insert(target);
                        }
                    }
                }
            } else {
                for listener in &cfg.server.listeners {
                    let target = NotrackTarget {
                        ip: (!listener.ip.is_unspecified()).then_some(listener.ip),
                        port: listener.port.unwrap_or(cfg.server.port),
                    };
                    if listener.ip.is_ipv4() {
                        v4_targets.insert(target);
                    } else {
                        v6_targets.insert(target);
                    }
                }
            }
        }
        ConntrackMode::Hybrid => {
            for ip in &cfg.server.conntrack_control.hybrid_listener_ips {
                for port in listener_port_set(cfg) {
                    let target = NotrackTarget {
                        ip: Some(*ip),
                        port,
                    };
                    if ip.is_ipv4() {
                        v4_targets.insert(target);
                    } else {
                        v6_targets.insert(target);
                    }
                }
            }
        }
    }
    (
        v4_targets.into_iter().collect(),
        v6_targets.into_iter().collect(),
    )
}
