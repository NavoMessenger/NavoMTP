use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::config::ProxyConfig;

use super::ApiShared;

const SOURCE_UNAVAILABLE_REASON: &str = "source_unavailable";

#[derive(Serialize)]
pub(super) struct SecurityWhitelistData {
    pub(super) generated_at_epoch_secs: u64,
    pub(super) enabled: bool,
    pub(super) entries_total: usize,
    pub(super) entries: Vec<String>,
}

#[derive(Serialize)]
pub(super) struct RuntimeMeQualityCountersData {
    pub(super) idle_close_by_peer_total: u64,
    pub(super) reader_eof_total: u64,
    pub(super) kdf_drift_total: u64,
    pub(super) kdf_port_only_drift_total: u64,
    pub(super) reconnect_attempt_total: u64,
    pub(super) reconnect_success_total: u64,
}

#[derive(Serialize)]
pub(super) struct RuntimeMeQualityRouteDropData {
    pub(super) no_conn_total: u64,
    pub(super) channel_closed_total: u64,
    pub(super) queue_full_total: u64,
    pub(super) queue_full_base_total: u64,
    pub(super) queue_full_high_total: u64,
}

#[derive(Serialize)]
pub(super) struct RuntimeMeQualityFamilyStateData {
    pub(super) family: &'static str,
    pub(super) state: &'static str,
    pub(super) state_since_epoch_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) suppressed_until_epoch_secs: Option<u64>,
    pub(super) fail_streak: u32,
    pub(super) recover_success_streak: u32,
}

#[derive(Serialize)]
pub(super) struct RuntimeMeQualityDrainGateData {
    pub(super) route_quorum_ok: bool,
    pub(super) redundancy_ok: bool,
    pub(super) block_reason: &'static str,
    pub(super) updated_at_epoch_secs: u64,
}

#[derive(Serialize)]
pub(super) struct RuntimeMeQualityDcRttData {
    pub(super) dc: i16,
    pub(super) rtt_ema_ms: Option<f64>,
    pub(super) alive_writers: usize,
    pub(super) required_writers: usize,
    pub(super) coverage_pct: f64,
}

#[derive(Serialize)]
pub(super) struct RuntimeMeQualityPayload {
    pub(super) counters: RuntimeMeQualityCountersData,
    pub(super) route_drops: RuntimeMeQualityRouteDropData,
    pub(super) family_states: Vec<RuntimeMeQualityFamilyStateData>,
    pub(super) drain_gate: RuntimeMeQualityDrainGateData,
    pub(super) dc_rtt: Vec<RuntimeMeQualityDcRttData>,
}

#[derive(Serialize)]
pub(super) struct RuntimeMeQualityData {
    pub(super) enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) reason: Option<&'static str>,
    pub(super) generated_at_epoch_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) data: Option<RuntimeMeQualityPayload>,
}

#[derive(Serialize)]
pub(super) struct RuntimeUpstreamQualityPolicyData {
    pub(super) connect_retry_attempts: u32,
    pub(super) connect_retry_backoff_ms: u64,
    pub(super) connect_budget_ms: u64,
    pub(super) unhealthy_fail_threshold: u32,
    pub(super) connect_failfast_hard_errors: bool,
}

#[derive(Serialize)]
pub(super) struct RuntimeUpstreamQualityCountersData {
    pub(super) connect_attempt_total: u64,
    pub(super) connect_success_total: u64,
    pub(super) connect_fail_total: u64,
    pub(super) connect_failfast_hard_error_total: u64,
}

#[derive(Serialize)]
pub(super) struct RuntimeUpstreamQualitySummaryData {
    pub(super) configured_total: usize,
    pub(super) healthy_total: usize,
    pub(super) unhealthy_total: usize,
    pub(super) direct_total: usize,
    pub(super) socks4_total: usize,
    pub(super) socks5_total: usize,
    pub(super) shadowsocks_total: usize,
}

#[derive(Serialize)]
pub(super) struct RuntimeUpstreamQualityDcData {
    pub(super) dc: i16,
    pub(super) latency_ema_ms: Option<f64>,
    pub(super) ip_preference: &'static str,
}

#[derive(Serialize)]
pub(super) struct RuntimeUpstreamQualityUpstreamData {
    pub(super) upstream_id: usize,
    pub(super) route_kind: &'static str,
    pub(super) address: String,
    pub(super) weight: u16,
    pub(super) scopes: String,
    pub(super) healthy: bool,
    pub(super) fails: u32,
    pub(super) last_check_age_secs: u64,
    pub(super) effective_latency_ms: Option<f64>,
    pub(super) dc: Vec<RuntimeUpstreamQualityDcData>,
}

#[derive(Serialize)]
pub(super) struct RuntimeUpstreamQualityData {
    pub(super) enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) reason: Option<&'static str>,
    pub(super) generated_at_epoch_secs: u64,
    pub(super) policy: RuntimeUpstreamQualityPolicyData,
    pub(super) counters: RuntimeUpstreamQualityCountersData,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) summary: Option<RuntimeUpstreamQualitySummaryData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) upstreams: Option<Vec<RuntimeUpstreamQualityUpstreamData>>,
}

#[derive(Serialize)]
pub(super) struct RuntimeNatStunReflectionData {
    pub(super) addr: String,
    pub(super) age_secs: u64,
}

#[derive(Serialize)]
pub(super) struct RuntimeNatStunFlagsData {
    pub(super) nat_probe_enabled: bool,
    pub(super) nat_probe_disabled_runtime: bool,
    pub(super) nat_probe_attempts: u8,
}

#[derive(Serialize)]
pub(super) struct RuntimeNatStunServersData {
    pub(super) configured: Vec<String>,
    pub(super) live: Vec<String>,
    pub(super) live_total: usize,
}

#[derive(Serialize)]
pub(super) struct RuntimeNatStunReflectionBlockData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) v4: Option<RuntimeNatStunReflectionData>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) v6: Option<RuntimeNatStunReflectionData>,
}

#[derive(Serialize)]
pub(super) struct RuntimeNatStunPayload {
    pub(super) flags: RuntimeNatStunFlagsData,
    pub(super) servers: RuntimeNatStunServersData,
    pub(super) reflection: RuntimeNatStunReflectionBlockData,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) stun_backoff_remaining_ms: Option<u64>,
}

#[derive(Serialize)]
pub(super) struct RuntimeNatStunData {
    pub(super) enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) reason: Option<&'static str>,
    pub(super) generated_at_epoch_secs: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) data: Option<RuntimeNatStunPayload>,
}

pub(super) fn build_security_whitelist_data(cfg: &ProxyConfig) -> SecurityWhitelistData {
    let entries = cfg
        .server
        .api
        .whitelist
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    SecurityWhitelistData {
        generated_at_epoch_secs: now_epoch_secs(),
        enabled: !entries.is_empty(),
        entries_total: entries.len(),
        entries,
    }
}

pub(super) async fn build_runtime_me_quality_data(shared: &ApiShared) -> RuntimeMeQualityData {
    let now_epoch_secs = now_epoch_secs();
    let Some(pool) = shared.me_pool.read().await.clone() else {
        return RuntimeMeQualityData {
            enabled: false,
            reason: Some(SOURCE_UNAVAILABLE_REASON),
            generated_at_epoch_secs: now_epoch_secs,
            data: None,
        };
    };

    let status = pool.api_status_snapshot().await;
    let family_states = pool
        .api_family_state_snapshot()
        .into_iter()
        .map(|entry| RuntimeMeQualityFamilyStateData {
            family: entry.family,
            state: entry.state,
            state_since_epoch_secs: entry.state_since_epoch_secs,
            suppressed_until_epoch_secs: entry.suppressed_until_epoch_secs,
            fail_streak: entry.fail_streak,
            recover_success_streak: entry.recover_success_streak,
        })
        .collect();
    let drain_gate_snapshot = pool.api_drain_gate_snapshot();
    RuntimeMeQualityData {
        enabled: true,
        reason: None,
        generated_at_epoch_secs: status.generated_at_epoch_secs,
        data: Some(RuntimeMeQualityPayload {
            counters: RuntimeMeQualityCountersData {
                idle_close_by_peer_total: shared.stats.get_me_idle_close_by_peer_total(),
                reader_eof_total: shared.stats.get_me_reader_eof_total(),
                kdf_drift_total: shared.stats.get_me_kdf_drift_total(),
                kdf_port_only_drift_total: shared.stats.get_me_kdf_port_only_drift_total(),
                reconnect_attempt_total: shared.stats.get_me_reconnect_attempts(),
                reconnect_success_total: shared.stats.get_me_reconnect_success(),
            },
            route_drops: RuntimeMeQualityRouteDropData {
                no_conn_total: shared.stats.get_me_route_drop_no_conn(),
                channel_closed_total: shared.stats.get_me_route_drop_channel_closed(),
                queue_full_total: shared.stats.get_me_route_drop_queue_full(),
                queue_full_base_total: shared.stats.get_me_route_drop_queue_full_base(),
                queue_full_high_total: shared.stats.get_me_route_drop_queue_full_high(),
            },
            family_states,
            drain_gate: RuntimeMeQualityDrainGateData {
                route_quorum_ok: drain_gate_snapshot.route_quorum_ok,
                redundancy_ok: drain_gate_snapshot.redundancy_ok,
                block_reason: drain_gate_snapshot.block_reason,
                updated_at_epoch_secs: drain_gate_snapshot.updated_at_epoch_secs,
            },
            dc_rtt: status
                .dcs
                .into_iter()
                .map(|dc| RuntimeMeQualityDcRttData {
                    dc: dc.dc,
                    rtt_ema_ms: dc.rtt_ms,
                    alive_writers: dc.alive_writers,
                    required_writers: dc.required_writers,
                    coverage_pct: dc.coverage_pct,
                })
                .collect(),
        }),
    }
}

pub(super) async fn build_runtime_upstream_quality_data(
    shared: &ApiShared,
) -> RuntimeUpstreamQualityData {
    let generated_at_epoch_secs = now_epoch_secs();
    let policy = shared.upstream_manager.api_policy_snapshot();
    let counters = RuntimeUpstreamQualityCountersData {
        connect_attempt_total: shared.stats.get_upstream_connect_attempt_total(),
        connect_success_total: shared.stats.get_upstream_connect_success_total(),
        connect_fail_total: shared.stats.get_upstream_connect_fail_total(),
        connect_failfast_hard_error_total: shared
            .stats
            .get_upstream_connect_failfast_hard_error_total(),
    };

    let Some(snapshot) = shared.upstream_manager.try_api_snapshot() else {
        return RuntimeUpstreamQualityData {
            enabled: false,
            reason: Some(SOURCE_UNAVAILABLE_REASON),
            generated_at_epoch_secs,
            policy: RuntimeUpstreamQualityPolicyData {
                connect_retry_attempts: policy.connect_retry_attempts,
                connect_retry_backoff_ms: policy.connect_retry_backoff_ms,
                connect_budget_ms: policy.connect_budget_ms,
                unhealthy_fail_threshold: policy.unhealthy_fail_threshold,
                connect_failfast_hard_errors: policy.connect_failfast_hard_errors,
            },
            counters,
            summary: None,
            upstreams: None,
        };
    };

    RuntimeUpstreamQualityData {
        enabled: true,
        reason: None,
        generated_at_epoch_secs,
        policy: RuntimeUpstreamQualityPolicyData {
            connect_retry_attempts: policy.connect_retry_attempts,
            connect_retry_backoff_ms: policy.connect_retry_backoff_ms,
            connect_budget_ms: policy.connect_budget_ms,
            unhealthy_fail_threshold: policy.unhealthy_fail_threshold,
            connect_failfast_hard_errors: policy.connect_failfast_hard_errors,
        },
        counters,
        summary: Some(RuntimeUpstreamQualitySummaryData {
            configured_total: snapshot.summary.configured_total,
            healthy_total: snapshot.summary.healthy_total,
            unhealthy_total: snapshot.summary.unhealthy_total,
            direct_total: snapshot.summary.direct_total,
            socks4_total: snapshot.summary.socks4_total,
            socks5_total: snapshot.summary.socks5_total,
            shadowsocks_total: snapshot.summary.shadowsocks_total,
        }),
        upstreams: Some(
            snapshot
                .upstreams
                .into_iter()
                .map(|upstream| RuntimeUpstreamQualityUpstreamData {
                    upstream_id: upstream.upstream_id,
                    route_kind: match upstream.route_kind {
                        crate::transport::UpstreamRouteKind::Direct => "direct",
                        crate::transport::UpstreamRouteKind::Socks4 => "socks4",
                        crate::transport::UpstreamRouteKind::Socks5 => "socks5",
                        crate::transport::UpstreamRouteKind::Shadowsocks => "shadowsocks",
                    },
                    address: upstream.address,
                    weight: upstream.weight,
                    scopes: upstream.scopes,
                    healthy: upstream.healthy,
                    fails: upstream.fails,
                    last_check_age_secs: upstream.last_check_age_secs,
                    effective_latency_ms: upstream.effective_latency_ms,
                    dc: upstream
                        .dc
                        .into_iter()
                        .map(|dc| RuntimeUpstreamQualityDcData {
                            dc: dc.dc,
                            latency_ema_ms: dc.latency_ema_ms,
                            ip_preference: match dc.ip_preference {
                                crate::transport::upstream::IpPreference::Unknown => "unknown",
                                crate::transport::upstream::IpPreference::PreferV6 => "prefer_v6",
                                crate::transport::upstream::IpPreference::PreferV4 => "prefer_v4",
                                crate::transport::upstream::IpPreference::BothWork => "both_work",
                                crate::transport::upstream::IpPreference::Unavailable => {
                                    "unavailable"
                                }
                            },
                        })
                        .collect(),
                })
                .collect(),
        ),
    }
}

// ME pool runtime-state projection.
mod me_pool;
// NAT/STUN runtime projection and timestamping.
mod nat;
pub(super) use me_pool::build_runtime_me_pool_state_data;
pub(super) use nat::build_runtime_nat_stun_data;
use nat::now_epoch_secs;
