use serde::Serialize;

use crate::config::{ProxyConfig, WebDecoyFastTrackMode, WebHttpConnectionCapacityAction};
use crate::web::control::{WebRuntimeLifecycle, WebRuntimePublication};
use crate::web::manager::{WebCapacityResourceStatus, WebCapacitySnapshot, WebProcessRuntime};
use crate::web::telemetry::{
    WebBridgeRecoveryCounter, WebCarrierFailureCounter, WebCarrierLearningCounter,
    WebCarrierSelectionCounter, WebDecoyFastTrackCounter, WebSessionCloseCounter,
    WebSessionLifecycleObservationCounter,
};
use crate::web::telemetry::{WebOutcomeCounter, WebRejectionCounter};

/// Private WEB ingress state owned by this Telemt process.
#[derive(Serialize)]
pub(super) struct WebIngressStatus {
    configured_listeners: usize,
    live_acceptors: usize,
    accepting_connections: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    tcp_accept_total: u64,
    tcp_accept_error_total: u64,
}

impl WebIngressStatus {
    /// Builds a process-ingress snapshot without probing external TLS termination.
    pub(super) fn new(publication: &WebRuntimePublication, runtime_available: bool) -> Self {
        let configured_listeners = publication.listeners.len();
        let live_acceptors = publication.telemetry.live_acceptors();
        let accepting_connections = publication.lifecycle == WebRuntimeLifecycle::Running
            && runtime_available
            && configured_listeners != 0
            && live_acceptors == configured_listeners;
        let reason = if accepting_connections {
            None
        } else {
            Some(match publication.lifecycle {
                WebRuntimeLifecycle::Starting => "starting",
                WebRuntimeLifecycle::NoWebListener => "no_web_listener",
                WebRuntimeLifecycle::Draining => "ingress_draining",
                WebRuntimeLifecycle::Drained => "ingress_drained",
                WebRuntimeLifecycle::DeadlineExceeded => "deadline_exceeded",
                WebRuntimeLifecycle::Running if !runtime_available => "runtime_released",
                WebRuntimeLifecycle::Running if configured_listeners == 0 => "no_web_listener",
                WebRuntimeLifecycle::Running => "acceptor_unavailable",
            })
        };
        Self {
            configured_listeners,
            live_acceptors,
            accepting_connections,
            reason,
            tcp_accept_total: publication.telemetry.accepted(),
            tcp_accept_error_total: publication.telemetry.accept_errors(),
        }
    }
}

/// Bounded process-wide WEB capacity and terminal rejection view.
#[derive(Serialize)]
pub(super) struct WebCapacityStatus {
    http_connection_capacity_action: WebHttpConnectionCapacityAction,
    max_http_overload_connections: usize,
    http_overload_timeout_ms: u64,
    resources: Vec<WebCapacityResourceStatus>,
    saturated_resources: Vec<&'static str>,
    partial: Vec<&'static str>,
    rejections: Vec<WebRejectionCounter>,
    http_connection_overload_outcomes: Vec<WebOutcomeCounter>,
}

impl WebCapacityStatus {
    /// Builds a bounded capacity snapshot from non-blocking runtime observations.
    pub(super) fn new(
        publication: &WebRuntimePublication,
        runtime: Option<&WebProcessRuntime>,
        config: &ProxyConfig,
    ) -> Self {
        let snapshot = runtime
            .map(WebProcessRuntime::capacity_snapshot)
            .unwrap_or_else(runtime_unavailable_snapshot);
        Self {
            http_connection_capacity_action: config.web.http_connection_capacity_action,
            max_http_overload_connections: config.web.limits.max_http_overload_connections,
            http_overload_timeout_ms: config.web.timeouts.http_overload_timeout_ms,
            resources: snapshot.resources,
            saturated_resources: snapshot.saturated_resources,
            partial: snapshot.partial,
            rejections: publication.telemetry.rejection_counters(),
            http_connection_overload_outcomes: publication.telemetry.overload_counters(),
        }
    }
}

fn runtime_unavailable_snapshot() -> WebCapacitySnapshot {
    WebCapacitySnapshot {
        resources: Vec::new(),
        saturated_resources: Vec::new(),
        partial: vec!["runtime"],
    }
}

/// Passive health of Telemt's internal plain-HTTP decoy origin hop.
#[derive(Serialize)]
pub(super) struct WebDecoyUpstreamStatus {
    outcomes: Vec<WebOutcomeCounter>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_outcome: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_outcome_age_ms: Option<u64>,
}

impl WebDecoyUpstreamStatus {
    /// Builds the fixed internal decoy-origin outcome snapshot.
    pub(super) fn new(publication: &WebRuntimePublication) -> Self {
        let last = publication.telemetry.last_decoy();
        Self {
            outcomes: publication.telemetry.decoy_counters(),
            last_outcome: last.map(|value| value.0),
            last_outcome_age_ms: last.map(|value| value.1),
        }
    }
}

/// Fixed-cardinality process-lifetime decoy capability-routing counters.
#[derive(Serialize)]
pub(super) struct WebDecoyFastTrackStatus {
    mode: WebDecoyFastTrackMode,
    requests: Vec<WebDecoyFastTrackCounter>,
}

impl WebDecoyFastTrackStatus {
    /// Builds effective policy and counters without requiring the runtime manager.
    pub(super) fn new(publication: &WebRuntimePublication, config: &ProxyConfig) -> Self {
        Self {
            mode: config.web.decoy_fasttrack_mode,
            requests: publication.telemetry.decoy_fasttrack_counters(),
        }
    }
}

/// Fixed-cardinality process-lifetime carrier negotiation counters.
#[derive(Serialize)]
pub(super) struct WebCarrierNegotiationStatus {
    selections: Vec<WebCarrierSelectionCounter>,
    reported_failures: Vec<WebCarrierFailureCounter>,
    learning_outcomes: Vec<WebCarrierLearningCounter>,
}

impl WebCarrierNegotiationStatus {
    /// Builds counters from publication ownership even when runtime state is unavailable.
    pub(super) fn new(publication: &WebRuntimePublication) -> Self {
        Self {
            selections: publication.telemetry.carrier_selection_counters(),
            reported_failures: publication.telemetry.carrier_failure_counters(),
            learning_outcomes: publication.telemetry.carrier_learning_counters(),
        }
    }
}

/// Fixed-cardinality process-lifetime WEB lifecycle counters.
#[derive(Serialize)]
pub(super) struct WebLifecycleCountersStatus {
    bridge_recovery_secs: u64,
    session_closures: Vec<WebSessionCloseCounter>,
    session_observations: Vec<WebSessionLifecycleObservationCounter>,
    bridge_recovery_events: Vec<WebBridgeRecoveryCounter>,
}

impl WebLifecycleCountersStatus {
    /// Builds a complete counter set from process-owned telemetry.
    pub(super) fn new(publication: &WebRuntimePublication, config: &ProxyConfig) -> Self {
        Self {
            bridge_recovery_secs: config.web.timeouts.bridge_recovery_secs,
            session_closures: publication.telemetry.session_close_counters(),
            session_observations: publication.telemetry.session_observation_counters(),
            bridge_recovery_events: publication.telemetry.bridge_recovery_counters(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::config::ProxyConfig;
    use crate::web::control::WebRuntimeControl;

    #[test]
    fn starting_ingress_does_not_claim_external_availability() {
        let control = WebRuntimeControl::new();
        let publication = control.subscribe().borrow().clone();
        let value =
            serde_json::to_value(super::WebIngressStatus::new(&publication, false)).unwrap();
        assert_eq!(value["configured_listeners"], 0);
        assert_eq!(value["live_acceptors"], 0);
        assert_eq!(value["accepting_connections"], false);
        assert_eq!(value["reason"], "starting");
    }

    #[test]
    fn unavailable_runtime_keeps_fixed_counter_sets_visible() {
        let control = WebRuntimeControl::new();
        let publication = control.subscribe().borrow().clone();
        let config = ProxyConfig::default();
        let capacity =
            serde_json::to_value(super::WebCapacityStatus::new(&publication, None, &config))
                .unwrap();
        let decoy = serde_json::to_value(super::WebDecoyUpstreamStatus::new(&publication)).unwrap();
        let fasttrack =
            serde_json::to_value(super::WebDecoyFastTrackStatus::new(&publication, &config))
                .unwrap();
        let carrier =
            serde_json::to_value(super::WebCarrierNegotiationStatus::new(&publication)).unwrap();
        let lifecycle = serde_json::to_value(super::WebLifecycleCountersStatus::new(
            &publication,
            &config,
        ))
        .unwrap();

        assert_eq!(
            capacity["rejections"].as_array().unwrap().len(),
            crate::web::telemetry::WebRejectionReason::ALL.len()
        );
        assert_eq!(
            capacity["http_connection_overload_outcomes"]
                .as_array()
                .unwrap()
                .len(),
            crate::web::telemetry::WebHttpConnectionOverloadOutcome::ALL.len()
        );
        assert_eq!(
            decoy["outcomes"].as_array().unwrap().len(),
            crate::web::telemetry::WebDecoyUpstreamOutcome::ALL.len()
        );
        assert_eq!(fasttrack["mode"], "off");
        assert_eq!(
            fasttrack["requests"].as_array().unwrap().len(),
            crate::web::telemetry::WebDecoyFastTrackDisposition::ALL.len()
        );
        assert_eq!(capacity["partial"][0], "runtime");
        assert_eq!(
            carrier["selections"].as_array().unwrap().len(),
            crate::config::WebCarrier::ALL.len()
                * crate::web::telemetry::WebCarrierSelectionDisposition::ALL.len()
        );
        assert_eq!(
            carrier["reported_failures"].as_array().unwrap().len(),
            crate::config::WebCarrier::ALL.len()
                * crate::web::telemetry::WebCarrierFailurePhase::ALL.len()
                * crate::web::manager::CarrierFailure::ALL.len()
        );
        assert_eq!(
            carrier["learning_outcomes"].as_array().unwrap().len(),
            crate::config::WebCarrier::ALL.len()
                * crate::web::telemetry::WebCarrierLearningOutcome::ALL.len()
        );
        assert_eq!(
            lifecycle["session_closures"].as_array().unwrap().len(),
            crate::config::WebCarrier::ALL.len()
                * crate::web::session::SessionCloseReason::ALL.len()
        );
        assert_eq!(
            lifecycle["session_observations"].as_array().unwrap().len(),
            crate::config::WebCarrier::ALL.len()
                * crate::web::telemetry::WebSessionLifecycleObservation::ALL.len()
        );
        assert_eq!(
            lifecycle["bridge_recovery_events"]
                .as_array()
                .unwrap()
                .len(),
            crate::web::telemetry::WebBridgeRecoveryEvent::ALL.len()
        );
    }
}
