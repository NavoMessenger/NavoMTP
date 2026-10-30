use super::*;
use crate::config::WebCarrier;
use crate::web::manager::CarrierFailure;
use crate::web::session::SessionCloseReason;

#[test]
fn fixed_counter_sets_and_acceptor_guard_are_exact() {
    let telemetry = WebTelemetry::new();
    let guard = telemetry.acceptor_guard();
    assert_eq!(telemetry.live_acceptors(), 1);
    telemetry.record_rejection(WebRejectionReason::HttpConnectionCapacity);
    telemetry.record_overload(WebHttpConnectionOverloadOutcome::Dropped);
    telemetry.record_decoy(WebDecoyUpstreamOutcome::ConnectRefused);
    telemetry.record_carrier_selection(WebCarrier::Https, WebCarrierSelectionDisposition::Cold);
    telemetry.record_carrier_failure(
        WebCarrier::Https,
        WebCarrierFailurePhase::Provisional,
        CarrierFailure::Network,
    );
    telemetry.record_carrier_learning(WebCarrier::Https, WebCarrierLearningOutcome::Recorded);
    telemetry.record_decoy_fasttrack(WebDecoyFastTrackDisposition::ShadowWouldFastTrack);
    telemetry.record_session_closed(WebCarrier::Https, SessionCloseReason::ApiClose);
    telemetry.record_session_observation(
        WebCarrier::Https,
        WebSessionLifecycleObservation::RequestAfterClose,
    );
    telemetry.record_bridge_recovery(WebBridgeRecoveryEvent::BootstrapIssued);
    assert_eq!(
        telemetry.rejection_counters().len(),
        WebRejectionReason::ALL.len()
    );
    assert_eq!(
        telemetry.overload_counters().len(),
        WebHttpConnectionOverloadOutcome::ALL.len()
    );
    assert_eq!(
        telemetry.decoy_counters().len(),
        WebDecoyUpstreamOutcome::ALL.len()
    );
    assert_eq!(
        telemetry.carrier_selection_counters().len(),
        WebCarrier::ALL.len() * WebCarrierSelectionDisposition::ALL.len()
    );
    assert_eq!(
        telemetry.carrier_failure_counters().len(),
        WebCarrier::ALL.len() * WebCarrierFailurePhase::ALL.len() * CarrierFailure::ALL.len()
    );
    assert_eq!(
        telemetry.carrier_learning_counters().len(),
        WebCarrier::ALL.len() * WebCarrierLearningOutcome::ALL.len()
    );
    assert_eq!(
        telemetry.decoy_fasttrack_counters().len(),
        WebDecoyFastTrackDisposition::ALL.len()
    );
    assert_eq!(
        telemetry.decoy_fasttrack_total(WebDecoyFastTrackDisposition::ShadowWouldFastTrack),
        1
    );
    assert_eq!(
        telemetry.session_close_counters().len(),
        WebCarrier::ALL.len() * SessionCloseReason::ALL.len()
    );
    assert_eq!(
        telemetry.session_observation_counters().len(),
        WebCarrier::ALL.len() * WebSessionLifecycleObservation::ALL.len()
    );
    assert_eq!(
        telemetry.bridge_recovery_counters().len(),
        WebBridgeRecoveryEvent::ALL.len()
    );
    assert_eq!(
        telemetry.rejection_total(WebRejectionReason::HttpConnectionCapacity),
        1
    );
    assert_eq!(
        telemetry.last_decoy().map(|value| value.0),
        Some("connect_refused")
    );
    assert_eq!(telemetry.aggregates().sessions_closed, 1);
    assert_eq!(
        telemetry
            .session_close_counters()
            .into_iter()
            .map(|counter| counter.total)
            .sum::<u64>(),
        1
    );
    drop(guard);
    assert_eq!(telemetry.live_acceptors(), 0);
}
