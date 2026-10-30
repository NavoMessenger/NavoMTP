use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;

use crate::config::WebCarrier;
use crate::web::session::SessionCloseReason;

use super::WebTelemetry;

pub(super) const SESSION_CLOSE_SLOTS: usize = WebCarrier::ALL.len() * SessionCloseReason::ALL.len();
pub(super) const SESSION_OBSERVATION_SLOTS: usize =
    WebCarrier::ALL.len() * WebSessionLifecycleObservation::ALL.len();

/// Stable authenticated session lifecycle observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub(crate) enum WebSessionLifecycleObservation {
    /// A valid HTTP carrier request resumed after a suspicious peer gap.
    HttpActivityAfterGap,
    /// A valid WebSocket message resumed after a suspicious peer gap.
    WebSocketActivityAfterGap,
    /// A valid retained bearer was used after its session closed.
    RequestAfterClose,
}

impl WebSessionLifecycleObservation {
    /// Complete fixed observation set in stable metric order.
    pub(crate) const ALL: [Self; 3] = [
        Self::HttpActivityAfterGap,
        Self::WebSocketActivityAfterGap,
        Self::RequestAfterClose,
    ];

    /// Returns the stable API and Prometheus token.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::HttpActivityAfterGap => "http_activity_after_gap",
            Self::WebSocketActivityAfterGap => "websocket_activity_after_gap",
            Self::RequestAfterClose => "request_after_close",
        }
    }
}

/// Stable server-side milestone for one bridge recovery incarnation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub(crate) enum WebBridgeRecoveryEvent {
    /// A recovery request received a fresh bootstrap.
    BootstrapIssued,
    /// A fresh recovery session was registered.
    SessionCreated,
    /// The recovery session committed a real carrier.
    Committed,
    /// An issued recovery bootstrap expired without session creation.
    ExpiredUnused,
    /// A recovery session closed before carrier commit.
    ClosedBeforeCommit,
}

impl WebBridgeRecoveryEvent {
    /// Complete fixed recovery event set in stable metric order.
    pub(crate) const ALL: [Self; 5] = [
        Self::BootstrapIssued,
        Self::SessionCreated,
        Self::Committed,
        Self::ExpiredUnused,
        Self::ClosedBeforeCommit,
    ];

    /// Returns the stable API and Prometheus token.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::BootstrapIssued => "bootstrap_issued",
            Self::SessionCreated => "session_created",
            Self::Committed => "committed",
            Self::ExpiredUnused => "expired_unused",
            Self::ClosedBeforeCommit => "closed_before_commit",
        }
    }
}

/// API-safe typed session-close counter.
#[derive(Clone, Serialize)]
pub(crate) struct WebSessionCloseCounter {
    /// Fixed carrier owning the closed incarnation.
    pub(crate) carrier: &'static str,
    /// Fixed terminal close cause.
    pub(crate) reason: &'static str,
    /// Monotonic process-lifetime count.
    pub(crate) total: u64,
}

/// API-safe typed lifecycle-observation counter.
#[derive(Clone, Serialize)]
pub(crate) struct WebSessionLifecycleObservationCounter {
    /// Fixed carrier associated with the observation.
    pub(crate) carrier: &'static str,
    /// Fixed lifecycle observation.
    pub(crate) observation: &'static str,
    /// Monotonic process-lifetime count.
    pub(crate) total: u64,
}

/// API-safe typed bridge-recovery counter.
#[derive(Clone, Serialize)]
pub(crate) struct WebBridgeRecoveryCounter {
    /// Fixed recovery milestone.
    pub(crate) event: &'static str,
    /// Monotonic process-lifetime count.
    pub(crate) total: u64,
}

pub(super) const fn session_close_slot(carrier: WebCarrier, reason: SessionCloseReason) -> usize {
    carrier.index() * SessionCloseReason::ALL.len() + reason as usize
}

pub(super) const fn session_observation_slot(
    carrier: WebCarrier,
    observation: WebSessionLifecycleObservation,
) -> usize {
    carrier.index() * WebSessionLifecycleObservation::ALL.len() + observation as usize
}

pub(super) fn load(counter: &AtomicU64) -> u64 {
    counter.load(Ordering::Relaxed)
}

impl WebTelemetry {
    /// Records one closed session incarnation and its exact terminal cause.
    pub(crate) fn record_session_closed(&self, carrier: WebCarrier, reason: SessionCloseReason) {
        self.sessions_closed.fetch_add(1, Ordering::Relaxed);
        self.session_closures[session_close_slot(carrier, reason)].fetch_add(1, Ordering::Relaxed);
    }

    /// Returns one fixed session-close counter.
    pub(crate) fn session_close_total(
        &self,
        carrier: WebCarrier,
        reason: SessionCloseReason,
    ) -> u64 {
        load(&self.session_closures[session_close_slot(carrier, reason)])
    }

    /// Captures the complete fixed session-close matrix for API serialization.
    pub(crate) fn session_close_counters(&self) -> Vec<WebSessionCloseCounter> {
        WebCarrier::ALL
            .into_iter()
            .flat_map(|carrier| {
                SessionCloseReason::ALL
                    .into_iter()
                    .map(move |reason| WebSessionCloseCounter {
                        carrier: carrier.as_str(),
                        reason: reason.as_str(),
                        total: self.session_close_total(carrier, reason),
                    })
            })
            .collect()
    }

    /// Records one fixed authenticated lifecycle observation.
    pub(crate) fn record_session_observation(
        &self,
        carrier: WebCarrier,
        observation: WebSessionLifecycleObservation,
    ) {
        self.session_observations[session_observation_slot(carrier, observation)]
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Returns one fixed authenticated lifecycle observation counter.
    pub(crate) fn session_observation_total(
        &self,
        carrier: WebCarrier,
        observation: WebSessionLifecycleObservation,
    ) -> u64 {
        load(&self.session_observations[session_observation_slot(carrier, observation)])
    }

    /// Captures the complete fixed lifecycle-observation matrix.
    pub(crate) fn session_observation_counters(
        &self,
    ) -> Vec<WebSessionLifecycleObservationCounter> {
        WebCarrier::ALL
            .into_iter()
            .flat_map(|carrier| {
                WebSessionLifecycleObservation::ALL
                    .into_iter()
                    .map(move |observation| WebSessionLifecycleObservationCounter {
                        carrier: carrier.as_str(),
                        observation: observation.as_str(),
                        total: self.session_observation_total(carrier, observation),
                    })
            })
            .collect()
    }

    /// Records one fixed bridge-recovery milestone.
    pub(crate) fn record_bridge_recovery(&self, event: WebBridgeRecoveryEvent) {
        self.bridge_recovery_events[event as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// Adds a bounded batch of identical recovery milestones.
    pub(crate) fn record_bridge_recovery_count(&self, event: WebBridgeRecoveryEvent, count: usize) {
        self.bridge_recovery_events[event as usize]
            .fetch_add(u64::try_from(count).unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    /// Returns one fixed bridge-recovery counter.
    pub(crate) fn bridge_recovery_total(&self, event: WebBridgeRecoveryEvent) -> u64 {
        load(&self.bridge_recovery_events[event as usize])
    }

    /// Captures the complete fixed bridge-recovery event set.
    pub(crate) fn bridge_recovery_counters(&self) -> Vec<WebBridgeRecoveryCounter> {
        WebBridgeRecoveryEvent::ALL
            .into_iter()
            .map(|event| WebBridgeRecoveryCounter {
                event: event.as_str(),
                total: self.bridge_recovery_total(event),
            })
            .collect()
    }
}
