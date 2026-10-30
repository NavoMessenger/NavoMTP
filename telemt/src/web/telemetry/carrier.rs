use std::sync::atomic::Ordering;

use serde::Serialize;

use super::WebTelemetry;
use crate::config::WebCarrier;
use crate::web::manager::CarrierFailure;

/// Reason learning did or did not influence one successful initial selection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub(crate) enum WebCarrierSelectionDisposition {
    /// The selected runtime profile did not enable learning.
    ProfileDisabled,
    /// The effective process policy disabled learning.
    PolicyDisabled,
    /// The exact generation policy had not reached the process store.
    PolicyPending,
    /// The monotonic evidence epoch space was exhausted.
    EpochExhausted,
    /// Active evidence produced no non-zero candidate score.
    Cold,
    /// Active evidence contributed to candidate ordering.
    Applied,
}

impl WebCarrierSelectionDisposition {
    /// Complete fixed selection disposition set in stable metric order.
    pub(crate) const ALL: [Self; 6] = [
        Self::ProfileDisabled,
        Self::PolicyDisabled,
        Self::PolicyPending,
        Self::EpochExhausted,
        Self::Cold,
        Self::Applied,
    ];

    /// Returns the stable API and Prometheus label token.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::ProfileDisabled => "profile_disabled",
            Self::PolicyDisabled => "policy_disabled",
            Self::PolicyPending => "policy_pending",
            Self::EpochExhausted => "epoch_exhausted",
            Self::Cold => "cold",
            Self::Applied => "applied",
        }
    }
}

/// Attempt-chain phase in which a client reported one carrier failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub(crate) enum WebCarrierFailurePhase {
    /// The replaced attempt had not committed carrier progress.
    Provisional,
    /// The committed attempt failed before its health publication completed.
    Committed,
}

impl WebCarrierFailurePhase {
    /// Complete fixed reported-failure phase set.
    pub(crate) const ALL: [Self; 2] = [Self::Provisional, Self::Committed];

    /// Returns the stable API and Prometheus label token.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Provisional => "provisional",
            Self::Committed => "committed",
        }
    }
}

/// Terminal result of one carrier health or learning publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub(crate) enum WebCarrierLearningOutcome {
    /// The complete eligible chain was recorded.
    Recorded,
    /// The healthy session had no learning context.
    NotEligible,
    /// The effective learning policy rejected evidence.
    PolicyDisabled,
    /// The sample belonged to a superseded evidence epoch.
    StaleEpoch,
    /// The bounded evidence store could not accept the complete sample.
    CapacityRejected,
    /// Evidence insertion identifiers were exhausted.
    SequenceExhausted,
    /// The attempt chain no longer existed at publication time.
    MissingChain,
    /// The attempt chain was not awaiting health publication.
    PhaseMismatch,
    /// Another session incarnation owned the attempt chain.
    SessionMismatch,
    /// The exact WebSocket owner was closing or no longer active.
    OwnerNotLive,
    /// Session closure won the publication race.
    ClosedBeforeHealth,
}

impl WebCarrierLearningOutcome {
    /// Complete fixed health and learning outcome set.
    pub(crate) const ALL: [Self; 11] = [
        Self::Recorded,
        Self::NotEligible,
        Self::PolicyDisabled,
        Self::StaleEpoch,
        Self::CapacityRejected,
        Self::SequenceExhausted,
        Self::MissingChain,
        Self::PhaseMismatch,
        Self::SessionMismatch,
        Self::OwnerNotLive,
        Self::ClosedBeforeHealth,
    ];

    /// Returns the stable API and Prometheus label token.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Recorded => "recorded",
            Self::NotEligible => "not_eligible",
            Self::PolicyDisabled => "policy_disabled",
            Self::StaleEpoch => "stale_epoch",
            Self::CapacityRejected => "capacity_rejected",
            Self::SequenceExhausted => "sequence_exhausted",
            Self::MissingChain => "missing_chain",
            Self::PhaseMismatch => "phase_mismatch",
            Self::SessionMismatch => "session_mismatch",
            Self::OwnerNotLive => "owner_not_live",
            Self::ClosedBeforeHealth => "closed_before_health",
        }
    }
}

pub(super) const CARRIER_SELECTION_SLOTS: usize =
    WebCarrier::ALL.len() * WebCarrierSelectionDisposition::ALL.len();
pub(super) const CARRIER_FAILURE_SLOTS: usize =
    WebCarrier::ALL.len() * WebCarrierFailurePhase::ALL.len() * CarrierFailure::ALL.len();
pub(super) const CARRIER_LEARNING_SLOTS: usize =
    WebCarrier::ALL.len() * WebCarrierLearningOutcome::ALL.len();

/// API-safe fixed carrier selection counter.
#[derive(Clone, Serialize)]
pub(crate) struct WebCarrierSelectionCounter {
    /// Stable carrier token.
    pub(crate) carrier: &'static str,
    /// Stable selection disposition token.
    pub(crate) disposition: &'static str,
    /// Process-lifetime event count.
    pub(crate) total: u64,
}

/// API-safe fixed client-reported carrier failure counter.
#[derive(Clone, Serialize)]
pub(crate) struct WebCarrierFailureCounter {
    /// Stable carrier token.
    pub(crate) carrier: &'static str,
    /// Attempt-chain phase at failure reporting time.
    pub(crate) phase: &'static str,
    /// Canonical client-reported failure token.
    pub(crate) reason: &'static str,
    /// Process-lifetime event count.
    pub(crate) total: u64,
}

/// API-safe fixed carrier health and learning outcome counter.
#[derive(Clone, Serialize)]
pub(crate) struct WebCarrierLearningCounter {
    /// Stable carrier token.
    pub(crate) carrier: &'static str,
    /// Terminal health or learning publication token.
    pub(crate) outcome: &'static str,
    /// Process-lifetime event count.
    pub(crate) total: u64,
}

impl WebTelemetry {
    /// Records why learning did or did not affect one successful selection.
    pub(crate) fn record_carrier_selection(
        &self,
        carrier: WebCarrier,
        disposition: WebCarrierSelectionDisposition,
    ) {
        self.carrier_selections[selection_index(carrier, disposition)]
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Returns one fixed carrier selection counter.
    pub(crate) fn carrier_selection_total(
        &self,
        carrier: WebCarrier,
        disposition: WebCarrierSelectionDisposition,
    ) -> u64 {
        self.carrier_selections[selection_index(carrier, disposition)].load(Ordering::Relaxed)
    }

    /// Captures the complete carrier selection counter set.
    pub(crate) fn carrier_selection_counters(&self) -> Vec<WebCarrierSelectionCounter> {
        WebCarrier::ALL
            .into_iter()
            .flat_map(|carrier| {
                WebCarrierSelectionDisposition::ALL
                    .into_iter()
                    .map(move |disposition| WebCarrierSelectionCounter {
                        carrier: carrier.as_str(),
                        disposition: disposition.as_str(),
                        total: self.carrier_selection_total(carrier, disposition),
                    })
            })
            .collect()
    }

    /// Records one canonical failure reported for an authenticated chain.
    pub(crate) fn record_carrier_failure(
        &self,
        carrier: WebCarrier,
        phase: WebCarrierFailurePhase,
        reason: CarrierFailure,
    ) {
        self.carrier_failures[failure_index(carrier, phase, reason)]
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Returns one fixed client-reported carrier failure counter.
    pub(crate) fn carrier_failure_total(
        &self,
        carrier: WebCarrier,
        phase: WebCarrierFailurePhase,
        reason: CarrierFailure,
    ) -> u64 {
        self.carrier_failures[failure_index(carrier, phase, reason)].load(Ordering::Relaxed)
    }

    /// Captures the complete client-reported carrier failure counter set.
    pub(crate) fn carrier_failure_counters(&self) -> Vec<WebCarrierFailureCounter> {
        WebCarrier::ALL
            .into_iter()
            .flat_map(|carrier| {
                WebCarrierFailurePhase::ALL
                    .into_iter()
                    .flat_map(move |phase| {
                        CarrierFailure::ALL.into_iter().map(move |reason| {
                            WebCarrierFailureCounter {
                                carrier: carrier.as_str(),
                                phase: phase.as_str(),
                                reason: reason.as_str(),
                                total: self.carrier_failure_total(carrier, phase, reason),
                            }
                        })
                    })
            })
            .collect()
    }

    /// Records one terminal health or evidence publication result.
    pub(crate) fn record_carrier_learning(
        &self,
        carrier: WebCarrier,
        outcome: WebCarrierLearningOutcome,
    ) {
        self.carrier_learning_outcomes[learning_index(carrier, outcome)]
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Returns one fixed health and learning outcome counter.
    pub(crate) fn carrier_learning_total(
        &self,
        carrier: WebCarrier,
        outcome: WebCarrierLearningOutcome,
    ) -> u64 {
        self.carrier_learning_outcomes[learning_index(carrier, outcome)].load(Ordering::Relaxed)
    }

    /// Captures the complete health and learning outcome counter set.
    pub(crate) fn carrier_learning_counters(&self) -> Vec<WebCarrierLearningCounter> {
        WebCarrier::ALL
            .into_iter()
            .flat_map(|carrier| {
                WebCarrierLearningOutcome::ALL
                    .into_iter()
                    .map(move |outcome| WebCarrierLearningCounter {
                        carrier: carrier.as_str(),
                        outcome: outcome.as_str(),
                        total: self.carrier_learning_total(carrier, outcome),
                    })
            })
            .collect()
    }
}

const fn selection_index(
    carrier: WebCarrier,
    disposition: WebCarrierSelectionDisposition,
) -> usize {
    carrier.index() * WebCarrierSelectionDisposition::ALL.len() + disposition as usize
}

const fn failure_index(
    carrier: WebCarrier,
    phase: WebCarrierFailurePhase,
    reason: CarrierFailure,
) -> usize {
    (carrier.index() * WebCarrierFailurePhase::ALL.len() + phase as usize)
        * CarrierFailure::ALL.len()
        + reason.index()
}

const fn learning_index(carrier: WebCarrier, outcome: WebCarrierLearningOutcome) -> usize {
    carrier.index() * WebCarrierLearningOutcome::ALL.len() + outcome as usize
}
