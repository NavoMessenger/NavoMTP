use std::time::{Duration, Instant};

use crate::config::WebCarrierNegotiationAggressiveness;

use super::{CarrierLearning, DetachedCarrierEvidence, LearningPolicy};

/// Exact result of matching one request snapshot to the applied learning policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::web::manager) enum CarrierLearningEpoch {
    /// The request may use the returned evidence epoch.
    Ready(u64),
    /// The process store has not applied this exact generation and policy yet.
    Pending,
    /// The exact policy is active but its monotonic epoch space is exhausted.
    Exhausted,
}

/// Terminal result of applying one complete attempt chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::web::manager) enum CarrierLearningRecordOutcome {
    /// Every eligible evidence key received the complete sample.
    Recorded,
    /// The effective learning policy does not accept evidence.
    PolicyDisabled,
    /// The result belongs to a superseded or exhausted epoch.
    StaleEpoch,
    /// The bounded store cannot fit all evidence keys atomically.
    CapacityRejected,
    /// A unique insertion sequence cannot be assigned to every new key.
    SequenceExhausted,
}

/// Bounded control-plane summary of carrier-learning state.
#[derive(Clone, Copy)]
pub(crate) struct CarrierLearningStatus {
    /// Whether outcome learning is active in the effective policy.
    pub(crate) enabled: bool,
    /// Effective evidence thresholds.
    pub(crate) aggressiveness: WebCarrierNegotiationAggressiveness,
    /// Generation whose policy is applied to the process-owned store.
    pub(crate) policy_generation: Option<u64>,
    /// Current evidence epoch, or none after counter exhaustion.
    pub(crate) epoch: Option<u64>,
    /// Retained evidence entries.
    pub(crate) entries: usize,
    /// Restart-owned evidence ceiling.
    pub(crate) capacity: usize,
    /// Effective evidence lifetime.
    pub(crate) lifetime_secs: u64,
    /// Effective post-commit health observation window.
    pub(crate) health_secs: u64,
    /// Monotonic age of the current semantic policy epoch.
    pub(crate) age_ms: u64,
}

/// Result of one epoch-fenced learning reset.
#[derive(Clone, Copy)]
pub(crate) struct CarrierLearningResetOutcome {
    /// Evidence entries detached by the reset.
    pub(crate) entries_cleared: usize,
    /// New epoch fencing pre-reset outcomes.
    pub(crate) epoch: u64,
}

impl CarrierLearning {
    pub(super) fn status(&self, now: Instant) -> CarrierLearningStatus {
        let policy = self.policy.unwrap_or(LearningPolicy {
            enabled: false,
            aggressiveness: WebCarrierNegotiationAggressiveness::Conservative,
            lifetime: Duration::ZERO,
            health_window: Duration::ZERO,
        });
        CarrierLearningStatus {
            enabled: policy.enabled,
            aggressiveness: policy.aggressiveness,
            policy_generation: self.applied_generation,
            epoch: self.epoch,
            entries: self.entries.len(),
            capacity: self.capacity,
            lifetime_secs: policy.lifetime.as_secs(),
            health_secs: policy.health_window.as_secs(),
            age_ms: millis(now.saturating_duration_since(self.policy_started_at)),
        }
    }
}

impl super::super::WebProcessRuntime {
    /// Captures learning state without waiting for a contended evidence lock.
    pub(crate) fn try_carrier_learning_status(&self) -> Option<CarrierLearningStatus> {
        self.learning
            .try_lock()
            .map(|learning| learning.status(Instant::now()))
    }

    /// Clears all evidence under a new epoch without changing the active policy.
    pub(crate) fn reset_carrier_learning(
        &self,
    ) -> Result<CarrierLearningResetOutcome, super::super::ManagerError> {
        let control = self
            .control_mutation_guard()
            .map_err(|_| super::super::ManagerError::Closed)?;
        let (outcome, detached) = {
            let mut learning = self.learning.lock();
            let epoch = learning
                .epoch
                .and_then(|epoch| epoch.checked_add(1))
                .ok_or(super::super::ManagerError::Closed)?;
            learning.epoch = Some(epoch);
            learning.insertion_sequence = 1;
            learning.policy_started_at = Instant::now();
            let entries = std::mem::take(&mut learning.entries);
            let entries_cleared = entries.len();
            let detached = DetachedCarrierEvidence {
                entries,
                insertion_order: std::mem::take(&mut learning.insertion_order),
            };
            (
                CarrierLearningResetOutcome {
                    entries_cleared,
                    epoch,
                },
                detached,
            )
        };
        drop(control);
        drop(detached);
        Ok(outcome)
    }
}

impl Drop for DetachedCarrierEvidence {
    fn drop(&mut self) {
        self.entries.clear();
        self.insertion_order.clear();
    }
}

fn millis(duration: Duration) -> u64 {
    duration.as_millis().min(u128::from(u64::MAX)) as u64
}
