use std::time::Duration;
use tokio::time::Instant;

/// Durable intent exists even if a reinit returns before creating a pending generation.
pub(super) struct RetryObjective {
    /// Distinguishes separate external requests for the same endpoint revision.
    pub(super) id: u64,
    /// Exact endpoint snapshot to reconcile.
    pub(super) revision: u64,
    /// Coalesced external causes used for diagnostic logging.
    pub(super) triggers: u8,
    /// Completed failures; the count saturates but never terminates recovery.
    pub(super) attempt: usize,
    /// A missing deadline means the objective currently owns a running task.
    pub(super) deadline: Option<Instant>,
    ready_wake: Option<(u64, u64, u64)>,
}

impl RetryObjective {
    /// Creates retryable intent before any asynchronous attempt can fail.
    pub(super) fn new(id: u64, revision: u64, triggers: u8, delay: Duration) -> Self {
        Self {
            id,
            revision,
            triggers,
            attempt: 0,
            deadline: Some(Instant::now() + delay),
            ready_wake: None,
        }
    }

    /// Rejects completions from superseded objectives, including the same endpoint revision.
    pub(super) fn matches(&self, identity: (u64, u64)) -> bool {
        (self.id, self.revision) == identity
    }

    /// Measures backoff from completion and never caps the number of retry attempts.
    pub(super) fn failed(&mut self, delay: Duration) {
        self.attempt = self.attempt.saturating_add(1);
        self.deadline = Some(Instant::now() + delay);
    }

    /// Accelerates once per observed ready tuple without allowing an epoch storm to spin.
    pub(super) fn ready(&mut self, key: (u64, u64, u64)) {
        if self.ready_wake != Some(key) {
            self.ready_wake = Some(key);
            self.deadline = Some(Instant::now());
        }
    }

    /// Re-arms acceleration only after a coherent observation of lost readiness.
    pub(super) fn not_ready(&mut self) {
        self.ready_wake = None;
    }
}
