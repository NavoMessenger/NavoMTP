use std::time::{Duration, Instant};

use super::{SessionState, WebSession};
use crate::web::telemetry::WebSessionLifecycleObservation;

/// Session-local activity clocks with distinct lease and diagnostic authority.
pub(super) struct SessionActivity {
    last_peer: Instant,
    last_progress: Instant,
}

impl WebSession {
    /// Refreshes the authenticated peer lease and records only threshold-crossing gaps.
    pub(super) fn touch_peer_locked(
        &self,
        state: &mut SessionState,
        now: Instant,
        observation: WebSessionLifecycleObservation,
    ) {
        let gap = state.activity.touch_peer(now);
        if gap >= Duration::from_secs(self.timeouts.reconnect_grace_secs)
            && let Some(manager) = self.manager.upgrade()
        {
            manager
                .telemetry()
                .record_session_observation(self.carrier(), observation);
        }
    }

    /// Records one valid WebSocket control message as authenticated peer activity.
    pub(crate) fn record_websocket_peer_activity(&self) -> bool {
        let mut state = self.state.lock();
        if state.closed {
            return false;
        }
        self.touch_peer_locked(
            &mut state,
            Instant::now(),
            WebSessionLifecycleObservation::WebSocketActivityAfterGap,
        );
        true
    }
}

impl SessionActivity {
    /// Starts both activity clocks at the same session creation instant.
    pub(super) fn new(now: Instant) -> Self {
        Self {
            last_peer: now,
            last_progress: now,
        }
    }

    /// Records one validated peer operation and returns the preceding peer gap.
    pub(super) fn touch_peer(&mut self, now: Instant) -> Duration {
        let gap = now.saturating_duration_since(self.last_peer);
        self.last_peer = now;
        self.last_progress = now;
        gap
    }

    /// Records server-side carrier progress without extending the peer lease.
    pub(super) fn touch_progress(&mut self, now: Instant) {
        self.last_progress = now;
    }

    /// Returns elapsed time since the latest validated peer operation.
    pub(super) fn peer_idle(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.last_peer)
    }

    /// Returns elapsed time since the latest carrier-side progress.
    pub(super) fn progress_idle(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.last_progress)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn progress_does_not_extend_the_authenticated_peer_lease() {
        let started = Instant::now();
        let mut activity = SessionActivity::new(started);
        activity.touch_progress(started + Duration::from_secs(4));

        assert_eq!(
            activity.peer_idle(started + Duration::from_secs(9)),
            Duration::from_secs(9)
        );
        assert_eq!(
            activity.progress_idle(started + Duration::from_secs(9)),
            Duration::from_secs(5)
        );
        assert_eq!(
            activity.touch_peer(started + Duration::from_secs(9)),
            Duration::from_secs(9)
        );
        assert_eq!(
            activity.peer_idle(started + Duration::from_secs(10)),
            Duration::from_secs(1)
        );
    }
}
