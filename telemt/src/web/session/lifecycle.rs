use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use super::{DeferredSessionEffects, WebSession};

/// Stable terminal cause assigned by the first session-close winner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub(crate) enum SessionCloseReason {
    /// An authenticated client explicitly deleted its current session.
    ClientDelete,
    /// A surviving bridge replaced an unreachable carrier incarnation.
    BridgeRecovery,
    /// No validated peer operation arrived within the frozen reconnect grace.
    PeerIdle,
    /// Automatic carrier negotiation exhausted its absolute deadline.
    NegotiationTimeout,
    /// A successful negotiation replacement retired this incarnation.
    CarrierSuperseded,
    /// Authenticated carrier framing or sequencing violated the protocol.
    Protocol,
    /// Mandatory bounded control state could not be retained.
    Backpressure,
    /// A committed WebSocket carrier ended.
    WebSocketEnded,
    /// An authenticated control-plane request selected this session.
    ApiClose,
    /// Process user authority revoked or replaced the authenticated credential.
    UserDisabled,
    /// A graceful operator drain reached its force-close deadline.
    OperatorForce,
    /// Terminal process shutdown closed all remaining sessions.
    RuntimeShutdown,
}

impl SessionCloseReason {
    /// Complete fixed reason set in stable API and metric order.
    pub(crate) const ALL: [Self; 12] = [
        Self::ClientDelete,
        Self::BridgeRecovery,
        Self::PeerIdle,
        Self::NegotiationTimeout,
        Self::CarrierSuperseded,
        Self::Protocol,
        Self::Backpressure,
        Self::WebSocketEnded,
        Self::ApiClose,
        Self::UserDisabled,
        Self::OperatorForce,
        Self::RuntimeShutdown,
    ];

    /// Returns the stable API, trace, and Prometheus token.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::ClientDelete => "client_delete",
            Self::BridgeRecovery => "bridge_recovery",
            Self::PeerIdle => "peer_idle",
            Self::NegotiationTimeout => "negotiation_timeout",
            Self::CarrierSuperseded => "carrier_superseded",
            Self::Protocol => "protocol",
            Self::Backpressure => "backpressure",
            Self::WebSocketEnded => "websocket_ended",
            Self::ApiClose => "api_close",
            Self::UserDisabled => "user_disabled",
            Self::OperatorForce => "operator_force",
            Self::RuntimeShutdown => "runtime_shutdown",
        }
    }
}

/// Result of one first-writer-wins close request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SessionCloseOutcome {
    /// This caller closed the session synchronously.
    Closed,
    /// This caller owns a close deferred behind carrier replacement.
    Deferred,
    /// An earlier caller already owns or completed session closure.
    AlreadyClosing,
}

impl SessionCloseOutcome {
    /// Returns whether this caller won the terminal cause.
    pub(crate) const fn accepted(self) -> bool {
        !matches!(self, Self::AlreadyClosing)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum SessionNegotiationPhase {
    Uncommitted,
    Replacing,
    Committed,
    Superseded,
}

struct ReleasedQueues {
    data_bytes: usize,
    data_items: usize,
    control_bytes: usize,
    control_items: usize,
    closed_before_health: bool,
    recovery_closed_before_commit: bool,
    reason: SessionCloseReason,
    peer_gap: Duration,
    effects: DeferredSessionEffects,
}

/// Deferred queue release after manager publication linearizes a supersede.
#[must_use]
pub(crate) struct CarrierSupersedeCompletion<'a> {
    session: &'a WebSession,
    released: ReleasedQueues,
}

impl CarrierSupersedeCompletion<'_> {
    /// Releases process budgets and signals cancellation after manager locks are dropped.
    pub(crate) fn finish(self) {
        self.session.finish_close(self.released);
    }
}

impl WebSession {
    /// Closes a bearer as soon as its process-owned user registration is revoked.
    pub(crate) fn close_if_cancelled(&self) -> bool {
        if !self.cancel.is_cancelled() {
            return false;
        }
        self.close(SessionCloseReason::UserDisabled);
        true
    }

    /// Closes carrier state while relay tasks retain their admission until exit.
    pub(crate) fn close(&self, reason: SessionCloseReason) -> SessionCloseOutcome {
        let effects = DeferredSessionEffects::new();
        let mut state = self.state.lock();
        if state.closed || state.close_requested.is_some() {
            return SessionCloseOutcome::AlreadyClosing;
        }
        if state.negotiation_phase == SessionNegotiationPhase::Replacing {
            state.close_requested = Some(reason);
            return SessionCloseOutcome::Deferred;
        }
        let released = self.release_on_close_locked(&mut state, reason, effects);
        drop(state);
        self.finish_close(released);
        SessionCloseOutcome::Closed
    }

    /// Atomically prevents first-frame commit while one successor is prepared.
    pub(crate) fn begin_carrier_supersede(&self) -> bool {
        let mut state = self.state.lock();
        if state.closed || state.close_requested.is_some() {
            return false;
        }
        match state.negotiation_phase {
            SessionNegotiationPhase::Uncommitted => {
                state.negotiation_phase = SessionNegotiationPhase::Replacing;
                true
            }
            SessionNegotiationPhase::Replacing
            | SessionNegotiationPhase::Committed
            | SessionNegotiationPhase::Superseded => false,
        }
    }

    /// Restores an uncommitted attempt after successor admission failed.
    pub(crate) fn cancel_carrier_supersede(&self) {
        let effects = DeferredSessionEffects::new();
        let mut state = self.state.lock();
        if !state.closed && state.negotiation_phase == SessionNegotiationPhase::Replacing {
            state.negotiation_phase = SessionNegotiationPhase::Uncommitted;
        }
        let Some(reason) = state.close_requested.filter(|_| !state.closed) else {
            return;
        };
        let released = self.release_on_close_locked(&mut state, reason, effects);
        drop(state);
        self.finish_close(released);
    }

    /// Linearizes manager publication against close requests on the old token.
    pub(crate) fn prepare_carrier_supersede(&self) -> Option<CarrierSupersedeCompletion<'_>> {
        let effects = DeferredSessionEffects::new();
        let mut state = self.state.lock();
        if state.closed
            || state.negotiation_phase != SessionNegotiationPhase::Replacing
            || state.close_requested.is_some()
        {
            return None;
        }
        let released = self.release_on_close_locked(
            &mut state,
            SessionCloseReason::CarrierSuperseded,
            effects,
        );
        Some(CarrierSupersedeCompletion {
            session: self,
            released,
        })
    }

    /// Waits for all logical-stream tasks after admission has closed.
    pub(crate) async fn wait(&self) {
        loop {
            let notified = self.tasks_done.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.tasks_live.load(Ordering::Acquire) == 0 {
                return;
            }
            notified.await;
        }
    }

    /// Waits until registry removal and close telemetry have completed.
    pub(crate) async fn wait_close_complete(&self) {
        loop {
            let notified = self.close_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.close_complete.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }

    /// Returns the current number of registered logical-stream tasks.
    pub(crate) fn tasks_live(&self) -> usize {
        self.tasks_live.load(Ordering::Acquire)
    }

    /// Atomically closes a session only when reconnect grace is still due.
    pub(crate) fn close_if_due(&self, now: Instant) -> bool {
        if self.close_if_cancelled() {
            return true;
        }
        let healthy = {
            let mut state = self.state.lock();
            self.carrier_health_ready_locked(&mut state, now)
        };
        if let Some(claim) = healthy {
            self.finish_carrier_health(claim);
        }
        let Some(released) = self.begin_idle_close(now) else {
            return false;
        };
        self.finish_close(released);
        true
    }

    fn begin_idle_close(&self, now: Instant) -> Option<ReleasedQueues> {
        let effects = DeferredSessionEffects::new();
        let mut state = self.state.lock();
        if state.closed || state.close_requested.is_some() {
            return None;
        }
        if state.negotiation_phase == SessionNegotiationPhase::Replacing
            || state.activity.peer_idle(now)
                < Duration::from_secs(self.timeouts.reconnect_grace_secs)
        {
            return None;
        }
        Some(self.release_on_close_locked(&mut state, SessionCloseReason::PeerIdle, effects))
    }

    fn release_on_close_locked(
        &self,
        state: &mut super::SessionState,
        reason: SessionCloseReason,
        mut effects: DeferredSessionEffects,
    ) -> ReleasedQueues {
        let peer_gap = state.activity.peer_idle(Instant::now());
        let closed_before_health = self.automatic_carrier
            && state.negotiation_phase == SessionNegotiationPhase::Committed
            && self.reject_carrier_health_on_close();
        let recovery_closed_before_commit = self.recovery && !state.recovery_committed;
        state.close_requested = Some(reason);
        state.closed = true;
        for notify in state.conveyor.clear() {
            effects.notify(notify);
        }
        if reason == SessionCloseReason::CarrierSuperseded {
            state.negotiation_phase = SessionNegotiationPhase::Superseded;
        }
        for stream in state.streams.values_mut() {
            if let Some(waker) = stream.read_waker.take() {
                effects.wake(waker);
            }
            if let Some(waker) = stream.write_waker.take() {
                effects.wake(waker);
            }
        }
        state.streams.clear();
        state.pending_frames.clear();
        state.pending_windows.clear();
        if let Some(batch) = state.unacked.take() {
            batch.lease.detach();
            self.release_local_locked(state, batch.data_bytes, batch.data_items, false);
            self.release_local_locked(state, batch.control_bytes, batch.control_items, true);
            effects.retain_batch(batch);
        }
        let mut lane_data_bytes = 0usize;
        let mut lane_data_items = 0usize;
        let mut lane_control_bytes = 0usize;
        let mut lane_control_items = 0usize;
        for lane in state.carrier_lanes.values_mut() {
            effects.notify(std::sync::Arc::clone(&lane.notify));
            if let Some(batch) = lane.unacked.take() {
                batch.lease.detach();
                lane_data_bytes = lane_data_bytes.saturating_add(batch.data_bytes);
                lane_data_items = lane_data_items.saturating_add(batch.data_items);
                lane_control_bytes = lane_control_bytes.saturating_add(batch.control_bytes);
                lane_control_items = lane_control_items.saturating_add(batch.control_items);
                effects.retain_batch(batch);
            }
        }
        self.release_local_locked(state, lane_data_bytes, lane_data_items, false);
        self.release_local_locked(state, lane_control_bytes, lane_control_items, true);
        state.carrier_lanes.clear();
        let control_bytes = state.pending_control_bytes;
        let control_items = state.pending_control_items;
        let data_bytes = state.pending_bytes.saturating_sub(control_bytes);
        let data_items = state.pending_items.saturating_sub(control_items);
        state.pending_bytes = 0;
        state.pending_items = 0;
        state.pending_control_bytes = 0;
        state.pending_control_items = 0;
        ReleasedQueues {
            data_bytes,
            data_items,
            control_bytes,
            control_items,
            closed_before_health,
            recovery_closed_before_commit,
            reason,
            peer_gap,
            effects,
        }
    }

    fn finish_close(&self, mut released: ReleasedQueues) {
        let manager = self.manager.upgrade();
        if let Some(manager) = &manager {
            if released.closed_before_health {
                manager.telemetry().record_carrier_learning(
                    self.selected_carrier,
                    crate::web::telemetry::WebCarrierLearningOutcome::ClosedBeforeHealth,
                );
            }
            if released.recovery_closed_before_commit {
                manager.telemetry().record_bridge_recovery(
                    crate::web::telemetry::WebBridgeRecoveryEvent::ClosedBeforeCommit,
                );
            }
            released.effects.notify(manager.release_pending_quiet(
                self.profile_key,
                released.data_bytes,
                released.data_items,
                false,
            ));
            released.effects.notify(manager.release_pending_quiet(
                self.profile_key,
                released.control_bytes,
                released.control_items,
                true,
            ));
        }
        released.effects.finish();
        self.cancel.cancel();
        if self.carrier().is_multiplexed() {
            self.down_notify.notify_waiters();
        }
        if self.carrier().uses_lanes() {
            self.lane_open_notify.notify_waiters();
        }
        if !self.finished.swap(true, Ordering::AcqRel) {
            if let Some(manager) = &manager {
                manager.trace().record_lifecycle_with_context(
                    None,
                    Some(self.client_ip),
                    self.trace_identity(),
                    crate::web::trace::TraceLifecycleEvent::SessionClosed,
                    None,
                    Some(released.reason.as_str()),
                    crate::web::trace::TraceLifecycleContext {
                        peer_gap_ms: Some(
                            released.peer_gap.as_millis().min(u128::from(u64::MAX)) as u64
                        ),
                        predecessor_session_id: None,
                    },
                );
            }
            if released.reason != SessionCloseReason::CarrierSuperseded
                && let Some(manager) = manager
            {
                manager.session_finished(
                    self.token_hash,
                    self.client_ip,
                    self.profile_key,
                    &self.profile.host,
                    Duration::from_secs(self.timeouts.bootstrap_lifetime_secs),
                    released.reason,
                );
            }
            self.close_complete.store(true, Ordering::Release);
            self.close_notify.notify_waiters();
        }
    }
}
