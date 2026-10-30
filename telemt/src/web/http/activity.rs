use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use hyper::body::{Body, Frame, SizeHint};
use parking_lot::Mutex;
use tokio::time::Instant;

use super::{BoxError, HttpBody};
use crate::web::trace::{HttpTraceExchange, TraceBodyState, TraceDirection};

#[derive(Clone, Copy)]
struct DeadlineSlot {
    id: u64,
    deadline: Instant,
}

struct RequestSlot {
    id: u64,
    deadline: Option<DeadlineSlot>,
}

struct UpgradeSlot {
    request_id: u64,
    deadline: DeadlineSlot,
}

struct ActivityState {
    last_progress: Instant,
    next_request_id: u64,
    next_deadline_id: u64,
    request: Option<RequestSlot>,
    upgrade: Option<UpgradeSlot>,
    failed: bool,
}

/// Shared liveness state for one accepted HTTP connection.
#[derive(Clone)]
pub(super) struct ConnectionActivity {
    state: Arc<Mutex<ActivityState>>,
}

impl ConnectionActivity {
    /// Creates activity state at the connection acceptance boundary.
    pub(super) fn new() -> Self {
        Self {
            state: Arc::new(Mutex::new(ActivityState {
                last_progress: Instant::now(),
                next_request_id: 1,
                next_deadline_id: 1,
                request: None,
                upgrade: None,
                failed: false,
            })),
        }
    }

    /// Returns whether the connection has no protected operation or recent progress.
    pub(super) fn should_close(&self, now: Instant, idle: Duration) -> bool {
        let state = self.state.lock();
        if state.failed {
            return true;
        }
        let request_deadline = state
            .request
            .as_ref()
            .and_then(|request| request.deadline)
            .map(|deadline| deadline.deadline);
        let upgrade_deadline = state
            .upgrade
            .as_ref()
            .map(|upgrade| upgrade.deadline.deadline);
        let protected_until = request_deadline.into_iter().chain(upgrade_deadline).max();
        let idle_since = protected_until
            .filter(|deadline| *deadline > state.last_progress)
            .unwrap_or(state.last_progress);
        now.saturating_duration_since(idle_since) >= idle
    }

    fn fail(&self) {
        self.state.lock().failed = true;
    }
}

/// Cloneable authority for protecting one request's explicitly bounded awaits.
#[derive(Clone)]
pub(super) struct RequestDeadlineHandle {
    activity: ConnectionActivity,
    request_id: u64,
}

impl RequestDeadlineHandle {
    /// Protects the current bounded request operation until its absolute deadline.
    pub(super) fn lease_until(&self, deadline: Instant) -> Option<RequestDeadlineLease> {
        let now = Instant::now();
        let mut state = self.activity.state.lock();
        if state.failed {
            return None;
        }
        let Some(current) = state.request.as_ref() else {
            state.failed = true;
            return None;
        };
        if current.id != self.request_id
            || current
                .deadline
                .is_some_and(|active| now <= active.deadline)
        {
            state.failed = true;
            return None;
        }
        let id = state.next_deadline_id;
        let Some(next) = id.checked_add(1) else {
            state.failed = true;
            return None;
        };
        state.next_deadline_id = next;
        let Some(current) = state.request.as_mut() else {
            state.failed = true;
            return None;
        };
        current.deadline = Some(DeadlineSlot { id, deadline });
        Some(RequestDeadlineLease {
            handle: self.clone(),
            deadline_id: id,
        })
    }

    /// Protects the current bounded request operation for one checked duration.
    pub(super) fn lease_for(&self, duration: Duration) -> Option<RequestDeadlineLease> {
        let Some(deadline) = Instant::now().checked_add(duration) else {
            self.activity.fail();
            return None;
        };
        self.lease_until(deadline)
    }

    /// Transfers idle protection to a pending Hyper upgrade operation.
    pub(super) fn upgrade_until(&self, deadline: Instant) -> Option<UpgradeDeadlineLease> {
        let now = Instant::now();
        let mut state = self.activity.state.lock();
        if state.failed
            || state
                .request
                .as_ref()
                .is_none_or(|request| request.id != self.request_id)
            || state
                .upgrade
                .as_ref()
                .is_some_and(|upgrade| now <= upgrade.deadline.deadline)
        {
            state.failed = true;
            return None;
        }
        let id = state.next_deadline_id;
        let Some(next) = id.checked_add(1) else {
            state.failed = true;
            return None;
        };
        state.next_deadline_id = next;
        state.upgrade = Some(UpgradeSlot {
            request_id: self.request_id,
            deadline: DeadlineSlot { id, deadline },
        });
        Some(UpgradeDeadlineLease {
            activity: self.activity.clone(),
            request_id: self.request_id,
            deadline_id: id,
            deadline,
        })
    }
}

/// Exact request-operation lease that cannot clear a newer deadline.
pub(super) struct RequestDeadlineLease {
    handle: RequestDeadlineHandle,
    deadline_id: u64,
}

impl Drop for RequestDeadlineLease {
    fn drop(&mut self) {
        let mut state = self.handle.activity.state.lock();
        let matches = state.request.as_ref().is_some_and(|request| {
            request.id == self.handle.request_id
                && request
                    .deadline
                    .is_some_and(|deadline| deadline.id == self.deadline_id)
        });
        if matches {
            if let Some(request) = state.request.as_mut() {
                request.deadline = None;
            }
            state.last_progress = Instant::now();
        }
    }
}

/// Exact pending-upgrade lease retained by the spawned upgrade future.
pub(super) struct UpgradeDeadlineLease {
    activity: ConnectionActivity,
    request_id: u64,
    deadline_id: u64,
    deadline: Instant,
}

impl UpgradeDeadlineLease {
    /// Returns the absolute deadline shared with the upgrade timeout.
    pub(super) fn deadline(&self) -> Instant {
        self.deadline
    }
}

impl Drop for UpgradeDeadlineLease {
    fn drop(&mut self) {
        let mut state = self.activity.state.lock();
        let matches = state.upgrade.as_ref().is_some_and(|upgrade| {
            upgrade.request_id == self.request_id && upgrade.deadline.id == self.deadline_id
        });
        if matches {
            state.upgrade = None;
            state.last_progress = Instant::now();
        }
    }
}

/// Request lifecycle guard that refreshes HTTP connection activity on completion.
pub(super) struct RequestActivity {
    handle: RequestDeadlineHandle,
}

impl RequestActivity {
    /// Starts activity accounting for one HTTP request.
    pub(super) fn begin(activity: ConnectionActivity) -> Option<Self> {
        let mut state = activity.state.lock();
        if state.failed || state.request.is_some() {
            state.failed = true;
            return None;
        }
        let id = state.next_request_id;
        let Some(next) = id.checked_add(1) else {
            state.failed = true;
            return None;
        };
        state.next_request_id = next;
        state.last_progress = Instant::now();
        state.request = Some(RequestSlot { id, deadline: None });
        drop(state);
        Some(Self {
            handle: RequestDeadlineHandle {
                activity,
                request_id: id,
            },
        })
    }

    /// Returns the authority copied into request extensions for bounded awaits.
    pub(super) fn deadline_handle(&self) -> RequestDeadlineHandle {
        self.handle.clone()
    }

    fn progress(&self) {
        self.handle.activity.state.lock().last_progress = Instant::now();
    }

    fn enter_response(&mut self) {
        let mut state = self.handle.activity.state.lock();
        if let Some(request) = state
            .request
            .as_mut()
            .filter(|request| request.id == self.handle.request_id)
        {
            request.deadline = None;
            state.last_progress = Instant::now();
        }
    }
}

impl Drop for RequestActivity {
    fn drop(&mut self) {
        let mut state = self.handle.activity.state.lock();
        if state
            .request
            .as_ref()
            .is_some_and(|request| request.id == self.handle.request_id)
        {
            state.request = None;
            state.last_progress = Instant::now();
        }
    }
}

/// Response body wrapper that refreshes activity while downstream data progresses.
pub(super) struct ActivityBody {
    inner: HttpBody,
    activity: RequestActivity,
    trace: Option<Arc<HttpTraceExchange>>,
    terminal: bool,
}

impl ActivityBody {
    /// Binds one response body to its request activity guard.
    pub(super) fn new(
        inner: HttpBody,
        mut activity: RequestActivity,
        trace: Option<Arc<HttpTraceExchange>>,
    ) -> Self {
        activity.enter_response();
        Self {
            inner,
            activity,
            trace,
            terminal: false,
        }
    }

    fn finish(&mut self, state: TraceBodyState) {
        if self.terminal {
            return;
        }
        self.terminal = true;
        if let Some(trace) = &self.trace {
            trace.body_finished(TraceDirection::Response, state);
        }
    }
}

impl Body for ActivityBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let result = Pin::new(&mut self.inner).poll_frame(context);
        match &result {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref()
                    && let Some(trace) = &self.trace
                {
                    trace.body_data(TraceDirection::Response, data);
                }
                if self.inner.is_end_stream() {
                    self.finish(TraceBodyState::Complete);
                }
            }
            Poll::Ready(Some(Err(_))) => self.finish(TraceBodyState::Error),
            Poll::Ready(None) => self.finish(TraceBodyState::Complete),
            Poll::Pending => {}
        }
        if result.is_ready() {
            self.activity.progress();
        }
        result
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for ActivityBody {
    fn drop(&mut self) {
        self.finish(TraceBodyState::Aborted);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_request_deadline_suspends_only_idle_expiry() {
        let activity = ConnectionActivity::new();
        let request = RequestActivity::begin(activity.clone()).unwrap();
        let now = Instant::now();
        let lease = request
            .deadline_handle()
            .lease_until(now + Duration::from_secs(5))
            .unwrap();

        assert!(!activity.should_close(now + Duration::from_secs(4), Duration::from_secs(1)));
        assert!(activity.should_close(now + Duration::from_secs(6), Duration::from_secs(1)));

        drop(lease);
        assert!(!activity.should_close(Instant::now(), Duration::from_secs(1)));
    }

    #[test]
    fn expired_operation_lease_gets_one_idle_interval_to_publish_its_result() {
        let activity = ConnectionActivity::new();
        let request = RequestActivity::begin(activity.clone()).unwrap();
        let now = Instant::now();
        let _lease = request
            .deadline_handle()
            .lease_until(now + Duration::from_secs(1))
            .unwrap();

        assert!(!activity.should_close(now + Duration::from_millis(1500), Duration::from_secs(1)));
        assert!(activity.should_close(now + Duration::from_secs(2), Duration::from_secs(1)));
    }

    #[test]
    fn stale_request_lease_cannot_clear_a_new_request_deadline() {
        let activity = ConnectionActivity::new();
        let request_a = RequestActivity::begin(activity.clone()).unwrap();
        let now = Instant::now();
        let lease_a = request_a
            .deadline_handle()
            .lease_until(now - Duration::from_secs(1))
            .unwrap();
        drop(request_a);
        let request_b = RequestActivity::begin(activity.clone()).unwrap();
        let _lease_b = request_b
            .deadline_handle()
            .lease_until(now + Duration::from_secs(5))
            .unwrap();

        drop(lease_a);

        assert!(!activity.should_close(now + Duration::from_secs(4), Duration::from_secs(1)));
    }

    #[test]
    fn stale_upgrade_lease_cannot_clear_its_replacement() {
        let activity = ConnectionActivity::new();
        let request = RequestActivity::begin(activity.clone()).unwrap();
        let handle = request.deadline_handle();
        let now = Instant::now();
        let lease_a = handle.upgrade_until(now - Duration::from_secs(1)).unwrap();
        let _lease_b = handle.upgrade_until(now + Duration::from_secs(5)).unwrap();

        drop(lease_a);

        assert!(!activity.should_close(now + Duration::from_secs(4), Duration::from_secs(1)));
    }
}
