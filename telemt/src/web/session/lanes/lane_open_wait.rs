use std::time::{Duration, Instant};

use tokio::sync::OwnedSemaphorePermit;

use super::WebSession;
use crate::web::manager::ManagerError;
use crate::web::session::SessionCloseReason;
use crate::web::telemetry::WebSessionLifecycleObservation;

impl WebSession {
    /// Waits for a non-control lane to become observable within the bounded admission budget.
    pub(super) async fn wait_for_lane_open(
        &self,
        lane_id: u32,
        cursor: u64,
    ) -> Result<bool, ManagerError> {
        if self.close_if_cancelled() {
            return Err(ManagerError::Closed);
        }
        let wait = {
            let mut state = self.state.lock();
            if state.closed || self.cancel.is_cancelled() {
                drop(state);
                self.close_if_cancelled();
                return Err(ManagerError::Closed);
            }
            if state.carrier_lanes.contains_key(&lane_id) {
                return Ok(true);
            }
            if cursor != 0 || lane_id == 0 {
                drop(state);
                self.close(SessionCloseReason::Protocol);
                return Err(ManagerError::Protocol);
            }
            if state.closed_streams.contains(&lane_id)
                || state.closing_streams.contains_key(&lane_id)
            {
                return Ok(true);
            }
            if state.lane_open_waits >= self.limits.max_lane_open_waits_per_session {
                return Err(ManagerError::Limit);
            }
            let Some(manager) = self.manager.upgrade() else {
                return Err(ManagerError::Closed);
            };
            let Some(auxiliary) = manager.try_lane_poll(true) else {
                return Err(ManagerError::Limit);
            };
            state.lane_open_waits += 1;
            let observation = WebSessionLifecycleObservation::HttpActivityAfterGap;
            self.touch_peer_locked(&mut state, Instant::now(), observation);
            LaneOpenWaitGuard {
                session: self,
                _auxiliary: auxiliary,
            }
        };
        let deadline = Duration::from_secs(self.timeouts.lane_open_wait_secs);
        let opened = tokio::time::timeout(deadline, async {
            loop {
                let notified = self.lane_open_notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                {
                    let state = self.state.lock();
                    if state.closed || self.cancel.is_cancelled() {
                        drop(state);
                        self.close_if_cancelled();
                        return Err(ManagerError::Closed);
                    }
                    if state.carrier_lanes.contains_key(&lane_id)
                        || state.closed_streams.contains(&lane_id)
                        || state.closing_streams.contains_key(&lane_id)
                    {
                        return Ok(true);
                    }
                }
                notified.await;
            }
        });
        let opened = tokio::select! {
            biased;
            _ = self.cancel.cancelled() => {
                drop(wait);
                self.close_if_cancelled();
                return Err(ManagerError::Closed);
            }
            opened = opened => opened,
        };
        drop(wait);
        match opened {
            Ok(result) => result,
            Err(_) => {
                let state = self.state.lock();
                if state.closed || self.cancel.is_cancelled() {
                    drop(state);
                    self.close_if_cancelled();
                    Err(ManagerError::Closed)
                } else {
                    Ok(state.carrier_lanes.contains_key(&lane_id)
                        || state.closed_streams.contains(&lane_id)
                        || state.closing_streams.contains_key(&lane_id))
                }
            }
        }
    }
}

struct LaneOpenWaitGuard<'a> {
    session: &'a WebSession,
    _auxiliary: OwnedSemaphorePermit,
}

impl Drop for LaneOpenWaitGuard<'_> {
    fn drop(&mut self) {
        let mut state = self.session.state.lock();
        state.lane_open_waits = state.lane_open_waits.saturating_sub(1);
    }
}
