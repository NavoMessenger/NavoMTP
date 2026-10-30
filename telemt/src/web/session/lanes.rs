use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{BufMut, Bytes, BytesMut};

use super::lane_downlink::take_lane_down_batch;
use super::{
    CarrierLaneIdentity, DeferredSessionEffects, PendingClass, PollResult, QUEUE_ITEM_COST,
    QueuedFrame, SessionCloseReason, SessionState, WebSession, remember_closed,
};
use crate::web::frame::{self, FrameType};
use crate::web::manager::ManagerError;
use crate::web::telemetry::WebSessionLifecycleObservation;

// Bounded lane-open admission and cancellation-safe wait lifecycle.
mod lane_open_wait;

impl WebSession {
    /// Polls one lane with independent cursor replay and newest-poll-wins semantics.
    pub(crate) async fn poll_down_lane(
        &self,
        lane_id: u32,
        cursor: u64,
    ) -> Result<PollResult, ManagerError> {
        self.poll_down_lane_inner(lane_id, None, cursor).await
    }

    /// Polls only the exact lane incarnation owned by one WebSocket driver.
    pub(crate) async fn poll_down_websocket_lane(
        &self,
        lane: CarrierLaneIdentity,
        cursor: u64,
    ) -> Result<PollResult, ManagerError> {
        self.poll_down_lane_inner(lane.lane_id, Some(lane.instance), cursor)
            .await
    }

    async fn poll_down_lane_inner(
        &self,
        lane_id: u32,
        expected_instance: Option<u64>,
        cursor: u64,
    ) -> Result<PollResult, ManagerError> {
        if !self.carrier().uses_lanes() || lane_id > frame::MAX_STREAM_ID {
            return Err(ManagerError::Protocol);
        }
        if self.close_if_cancelled() {
            return Err(ManagerError::Closed);
        }
        let lane_ready = if let Some(expected_instance) = expected_instance {
            let state = self.state.lock();
            if state.closed || self.cancel.is_cancelled() {
                drop(state);
                self.close_if_cancelled();
                return Err(ManagerError::Closed);
            }
            state
                .carrier_lanes
                .get(&lane_id)
                .is_some_and(|lane| lane.instance == expected_instance)
        } else {
            self.wait_for_lane_open(lane_id, cursor).await?
        };
        if !lane_ready {
            return Ok(PollResult {
                body: Bytes::new(),
                next_cursor: cursor,
                lane_closed: expected_instance.is_some(),
            });
        }
        let mut effects = DeferredSessionEffects::new();
        let (instance, epoch, notify, healthy) = {
            let mut state = self.state.lock();
            if state.closed || self.cancel.is_cancelled() {
                drop(state);
                self.close_if_cancelled();
                return Err(ManagerError::Closed);
            }
            let (acknowledged, replay) = {
                let Some(lane) = state.carrier_lanes.get_mut(&lane_id) else {
                    return Ok(PollResult {
                        body: Bytes::new(),
                        next_cursor: cursor,
                        lane_closed: true,
                    });
                };
                if expected_instance.is_some_and(|instance| lane.instance != instance) {
                    return Ok(PollResult {
                        body: Bytes::new(),
                        next_cursor: cursor,
                        lane_closed: true,
                    });
                }
                if let Some(unacked) = &lane.unacked {
                    if cursor == unacked.base_cursor {
                        (
                            None,
                            Some(PollResult {
                                body: unacked.body.clone(),
                                next_cursor: unacked.next_cursor,
                                lane_closed: false,
                            }),
                        )
                    } else if cursor != unacked.next_cursor {
                        drop(state);
                        self.close(SessionCloseReason::Protocol);
                        return Err(ManagerError::Protocol);
                    } else {
                        (lane.unacked.take(), None)
                    }
                } else {
                    if cursor != lane.down_cursor {
                        drop(state);
                        self.close(SessionCloseReason::Protocol);
                        return Err(ManagerError::Protocol);
                    }
                    (None, None)
                }
            };
            if let Some(result) = replay {
                if expected_instance.is_none() {
                    self.touch_peer_locked(
                        &mut state,
                        Instant::now(),
                        WebSessionLifecycleObservation::HttpActivityAfterGap,
                    );
                }
                return Ok(result);
            }
            if let Some(batch) = acknowledged {
                if let Some(lane) = state.carrier_lanes.get_mut(&lane_id) {
                    lane.pending_bytes = lane.pending_bytes.saturating_sub(batch.data_bytes);
                    lane.pending_items = lane.pending_items.saturating_sub(batch.data_items);
                }
                batch.lease.detach();
                self.release_local_locked(&mut state, batch.data_bytes, batch.data_items, false);
                self.release_local_locked(
                    &mut state,
                    batch.control_bytes,
                    batch.control_items,
                    true,
                );
                state.carrier_health_downlink |= batch.carrier_health_eligible;
                if batch.carrier_health_eligible {
                    state.carrier_health_activity_at = Some(Instant::now());
                }
                if let Some(stream) = state.streams.get_mut(&lane_id)
                    && let Some(waker) = stream.write_waker.take()
                {
                    effects.wake(waker);
                }
                effects.retain_batch(batch);
            }
            let Some(lane) = state.carrier_lanes.get_mut(&lane_id) else {
                drop(state);
                effects.finish();
                return Err(ManagerError::Protocol);
            };
            let Some(epoch) = lane.down_epoch.checked_add(1) else {
                drop(state);
                effects.finish();
                self.close(SessionCloseReason::Protocol);
                return Err(ManagerError::Protocol);
            };
            lane.down_epoch = epoch;
            let instance = lane.instance;
            let notify = Arc::clone(&lane.notify);
            if expected_instance.is_none() {
                self.touch_peer_locked(
                    &mut state,
                    Instant::now(),
                    WebSessionLifecycleObservation::HttpActivityAfterGap,
                );
            }
            let healthy = self.carrier_health_ready_locked(&mut state, Instant::now());
            (instance, epoch, notify, healthy)
        };
        effects.finish();
        if let Some(claim) = healthy {
            self.finish_carrier_health(claim);
        }
        notify.notify_waiters();

        let deadline = Duration::from_secs(self.timeouts.long_poll_secs);
        let poll = async {
            loop {
                let notified = notify.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                let mut effects = DeferredSessionEffects::new();
                {
                    let mut state = self.state.lock();
                    if state.closed || self.cancel.is_cancelled() {
                        drop(state);
                        self.close_if_cancelled();
                        return Err(ManagerError::Closed);
                    }
                    let carrier_health_eligible = lane_id != 0
                        && state.negotiation_phase == super::SessionNegotiationPhase::Committed;
                    let Some(lane) = state.carrier_lanes.get_mut(&lane_id) else {
                        return Ok(PollResult {
                            body: Bytes::new(),
                            next_cursor: cursor,
                            lane_closed: true,
                        });
                    };
                    if lane.instance != instance {
                        return Ok(PollResult {
                            body: Bytes::new(),
                            next_cursor: cursor,
                            lane_closed: true,
                        });
                    }
                    if lane.down_epoch != epoch {
                        return Ok(PollResult {
                            body: Bytes::new(),
                            next_cursor: cursor,
                            lane_closed: false,
                        });
                    }
                    if !lane.pending_frames.is_empty() {
                        let batch = match take_lane_down_batch(
                            self,
                            &self.limits,
                            lane,
                            &mut effects,
                            cursor,
                            carrier_health_eligible,
                        ) {
                            Ok(batch) => batch,
                            Err(ManagerError::Backpressure) => {
                                return Err(ManagerError::Backpressure);
                            }
                            Err(error) => {
                                drop(state);
                                self.close(SessionCloseReason::Protocol);
                                return Err(error);
                            }
                        };
                        let result = PollResult {
                            body: batch.body.clone(),
                            next_cursor: batch.next_cursor,
                            lane_closed: false,
                        };
                        if let Some(previous) = lane.unacked.replace(batch) {
                            effects.retain_batch(previous);
                        }
                        drop(state);
                        effects.finish();
                        if let Some(manager) = self.manager.upgrade() {
                            manager.record_down(result.body.len());
                        }
                        return Ok(result);
                    }
                    if lane_id != 0
                        && !state.streams.contains_key(&lane_id)
                        && state.closed_streams.contains(&lane_id)
                    {
                        return Ok(PollResult {
                            body: Bytes::new(),
                            next_cursor: cursor,
                            lane_closed: true,
                        });
                    }
                }
                notified.await;
            }
        };
        tokio::select! {
            biased;
            _ = self.cancel.cancelled() => {
                self.close_if_cancelled();
                Err(ManagerError::Closed)
            }
            result = tokio::time::timeout(deadline, poll) => match result {
                Ok(result) => result,
                Err(_) => {
                    if self.close_if_cancelled() {
                        return Err(ManagerError::Closed);
                    }
                    let mut state = self.state.lock();
                    if state.closed || self.cancel.is_cancelled() {
                        drop(state);
                        self.close_if_cancelled();
                        return Err(ManagerError::Closed);
                    }
                    if !state.carrier_lanes.contains_key(&lane_id) {
                        return Ok(PollResult {
                            body: Bytes::new(),
                            next_cursor: cursor,
                            lane_closed: true,
                        });
                    }
                    if lane_id != 0
                        && !state.streams.contains_key(&lane_id)
                        && state.closed_streams.contains(&lane_id)
                    {
                        return Ok(PollResult {
                            body: Bytes::new(),
                            next_cursor: cursor,
                            lane_closed: true,
                        });
                    }
                    if let Some(lane) = state.carrier_lanes.get(&lane_id) {
                        if lane.instance != instance {
                            return Ok(PollResult {
                                body: Bytes::new(),
                                next_cursor: cursor,
                                lane_closed: true,
                            });
                        }
                        if lane.down_epoch == epoch {
                            state.activity.touch_progress(Instant::now());
                        }
                    }
                    Ok(PollResult {
                        body: Bytes::new(),
                        next_cursor: cursor,
                        lane_closed: false,
                    })
                }
            }
        }
    }

    pub(super) fn queue_lane_frame_locked(
        &self,
        state: &mut SessionState,
        effects: &mut DeferredSessionEffects,
        frame_type: FrameType,
        stream_id: u32,
        payload: &[u8],
        control: bool,
    ) -> bool {
        if !state.carrier_lanes.contains_key(&stream_id) {
            return false;
        }
        if frame_type == FrameType::Window {
            let coalesced = state.carrier_lanes.get(&stream_id).and_then(|lane| {
                let index = lane.pending_windows.get(&stream_id).copied()?;
                let queued = lane.pending_frames.get(index)?;
                let previous = u32::from_be_bytes(
                    queued.encoded[frame::HEADER_BYTES..frame::HEADER_BYTES + 4]
                        .try_into()
                        .unwrap_or([0; 4]),
                );
                previous
                    .checked_add(frame::window_amount(payload).unwrap_or(0))
                    .map(|total| (index, total))
            });
            if let Some((index, total)) = coalesced
                && let Some(lane) = state.carrier_lanes.get_mut(&stream_id)
                && let Some(queued) = lane.pending_frames.get_mut(index)
            {
                queued.encoded[frame::HEADER_BYTES..frame::HEADER_BYTES + 4]
                    .copy_from_slice(&total.to_be_bytes());
                effects.notify(Arc::clone(&lane.notify));
                return true;
            }
        }
        let can_coalesce = frame_type == FrameType::Data
            && state
                .carrier_lanes
                .get(&stream_id)
                .and_then(|lane| lane.pending_frames.back())
                .is_some_and(|last| {
                    last.frame_type == FrameType::Data
                        && last.stream_id == stream_id
                        && last.encoded.len() - frame::HEADER_BYTES + payload.len()
                            <= self.limits.max_frame_payload_bytes
                });
        if can_coalesce {
            if state.carrier_lanes.get(&stream_id).is_none_or(|lane| {
                let resident = lane.resident.snapshot();
                payload.len() > self.limits.pending_bytes_per_lane
                    || lane.pending_bytes.saturating_add(resident.data_bytes)
                        > self
                            .limits
                            .pending_bytes_per_lane
                            .saturating_sub(payload.len())
            }) {
                return false;
            }
            if !self.reserve_locked(state, payload.len(), 0, PendingClass::Downlink) {
                return false;
            }
            let Some(lane) = state.carrier_lanes.get_mut(&stream_id) else {
                self.release_locked(state, effects, payload.len(), 0, false);
                return false;
            };
            let Some(last) = lane.pending_frames.back_mut() else {
                self.release_locked(state, effects, payload.len(), 0, false);
                return false;
            };
            last.encoded.extend_from_slice(payload);
            last.cost += payload.len();
            let payload_len = (last.encoded.len() - frame::HEADER_BYTES) as u32;
            last.encoded[4..8].copy_from_slice(&payload_len.to_be_bytes());
            lane.pending_bytes += payload.len();
            effects.notify(Arc::clone(&lane.notify));
            return true;
        }
        let cost = frame::HEADER_BYTES + payload.len() + QUEUE_ITEM_COST;
        let class = if control {
            PendingClass::Control
        } else {
            PendingClass::Downlink
        };
        if !control
            && state.carrier_lanes.get(&stream_id).is_none_or(|lane| {
                let resident = lane.resident.snapshot();
                cost > self.limits.pending_bytes_per_lane
                    || lane.pending_bytes.saturating_add(resident.data_bytes)
                        > self.limits.pending_bytes_per_lane.saturating_sub(cost)
                    || lane.pending_items.saturating_add(resident.data_items)
                        >= self.limits.pending_items_per_lane
            })
        {
            return false;
        }
        if !self.reserve_locked(state, cost, 1, class) {
            return false;
        }
        let mut encoded = BytesMut::with_capacity(frame::HEADER_BYTES + payload.len());
        encoded.put_u8(frame_type as u8);
        encoded.put_u8((stream_id >> 16) as u8);
        encoded.put_u8((stream_id >> 8) as u8);
        encoded.put_u8(stream_id as u8);
        encoded.put_u32(payload.len() as u32);
        encoded.extend_from_slice(payload);
        let Some(lane) = state.carrier_lanes.get_mut(&stream_id) else {
            self.release_locked(state, effects, cost, 1, control);
            return false;
        };
        let index = lane.pending_frames.len();
        lane.pending_frames.push_back(QueuedFrame {
            encoded,
            frame_type,
            stream_id,
            control,
            cost,
        });
        if !control {
            lane.pending_bytes += cost;
            lane.pending_items += 1;
        }
        if frame_type == FrameType::Window {
            lane.pending_windows.insert(stream_id, index);
        }
        effects.notify(Arc::clone(&lane.notify));
        true
    }

    pub(super) fn remember_closed_locked(
        &self,
        state: &mut SessionState,
        effects: &mut DeferredSessionEffects,
        stream_id: u32,
    ) {
        let evicted = remember_closed(state, stream_id, self.limits.max_tombstones_per_session);
        if !self.carrier().uses_lanes() {
            return;
        }
        if let Some(evicted) = evicted {
            self.release_lane_locked(state, effects, evicted);
        }
        if let Some(lane) = state.carrier_lanes.get(&stream_id) {
            effects.notify(Arc::clone(&lane.notify));
        }
    }

    /// Retires exact lane queues and ordering history, deferring every waiter notification.
    pub(super) fn release_lane_locked(
        &self,
        state: &mut SessionState,
        effects: &mut DeferredSessionEffects,
        lane_id: u32,
    ) {
        if let Some(notify) = state.conveyor.remove(Some(lane_id)) {
            effects.notify(notify);
        }
        let Some(mut lane) = state.carrier_lanes.remove(&lane_id) else {
            return;
        };
        effects.notify(Arc::clone(&lane.notify));
        let mut data_bytes = 0usize;
        let mut data_items = 0usize;
        let mut control_bytes = 0usize;
        let mut control_items = 0usize;
        for queued in lane.pending_frames.drain(..) {
            if queued.control {
                control_bytes = control_bytes.saturating_add(queued.cost);
                control_items = control_items.saturating_add(1);
            } else {
                data_bytes = data_bytes.saturating_add(queued.cost);
                data_items = data_items.saturating_add(1);
            }
        }
        if let Some(batch) = lane.unacked.take() {
            batch.lease.detach();
            self.release_local_locked(state, batch.data_bytes, batch.data_items, false);
            self.release_local_locked(state, batch.control_bytes, batch.control_items, true);
            effects.retain_batch(batch);
        }
        self.release_locked(state, effects, data_bytes, data_items, false);
        self.release_locked(state, effects, control_bytes, control_items, true);
        effects.notify(Arc::clone(&self.lane_open_notify));
    }
}

// Lane-specific protocol, replay, and lifecycle tests.
#[cfg(test)]
mod tests;
