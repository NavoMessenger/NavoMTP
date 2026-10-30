use std::sync::Arc;

use bytes::{Bytes, BytesMut};

use super::super::resident::{OwnedBatchBody, PendingCounts, PendingResponseLease};
use super::super::{DeferredSessionEffects, DownBatch, SessionState, WebSession};
use crate::web::frame::FrameType;
use crate::web::manager::ManagerError;

impl WebSession {
    /// Stages one multiplexed batch while retaining its transient permit.
    pub(super) fn take_down_batch_locked(
        &self,
        state: &mut SessionState,
        effects: &mut DeferredSessionEffects,
        cursor: u64,
    ) -> Result<DownBatch, ManagerError> {
        let next_cursor = state
            .down_cursor
            .checked_add(1)
            .ok_or(ManagerError::Protocol)?;
        let mut count = 0usize;
        let mut body_len = 0usize;
        for queued in &state.pending_frames {
            if count >= self.limits.max_frames_per_body
                || (count != 0
                    && body_len.saturating_add(queued.encoded.len())
                        > self.limits.carrier_batch_bytes)
            {
                break;
            }
            body_len += queued.encoded.len();
            count += 1;
        }
        let Some(manager) = self.manager.upgrade() else {
            return Err(ManagerError::Closed);
        };
        let Some(staging) = manager.try_downlink_staging_budget(body_len) else {
            return Err(ManagerError::Backpressure);
        };
        effects.retain_staging_permit(staging);
        let mut body = BytesMut::with_capacity(body_len);
        let mut data_bytes = 0usize;
        let mut data_items = 0usize;
        let mut control_bytes = 0usize;
        let mut control_items = 0usize;
        for index in 0..count {
            let Some(queued) = state.pending_frames.get(index) else {
                break;
            };
            if queued.frame_type == FrameType::Window
                && state.pending_windows.get(&queued.stream_id) == Some(&index)
            {
                state.pending_windows.remove(&queued.stream_id);
            }
        }
        for _ in 0..count {
            let Some(queued) = state.pending_frames.pop_front() else {
                break;
            };
            body.extend_from_slice(&queued.encoded);
            if queued.control {
                control_bytes += queued.cost;
                control_items += 1;
            } else {
                data_bytes += queued.cost;
                data_items += 1;
            }
        }
        for index in state.pending_windows.values_mut() {
            *index = index.saturating_sub(count);
        }
        state.down_cursor = next_cursor;
        let counts = PendingCounts {
            data_bytes,
            data_items,
            control_bytes,
            control_items,
        };
        let lease = PendingResponseLease::new(self, counts, None);
        let body = Bytes::from_owner(OwnedBatchBody::new(body.freeze(), Arc::clone(&lease)));
        Ok(DownBatch {
            body,
            lease,
            base_cursor: cursor,
            next_cursor,
            data_bytes,
            data_items,
            control_bytes,
            control_items,
            carrier_health_eligible: state.negotiation_phase
                == super::super::SessionNegotiationPhase::Committed,
        })
    }

    /// Detaches one acknowledged response and defers writer wakes and lease drop.
    pub(super) fn release_unacked_locked(
        &self,
        state: &mut SessionState,
        effects: &mut DeferredSessionEffects,
    ) {
        let Some(batch) = state.unacked.take() else {
            return;
        };
        batch.lease.detach();
        self.release_local_locked(state, batch.data_bytes, batch.data_items, false);
        self.release_local_locked(state, batch.control_bytes, batch.control_items, true);
        for stream in state.streams.values_mut() {
            if let Some(waker) = stream.write_waker.take() {
                effects.wake(waker);
            }
        }
        effects.retain_batch(batch);
    }
}
