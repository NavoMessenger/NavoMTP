use std::sync::Arc;

use bytes::{Bytes, BytesMut};

use super::resident::{OwnedBatchBody, PendingCounts, PendingResponseLease};
use super::{CarrierLane, DeferredSessionEffects, DownBatch, WebSession};
use crate::config::WebLimitsConfig;
use crate::web::frame::FrameType;
use crate::web::manager::ManagerError;

/// Stages one bounded lane batch and transfers its accounting into response ownership.
pub(super) fn take_lane_down_batch(
    session: &WebSession,
    limits: &WebLimitsConfig,
    lane: &mut CarrierLane,
    effects: &mut DeferredSessionEffects,
    cursor: u64,
    carrier_health_eligible: bool,
) -> Result<DownBatch, ManagerError> {
    let next_cursor = lane
        .down_cursor
        .checked_add(1)
        .ok_or(ManagerError::Protocol)?;
    let mut count = 0usize;
    let mut body_len = 0usize;
    for queued in &lane.pending_frames {
        if count >= limits.max_frames_per_body
            || (count != 0
                && body_len.saturating_add(queued.encoded.len()) > limits.carrier_batch_bytes)
        {
            break;
        }
        body_len += queued.encoded.len();
        count += 1;
    }
    let Some(manager) = session.manager.upgrade() else {
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
        let Some(queued) = lane.pending_frames.get(index) else {
            break;
        };
        if queued.frame_type == FrameType::Window
            && lane.pending_windows.get(&queued.stream_id) == Some(&index)
        {
            lane.pending_windows.remove(&queued.stream_id);
        }
    }
    for _ in 0..count {
        let Some(queued) = lane.pending_frames.pop_front() else {
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
    for index in lane.pending_windows.values_mut() {
        *index = index.saturating_sub(count);
    }
    lane.down_cursor = next_cursor;
    let counts = PendingCounts {
        data_bytes,
        data_items,
        control_bytes,
        control_items,
    };
    let lease = PendingResponseLease::new(session, counts, Some(Arc::clone(&lane.resident)));
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
        carrier_health_eligible,
    })
}
