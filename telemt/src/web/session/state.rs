use std::collections::VecDeque;

use super::{CarrierLane, CarrierLaneIdentity, InboundChunk, QUEUE_ITEM_COST, SessionState};

pub(super) fn inbound_queue_cost(queue: &VecDeque<InboundChunk>) -> (usize, usize) {
    let bytes = queue.iter().fold(0usize, |total, chunk| {
        total.saturating_add(chunk.bytes.len().saturating_sub(chunk.offset) + QUEUE_ITEM_COST)
    });
    (bytes, queue.len())
}

pub(super) fn remember_closed(
    state: &mut SessionState,
    stream_id: u32,
    limit: usize,
) -> Option<u32> {
    if !state.closed_streams.insert(stream_id) {
        return None;
    }
    state.closed_order.push_back(stream_id);
    let mut evicted = None;
    while state.closed_order.len() > limit {
        if let Some(oldest) = state.closed_order.pop_front() {
            state.closed_streams.remove(&oldest);
            evicted = Some(oldest);
        }
    }
    evicted
}

pub(super) fn insert_carrier_lane(
    state: &mut SessionState,
    lane_id: u32,
) -> Option<CarrierLaneIdentity> {
    if state.carrier_lanes.contains_key(&lane_id) {
        return None;
    }
    let instance = state.next_lane_instance;
    state.next_lane_instance = instance.checked_add(1)?;
    state
        .carrier_lanes
        .insert(lane_id, CarrierLane::new(instance));
    Some(CarrierLaneIdentity { lane_id, instance })
}
