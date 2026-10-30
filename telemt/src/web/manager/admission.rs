use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::Notify;

use super::state::{allocate_stream_port, allow_rate, decrement_map, release_stream_port};
use super::{ProfileKey, WebProcessRuntime};
use crate::web::telemetry::WebRejectionReason;

impl WebProcessRuntime {
    /// Reserves one live stream slot and immediately dispatches any operator-fence wake.
    #[allow(dead_code)]
    pub(crate) fn try_acquire_stream(
        &self,
        profile_key: ProfileKey,
        max_streams: usize,
        client_ip: IpAddr,
        public_addr: SocketAddr,
    ) -> Result<u16, super::ManagerError> {
        let (result, notify) =
            self.try_acquire_stream_quiet(profile_key, max_streams, client_ip, public_addr);
        if let Some(notify) = notify {
            notify.notify_waiters();
        }
        result
    }

    /// Reserves one stream while returning any operator-fence wake for deferred dispatch.
    pub(crate) fn try_acquire_stream_quiet(
        &self,
        profile_key: ProfileKey,
        max_streams: usize,
        client_ip: IpAddr,
        public_addr: SocketAddr,
    ) -> (Result<u16, super::ManagerError>, Option<Arc<Notify>>) {
        let operator_admission = match self.try_operator_admission() {
            Ok(admission) => admission,
            Err(error) => {
                self.telemetry.record_stream_rejected();
                return (Err(error), None);
            }
        };
        let result = {
            let now = Instant::now();
            let mut state = self.stream_admission.lock();
            if state.closed {
                self.telemetry.record_stream_rejected();
                self.telemetry
                    .record_rejection(WebRejectionReason::RuntimeClosed);
                Err(super::ManagerError::Closed)
            } else if state.streams_live >= self.limits.max_streams_global
                || state
                    .streams_per_profile
                    .get(&profile_key)
                    .copied()
                    .unwrap_or(0)
                    >= max_streams
            {
                self.record_stream_rejected_reason(WebRejectionReason::StreamCapacity);
                Err(super::ManagerError::Limit)
            } else if !allow_rate(
                &mut state.stream_rate,
                now,
                self.limits.new_streams_per_minute,
                self.limits.new_streams_burst,
            ) {
                self.record_stream_rejected_reason(WebRejectionReason::StreamRate);
                Err(super::ManagerError::Limit)
            } else if let Some(peer_port) = allocate_stream_port(&mut state, client_ip, public_addr)
            {
                state.streams_live += 1;
                *state.streams_per_profile.entry(profile_key).or_insert(0) += 1;
                self.telemetry.record_stream_opened();
                Ok(peer_port)
            } else {
                self.record_stream_rejected_reason(WebRejectionReason::StreamTupleExhausted);
                Err(super::ManagerError::Limit)
            }
        };
        let notify = operator_admission.release_deferred();
        (result, notify)
    }

    /// Releases one live logical-stream slot after its relay task exits.
    pub(crate) fn release_stream(
        &self,
        profile_key: ProfileKey,
        client_ip: IpAddr,
        public_addr: SocketAddr,
        peer_port: u16,
    ) {
        if let Some(notify) =
            self.release_stream_quiet(profile_key, client_ip, public_addr, peer_port)
        {
            notify.notify_waiters();
        }
    }

    /// Releases one stream while returning any drain wake for deferred dispatch.
    pub(crate) fn release_stream_quiet(
        &self,
        profile_key: ProfileKey,
        client_ip: IpAddr,
        public_addr: SocketAddr,
        peer_port: u16,
    ) -> Option<Arc<Notify>> {
        let mut state = self.stream_admission.lock();
        if !release_stream_port(&mut state, client_ip, public_addr, peer_port) {
            return None;
        }
        state.streams_live = state.streams_live.saturating_sub(1);
        decrement_map(&mut state.streams_per_profile, &profile_key);
        drop(state);
        self.operator_lifecycle.work_changed_notification()
    }

    /// Records a logical stream rejected outside manager quota acquisition.
    pub(crate) fn record_stream_rejected(&self) {
        self.telemetry.record_stream_rejected();
        self.record_limit_hit();
    }

    /// Records one logical stream rejection with its operational cause.
    pub(crate) fn record_stream_rejected_reason(&self, reason: WebRejectionReason) {
        self.record_stream_rejected();
        self.telemetry.record_rejection(reason);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use arc_swap::ArcSwap;

    use super::*;
    use crate::config::ProxyConfig;
    use crate::maestro::generation::test_runtime_generation;
    use crate::web::session::QUEUE_ITEM_COST;

    #[tokio::test]
    async fn global_downlink_budget_preserves_one_maximum_uplink_batch() {
        let generation = test_runtime_generation(1, ProxyConfig::default());
        let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(generation)));
        let control_items = super::super::budget::control_item_reserve(&runtime.limits);
        let data_bytes = runtime
            .limits
            .pending_bytes_global
            .saturating_sub(runtime.limits.control_bytes_global);
        let data_items = runtime
            .limits
            .pending_items_global
            .saturating_sub(control_items);
        let uplink_bytes = runtime
            .limits
            .max_body_bytes
            .saturating_add(runtime.limits.max_frames_per_body * QUEUE_ITEM_COST);
        let websocket_bytes = runtime.limits.carrier_batch_bytes;
        let downlink_bytes = data_bytes - uplink_bytes - websocket_bytes;
        let downlink_items = data_items - runtime.limits.max_frames_per_body;

        assert!(runtime.try_reserve_pending([0; 32], downlink_bytes, downlink_items, false, true,));
        assert!(runtime.try_reserve_pending(
            [0; 32],
            uplink_bytes,
            runtime.limits.max_frames_per_body,
            false,
            false,
        ));
        let websocket = runtime.try_websocket_data_budget([0; 32], websocket_bytes);
        assert!(websocket.is_some());
        assert!(!runtime.try_reserve_pending([0; 32], 1, 1, false, true));

        drop(websocket);
        runtime.release_pending([0; 32], downlink_bytes, downlink_items, false);
        runtime.release_pending(
            [0; 32],
            uplink_bytes,
            runtime.limits.max_frames_per_body,
            false,
        );
        runtime.shutdown().await;
    }
}
