use super::*;

const MAX_WEBSOCKET_BATCH_BYTES: usize = 2 * 1024 * 1024;
const WEBSOCKET_IO_BUFFER_BYTES: usize = 64 * 1024;
const WEBSOCKET_DRIVER_OVERHEAD_BYTES: usize = 4 * 1024;
const WEBSOCKET_FRAME_OVERHEAD_BYTES: usize = 14;

/// Validates WebSocket admission, memory, and deadline invariants.
pub(super) fn validate(
    carriers: &[WebCarrier],
    limits: &WebLimitsConfig,
    timeouts: &WebTimeoutsConfig,
) -> Result<()> {
    if !(1..100).contains(&limits.websocket_admission_watermark_pct)
        || !(1..100).contains(&limits.websocket_eviction_watermark_pct)
        || limits.websocket_admission_watermark_pct >= limits.websocket_eviction_watermark_pct
    {
        return config_error(
            "web.limits WebSocket watermarks must satisfy 1 <= admission < eviction < 100",
        );
    }
    if limits.websocket_bytes_global == 0 {
        return config_error("web.limits.websocket_bytes_global must be > 0");
    }
    if timeouts.websocket_eviction_secs > timeouts.websocket_write_secs {
        return config_error(
            "web.timeouts.websocket_eviction_secs must not exceed websocket_write_secs",
        );
    }
    if !carriers.iter().any(|carrier| carrier.uses_websocket()) {
        return Ok(());
    }
    if limits.carrier_batch_bytes > MAX_WEBSOCKET_BATCH_BYTES {
        return config_error(
            "WebSocket carriers require web.limits.carrier_batch_bytes <= 2097152",
        );
    }
    if limits.websocket_http_connection_reserve == 0
        || limits.websocket_http_connection_reserve >= limits.max_http_connections
    {
        return config_error(
            "WebSocket carriers require websocket_http_connection_reserve within [1, max_http_connections)",
        );
    }
    let websocket_capacity = limits
        .max_http_connections
        .saturating_sub(limits.websocket_http_connection_reserve);
    if limits.max_websocket_evictions_in_flight > websocket_capacity {
        return config_error(
            "web.limits.max_websocket_evictions_in_flight must not exceed WebSocket connection capacity",
        );
    }
    let socket_base = WEBSOCKET_IO_BUFFER_BYTES
        .checked_mul(2)
        .and_then(|value| value.checked_add(WEBSOCKET_DRIVER_OVERHEAD_BYTES))
        .ok_or_else(|| ProxyError::Config("WebSocket base reservation overflowed usize".into()))?;
    let minimum_websocket_progress = limits
        .carrier_batch_bytes
        .checked_add(WEBSOCKET_FRAME_OVERHEAD_BYTES)
        .and_then(|value| value.checked_mul(2))
        .and_then(|value| value.checked_add(socket_base))
        .ok_or_else(|| {
            ProxyError::Config("WebSocket progress reservation overflowed usize".into())
        })?;
    if limits.websocket_bytes_global < minimum_websocket_progress {
        return config_error(
            "web.limits.websocket_bytes_global must preserve one socket read and write",
        );
    }
    let data_bytes = limits
        .pending_bytes_global
        .saturating_sub(limits.control_bytes_global);
    let queue_progress = limits
        .max_body_bytes
        .checked_add(
            limits
                .max_frames_per_body
                .checked_mul(WEB_QUEUE_ITEM_COST)
                .ok_or_else(|| {
                    ProxyError::Config("WEB queue progress reservation overflowed usize".into())
                })?,
        )
        .and_then(|value| value.checked_add(limits.carrier_batch_bytes))
        .ok_or_else(|| {
            ProxyError::Config("WEB queue progress reservation overflowed usize".into())
        })?;
    if limits.websocket_bytes_global > data_bytes.saturating_sub(queue_progress) {
        return config_error("web.limits.websocket_bytes_global must leave bounded queue progress");
    }
    Ok(())
}
