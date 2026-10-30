use super::*;

const MAX_WEB_TRACE_WINDOW_SECS: u64 = 86_400;
const MIN_WEB_DEBUG_BYTES_GLOBAL: usize = 4096;

/// Validates hot debug policy independently from process-owned storage limits.
pub(super) fn validate(policy: &WebDebugConfig, limits: &WebLimitsConfig) -> Result<()> {
    if limits.debug_bytes_global < MIN_WEB_DEBUG_BYTES_GLOBAL {
        return config_error("web.limits.debug_bytes_global must be at least 4096 bytes");
    }
    if policy.default_window_secs == 0
        || policy.max_window_secs == 0
        || policy.default_window_secs > policy.max_window_secs
        || policy.max_window_secs > MAX_WEB_TRACE_WINDOW_SECS
    {
        return config_error(
            "web.debug windows must be non-zero, ordered, and no greater than 86400 seconds",
        );
    }
    if policy.body_prefix_bytes > limits.max_body_bytes {
        return config_error(
            "web.debug.body_prefix_bytes must not exceed web.limits.max_body_bytes",
        );
    }
    if policy.body_prefix_bytes > limits.debug_bytes_global
        || policy.decoy_body_prefix_bytes > limits.debug_bytes_global
    {
        return config_error(
            "web.debug body prefixes must not exceed web.limits.debug_bytes_global",
        );
    }
    Ok(())
}
