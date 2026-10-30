use std::io;

#[derive(Debug)]
struct QuotaIoSentinel;

impl std::fmt::Display for QuotaIoSentinel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("user data quota exceeded")
    }
}

impl std::error::Error for QuotaIoSentinel {}

pub(super) fn quota_io_error() -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, QuotaIoSentinel)
}

pub(in crate::proxy::relay) fn is_quota_io_error(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::PermissionDenied
        && err
            .get_ref()
            .and_then(|source| source.downcast_ref::<QuotaIoSentinel>())
            .is_some()
}

const QUOTA_NEAR_LIMIT_BYTES: u64 = 64 * 1024;
const QUOTA_LARGE_CHARGE_BYTES: u64 = 16 * 1024;
const QUOTA_ADAPTIVE_INTERVAL_MIN_BYTES: u64 = 4 * 1024;
const QUOTA_ADAPTIVE_INTERVAL_MAX_BYTES: u64 = 64 * 1024;
pub(super) const QUOTA_RESERVE_MAX_ATTEMPTS_PER_POLL: usize = 4;

#[inline]
pub(in crate::proxy::relay) fn quota_adaptive_interval_bytes(remaining_before: u64) -> u64 {
    remaining_before.saturating_div(2).clamp(
        QUOTA_ADAPTIVE_INTERVAL_MIN_BYTES,
        QUOTA_ADAPTIVE_INTERVAL_MAX_BYTES,
    )
}

#[inline]
pub(in crate::proxy::relay) fn should_immediate_quota_check(
    remaining_before: u64,
    charge_bytes: u64,
) -> bool {
    remaining_before <= QUOTA_NEAR_LIMIT_BYTES || charge_bytes >= QUOTA_LARGE_CHARGE_BYTES
}
