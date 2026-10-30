use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use arc_swap::ArcSwap;
use dashmap::DashMap;
use ipnetwork::IpNetwork;
use parking_lot::Mutex as ParkingMutex;

use crate::config::RateLimitBps;

// Atomic per-user and per-CIDR accounting.
mod buckets;
// Immutable policy matching and sharded registries.
mod policy;
// Traffic lease accounting and cleanup.
mod lease;
// Runtime policy application and admission.
mod limiter;
// Epoch and arithmetic helpers.
mod helpers;

pub use helpers::next_refill_delay;
use helpers::{
    auto_cidr_bucket_key, bytes_per_epoch, current_epoch, decrement_atomic_saturating,
    now_epoch_secs,
};

#[cfg(test)]
mod tests;
const REGISTRY_SHARDS: usize = 64;
const FAIR_EPOCH_MS: u64 = 20;
const MAX_BORROW_CHUNK_BYTES: u64 = 32 * 1024;
const CLEANUP_INTERVAL_SECS: u64 = 60;
const RESERVE_CAS_ATTEMPT_LIMIT: usize = 16;
const REFUND_CAS_ATTEMPT_LIMIT: usize = 8;
const PACKED_USAGE_BITS: u32 = 28;
const PACKED_USAGE_MASK: u64 = (1u64 << PACKED_USAGE_BITS) - 1;
const PACKED_EPOCH_MAX: u64 = (1u64 << (u64::BITS - PACKED_USAGE_BITS)) - 1;

/// Traffic direction used by rate-limit accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateDirection {
    /// Traffic received from a client.
    Up,
    /// Traffic sent to a client.
    Down,
}

/// Result of an immediate traffic-budget request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TrafficConsumeResult {
    /// Number of bytes granted by all applicable limits.
    pub granted: u64,
    /// Whether the per-user limit prevented a grant.
    pub blocked_user: bool,
    /// Whether the per-CIDR limit prevented a grant.
    pub blocked_cidr: bool,
}

/// Process-wide traffic-limiter counters and gauges.
#[derive(Debug, Clone, Copy)]
pub struct TrafficLimiterMetricsSnapshot {
    /// Per-user upload throttle events.
    pub user_throttle_up_total: u64,
    /// Per-user download throttle events.
    pub user_throttle_down_total: u64,
    /// Per-CIDR upload throttle events.
    pub cidr_throttle_up_total: u64,
    /// Per-CIDR download throttle events.
    pub cidr_throttle_down_total: u64,
    /// Per-user accumulated upload wait time in milliseconds.
    pub user_wait_up_ms_total: u64,
    /// Per-user accumulated download wait time in milliseconds.
    pub user_wait_down_ms_total: u64,
    /// Per-CIDR accumulated upload wait time in milliseconds.
    pub cidr_wait_up_ms_total: u64,
    /// Per-CIDR accumulated download wait time in milliseconds.
    pub cidr_wait_down_ms_total: u64,
    /// Per-user upload reservations that exhausted their CAS budget.
    pub user_reserve_cas_retry_exhausted_up_total: u64,
    /// Per-user download reservations that exhausted their CAS budget.
    pub user_reserve_cas_retry_exhausted_down_total: u64,
    /// Per-user upload refunds that exhausted their CAS budget.
    pub user_refund_cas_retry_exhausted_up_total: u64,
    /// Per-user download refunds that exhausted their CAS budget.
    pub user_refund_cas_retry_exhausted_down_total: u64,
    /// Per-CIDR upload reservations that exhausted their CAS budget.
    pub cidr_reserve_cas_retry_exhausted_up_total: u64,
    /// Per-CIDR download reservations that exhausted their CAS budget.
    pub cidr_reserve_cas_retry_exhausted_down_total: u64,
    /// Per-CIDR upload refunds that exhausted their CAS budget.
    pub cidr_refund_cas_retry_exhausted_up_total: u64,
    /// Per-CIDR download refunds that exhausted their CAS budget.
    pub cidr_refund_cas_retry_exhausted_down_total: u64,
    /// Active leases with a per-user rate limit.
    pub user_active_leases: u64,
    /// Active leases with a per-CIDR rate limit.
    pub cidr_active_leases: u64,
    /// Configured per-user rate-limit entries.
    pub user_policy_entries: u64,
    /// Configured per-CIDR rate-limit entries.
    pub cidr_policy_entries: u64,
}

#[derive(Default)]
struct CasContentionMetrics {
    reserve_exhausted_total: AtomicU64,
    refund_exhausted_total: AtomicU64,
}

#[derive(Default)]
struct ScopeMetrics {
    throttle_up_total: AtomicU64,
    throttle_down_total: AtomicU64,
    wait_up_ms_total: AtomicU64,
    wait_down_ms_total: AtomicU64,
    contention_up: Arc<CasContentionMetrics>,
    contention_down: Arc<CasContentionMetrics>,
    active_leases: AtomicU64,
    policy_entries: AtomicU64,
}

#[derive(Default)]
struct AtomicRatePair {
    up_bps: AtomicU64,
    down_bps: AtomicU64,
    revision: ParkingMutex<u64>,
}

#[derive(Default)]
struct DirectionBucket {
    state: AtomicU64,
    contention: Arc<CasContentionMetrics>,
    #[cfg(test)]
    forced_reserve_failures: AtomicU64,
    #[cfg(test)]
    forced_refund_failures: AtomicU64,
    #[cfg(test)]
    reserve_cas_attempts: AtomicU64,
    #[cfg(test)]
    refund_cas_attempts: AtomicU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BucketReserveError {
    StaleEpoch,
    Contended,
    RefundContended,
    ReserveAndRefundContended,
    FairShareContended,
}

impl BucketReserveError {
    fn exhausted_reserve_budget(self) -> bool {
        matches!(self, Self::Contended | Self::ReserveAndRefundContended)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BucketRefundOutcome {
    Complete,
    Contended,
}

struct ReserveCasBudget {
    remaining: usize,
}

struct BucketReservation {
    granted: u64,
    debit: Option<DirectionDebit>,
}

struct CidrReservation {
    granted: u64,
    aggregate_debit: Option<DirectionDebit>,
    user_debit: Option<DirectionDebit>,
}

struct UserBucket {
    rates: AtomicRatePair,
    up: Arc<DirectionBucket>,
    down: Arc<DirectionBucket>,
    active_leases: AtomicU64,
}

struct CidrDirectionBucket {
    used: Arc<DirectionBucket>,
    active_users: Arc<DirectionBucket>,
}

struct CidrUserDirectionState {
    used: Arc<DirectionBucket>,
}

struct CidrUserShare {
    active_conns: AtomicU64,
    up: CidrUserDirectionState,
    down: CidrUserDirectionState,
}

struct CidrBucket {
    rates: AtomicRatePair,
    up: CidrDirectionBucket,
    down: CidrDirectionBucket,
    users: ShardedRegistry<CidrUserShare>,
    active_leases: AtomicU64,
}

#[derive(Clone)]
struct CidrRule {
    key: String,
    cidr: IpNetwork,
    limits: RateLimitBps,
    prefix_len: u8,
}

#[derive(Clone, Copy)]
struct CidrAutoRule {
    prefix_len: u8,
    limits: RateLimitBps,
}

enum CidrPolicyMatch<'a> {
    Explicit(&'a CidrRule),
    Auto { key: String, limits: RateLimitBps },
}

#[derive(Default)]
struct PolicySnapshot {
    revision: u64,
    source_generation: u64,
    user_limits: HashMap<String, RateLimitBps>,
    cidr_rules_v4: Vec<CidrRule>,
    cidr_rules_v6: Vec<CidrRule>,
    cidr_auto_rules_v4: Vec<CidrAutoRule>,
    cidr_auto_rules_v6: Vec<CidrAutoRule>,
    cidr_rule_keys: HashSet<String>,
}

struct ShardedRegistry<T> {
    shards: Box<[DashMap<String, Arc<T>>]>,
    mask: usize,
}

struct TrafficLeaseBinding {
    limiter: Arc<TrafficLimiter>,
    revision: u64,
    user_bucket: Option<Arc<UserBucket>>,
    cidr_bucket: Option<Arc<CidrBucket>>,
    cidr_user_key: Option<String>,
    cidr_user_share: Option<Arc<CidrUserShare>>,
}

/// A live traffic-limiter binding for one authenticated client session.
pub struct TrafficLease {
    limiter: Arc<TrafficLimiter>,
    user: String,
    client_ip: IpAddr,
    binding: ArcSwap<TrafficLeaseBinding>,
    refresh: ParkingMutex<()>,
}

/// Owns rate-limit policy, shared buckets, and limiter telemetry.
pub struct TrafficLimiter {
    policy: ArcSwap<PolicySnapshot>,
    policy_update: ParkingMutex<()>,
    user_buckets: ShardedRegistry<UserBucket>,
    cidr_buckets: ShardedRegistry<CidrBucket>,
    user_scope: ScopeMetrics,
    cidr_scope: ScopeMetrics,
    last_cleanup_epoch_secs: AtomicU64,
}

struct DirectionDebit {
    bucket: Arc<DirectionBucket>,
    epoch: u64,
    refundable: u64,
}

/// Refunds uncommitted shaping budget when an I/O attempt is cancelled.
#[must_use = "traffic reservations must be settled after the I/O attempt"]
pub(crate) struct TrafficReservation {
    result: TrafficConsumeResult,
    _binding: Arc<TrafficLeaseBinding>,
    user: Option<DirectionDebit>,
    cidr: Option<DirectionDebit>,
    cidr_user: Option<DirectionDebit>,
}
