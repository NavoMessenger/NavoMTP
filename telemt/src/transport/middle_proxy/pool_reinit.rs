use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use rand::RngExt;
use rand::seq::SliceRandom;
use std::collections::hash_map::DefaultHasher;
use tracing::{debug, info, warn};

use crate::config::MeBindStaleMode;
use crate::crypto::SecureRandom;
use crate::network::IpFamily;

use super::pool::{
    EndpointSnapshot, MeDrainGateReason, MePool, ReinitAttemptState, ReinitCoordinatorState,
    ReinitCore, ReinitPendingState, ReinitStatusSnapshot, WriterContour, WriterOpenIntent,
};

// Reinitialization admission, generation state, and coverage checks.
mod coordination;
// Generation warmup and stale-writer reconciliation.
mod reconcile;

#[cfg(test)]
mod dual_family_tests;
#[cfg(test)]
mod tests;
const ME_HARDSWAP_PENDING_TTL_SECS: u64 = 1800;

struct ReinitAttemptGuard {
    reinit: Arc<ReinitCore>,
    attempt_id: u64,
    generation: u64,
    previous_generation: u64,
    map_hash: u64,
    endpoint_revision: u64,
    hardswap: bool,
}

impl Drop for ReinitAttemptGuard {
    fn drop(&mut self) {
        let mut state = self.reinit.coordinator.lock();
        state.attempts.remove(&self.attempt_id);
        publish_reinit_state(self.reinit.as_ref(), &state);
    }
}

struct ReinitReservation {
    attempt: ReinitAttemptGuard,
    pending_reused: bool,
    pending_expired: bool,
    pending_age_secs: u64,
}

struct ReinitCommitOutcome {
    coverage_ratio: f32,
    missing_dc: Vec<i32>,
    missing_groups: Vec<DcFamilyGroup>,
    stale_writer_ids: Vec<u64>,
    force_close_writer_ids: Vec<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
/// One independently enforced hardswap writer-floor group.
pub(in crate::transport::middle_proxy) struct DcFamilyGroup {
    /// Telegram DC owning the group.
    pub(in crate::transport::middle_proxy) dc: i32,
    /// Address family whose floor is evaluated independently.
    pub(in crate::transport::middle_proxy) family: IpFamily,
}

/// Complete floor-coverage result for one candidate hardswap generation.
pub(in crate::transport::middle_proxy) struct HardswapCoverage {
    /// Fraction of configured DC-family groups that reached their full floor.
    pub(in crate::transport::middle_proxy) ratio: f32,
    /// Stable list of DC-family groups that remain below their floor.
    pub(in crate::transport::middle_proxy) missing_groups: Vec<DcFamilyGroup>,
    /// Total writer count still required across all missing groups.
    pub(in crate::transport::middle_proxy) writer_deficit: usize,
}

#[derive(Debug)]
enum ReinitCommitFailure {
    Superseded,
    Coverage {
        coverage_ratio: f32,
        missing_dc: Vec<i32>,
        missing_groups: Vec<DcFamilyGroup>,
    },
    Redundancy {
        coverage_ratio: f32,
        missing_dc: Vec<i32>,
        missing_groups: Vec<DcFamilyGroup>,
    },
}

fn publish_reinit_state(reinit: &ReinitCore, state: &ReinitCoordinatorState) {
    let mut warm_generations = state
        .attempts
        .values()
        .filter(|attempt| attempt.hardswap && !attempt.committed)
        .map(|attempt| attempt.generation)
        .collect::<Vec<_>>();
    if let Some(pending) = state.pending {
        warm_generations.push(pending.generation);
    }
    warm_generations.sort_unstable();
    warm_generations.dedup();
    let pending = state.pending;
    let snapshot = ReinitStatusSnapshot {
        active_generation: state.active_generation,
        warm_generations,
        pending_hardswap_generation: pending.map_or(0, |value| value.generation),
        pending_hardswap_started_at_epoch_secs: pending
            .map_or(0, |value| value.started_at_epoch_secs),
        pending_hardswap_map_hash: pending.map_or(0, |value| value.map_hash),
        pending_hardswap_endpoint_revision: pending.map_or(0, |value| value.endpoint_revision),
        inflight: state.attempts.len(),
    };
    reinit
        .active_generation
        .store(snapshot.active_generation, Ordering::Release);
    reinit.warm_generation.store(
        snapshot.warm_generations.last().copied().unwrap_or(0),
        Ordering::Release,
    );
    reinit
        .pending_hardswap_generation
        .store(snapshot.pending_hardswap_generation, Ordering::Release);
    reinit.pending_hardswap_started_at_epoch_secs.store(
        snapshot.pending_hardswap_started_at_epoch_secs,
        Ordering::Release,
    );
    reinit
        .pending_hardswap_map_hash
        .store(snapshot.pending_hardswap_map_hash, Ordering::Release);
    reinit.status.store(Arc::new(snapshot));
}

fn commit_reinit_state(
    state: &mut ReinitCoordinatorState,
    attempt_id: u64,
    generation: u64,
    map_hash: u64,
    endpoint_revision: u64,
    hardswap: bool,
) -> bool {
    let Some(record) = state.attempts.get(&attempt_id).copied() else {
        return false;
    };
    if record.map_hash != state.desired_map_hash
        || record.map_hash != map_hash
        || record.endpoint_revision != endpoint_revision
        || record.endpoint_revision != state.endpoint_revision
    {
        return false;
    }
    if hardswap {
        let pending_matches = state.pending.is_some_and(|pending| {
            pending.generation == generation
                && pending.map_hash == map_hash
                && pending.endpoint_revision == endpoint_revision
        });
        if !pending_matches || generation < state.active_generation {
            return false;
        }
        state.active_generation = generation;
        state.pending = None;
    }
    if let Some(record) = state.attempts.get_mut(&attempt_id) {
        record.committed = true;
    }
    true
}
