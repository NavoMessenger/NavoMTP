use std::net::IpAddr;
use std::sync::atomic::Ordering;

use super::{WebSocketEntry, WebSocketKind, WebSocketPhase, dead_after};
use crate::web::manager::ProfileKey;
use crate::web::manager::budget::WebSocketFairnessSnapshot;

/// Stable total-order key used by bounded victim selection.
pub(super) type VictimKey = (u8, u8, u8, u64, u64, u64);

/// Lifecycle class used before locality and least-recent-progress ordering.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum VictimClass {
    /// Active connection whose peer-liveness deadline elapsed.
    Dead,
    /// Claimed or upgraded connection still bounded by its startup deadlines.
    PreActive,
    /// Active per-stream lane connection.
    LiveLane,
    /// Active multiplexed session connection.
    LiveMultiplex,
}

impl VictimClass {
    fn rank(self) -> u8 {
        match self {
            Self::Dead | Self::PreActive => 0,
            Self::LiveLane => 1,
            Self::LiveMultiplex => 2,
        }
    }
}

/// Classifies one non-closing connection without conflating startup with death.
pub(super) fn victim_class(entry: &WebSocketEntry, now: u64) -> VictimClass {
    let phase = entry.phase.load(Ordering::Acquire);
    if phase == WebSocketPhase::Active as u8
        && now.saturating_sub(entry.last_peer_tick.load(Ordering::Acquire)) >= dead_after(entry)
    {
        VictimClass::Dead
    } else if phase < WebSocketPhase::Active as u8 {
        VictimClass::PreActive
    } else if matches!(entry.kind, WebSocketKind::Lane(_)) {
        VictimClass::LiveLane
    } else {
        VictimClass::LiveMultiplex
    }
}

/// Returns one eligible admission-victim key with global dead-first ordering.
pub(super) fn admission_key(
    entry: &WebSocketEntry,
    now: u64,
    requester_owner: ProfileKey,
    requester_session: u64,
    requester_ip: IpAddr,
    fairness: &WebSocketFairnessSnapshot,
) -> Option<VictimKey> {
    let class = victim_class(entry, now);
    if class == VictimClass::Dead {
        return Some((
            0,
            0,
            0,
            entry.last_peer_tick.load(Ordering::Acquire),
            entry.created_tick,
            entry.id,
        ));
    }
    let locality = if entry.session_id == requester_session {
        0
    } else if entry.owner == requester_owner {
        1
    } else if entry.client_ip == requester_ip {
        2
    } else if fairness.owner_usage(requester_owner) < fairness.fair_share
        && fairness.owner_usage(entry.owner) > fairness.fair_share
    {
        3
    } else {
        return None;
    };
    Some((
        1,
        locality,
        class.rank(),
        entry.last_progress_tick.load(Ordering::Acquire),
        entry.created_tick,
        entry.id,
    ))
}

/// Returns one pressure-victim key preferring dead and over-share owners.
pub(super) fn pressure_key(
    entry: &WebSocketEntry,
    now: u64,
    fairness: &WebSocketFairnessSnapshot,
) -> VictimKey {
    let class = victim_class(entry, now);
    let dead = class == VictimClass::Dead;
    (
        u8::from(!dead),
        if dead {
            0
        } else {
            u8::from(fairness.owner_usage(entry.owner) <= fairness.fair_share)
        },
        class.rank(),
        entry.last_progress_tick.load(Ordering::Acquire),
        entry.created_tick,
        entry.id,
    )
}
