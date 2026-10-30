use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use arc_swap::ArcSwap;
use dashmap::DashMap;
use parking_lot::Mutex;

use super::{QuotaReserveError, UserQuotaSnapshot};
use crate::proxy::user_admission::UserIncarnation;

/// Process-scoped per-user quota accounting shared by runtime generations.
#[derive(Default)]
pub struct QuotaStore {
    users: DashMap<String, Arc<QuotaUserSlot>>,
}

struct QuotaUserSlot {
    state: Mutex<QuotaSlotState>,
}

#[derive(Default)]
struct QuotaSlotState {
    high_water: UserIncarnation,
    current: Option<QuotaAccount>,
    startup_seed: Option<UserQuotaSnapshot>,
}

struct QuotaAccount {
    incarnation: UserIncarnation,
    counters: Arc<UserQuotaCounters>,
}

/// Exact quota ownership pinned to one authenticated user incarnation.
#[derive(Clone)]
pub(crate) struct UserQuotaHandle {
    incarnation: UserIncarnation,
    counters: Arc<UserQuotaCounters>,
}

/// Atomically replaceable quota state for one configured user.
pub(crate) struct UserQuotaCounters {
    generation: ArcSwap<QuotaGeneration>,
}

struct QuotaGeneration {
    used_bytes: AtomicU64,
    last_reset_epoch_secs: u64,
}

/// Owns a quota debit until the corresponding I/O outcome is known.
#[must_use = "quota reservations must be committed or settled"]
pub(crate) struct QuotaReservation {
    generation: Arc<QuotaGeneration>,
    reserved_bytes: u64,
    total_after_reserve: u64,
}

impl QuotaStore {
    fn slot(&self, user: &str) -> Arc<QuotaUserSlot> {
        if let Some(existing) = self.users.get(user) {
            return Arc::clone(existing.value());
        }
        Arc::clone(
            self.users
                .entry(user.to_string())
                .or_insert_with(|| {
                    Arc::new(QuotaUserSlot {
                        state: Mutex::new(QuotaSlotState::default()),
                    })
                })
                .value(),
        )
    }

    pub(crate) fn current_or_legacy_handle(&self, user: &str) -> UserQuotaHandle {
        let slot = self.slot(user);
        let mut state = slot.state.lock();
        if let Some(account) = &state.current {
            return UserQuotaHandle {
                incarnation: account.incarnation,
                counters: Arc::clone(&account.counters),
            };
        }
        let seed = state.startup_seed.take().unwrap_or(UserQuotaSnapshot {
            used_bytes: 0,
            last_reset_epoch_secs: 0,
        });
        let counters = Arc::new(UserQuotaCounters::from_snapshot(&seed));
        let incarnation = state.high_water;
        state.current = Some(QuotaAccount {
            incarnation,
            counters: Arc::clone(&counters),
        });
        UserQuotaHandle {
            incarnation,
            counters,
        }
    }

    pub(crate) fn user(&self, user: &str) -> Arc<UserQuotaCounters> {
        self.current_or_legacy_handle(user).counters
    }

    /// Returns the quota account owned by the exact current incarnation.
    pub(crate) fn handle_exact(
        &self,
        user: &str,
        incarnation: UserIncarnation,
    ) -> Option<UserQuotaHandle> {
        let slot = self.users.get(user)?;
        let state = slot.state.lock();
        let account = state.current.as_ref()?;
        (account.incarnation == incarnation).then(|| UserQuotaHandle {
            incarnation,
            counters: Arc::clone(&account.counters),
        })
    }

    /// Creates a quota account for a new username lifetime without inheriting a retired account.
    pub(crate) fn activate_fresh(&self, user: &str, incarnation: UserIncarnation) {
        let slot = self.slot(user);
        let mut state = slot.state.lock();
        if incarnation <= state.high_water {
            return;
        }
        let snapshot = if state.high_water == 0 {
            state
                .current
                .as_ref()
                .map(|account| account.counters.snapshot())
                .or_else(|| state.startup_seed.take())
        } else {
            state.startup_seed = None;
            None
        }
        .unwrap_or(UserQuotaSnapshot {
            used_bytes: 0,
            last_reset_epoch_secs: 0,
        });
        state.high_water = state.high_water.max(incarnation);
        state.current = Some(QuotaAccount {
            incarnation,
            counters: Arc::new(UserQuotaCounters::from_snapshot(&snapshot)),
        });
    }

    /// Advances a credential incarnation while preserving usage captured at the transition.
    pub(crate) fn advance_preserving_usage(&self, user: &str, incarnation: UserIncarnation) {
        let slot = self.slot(user);
        let mut state = slot.state.lock();
        if incarnation <= state.high_water {
            return;
        }
        let snapshot = state
            .current
            .as_ref()
            .map(|account| account.counters.snapshot())
            .or_else(|| state.startup_seed.take())
            .unwrap_or(UserQuotaSnapshot {
                used_bytes: 0,
                last_reset_epoch_secs: 0,
            });
        state.high_water = incarnation;
        state.current = Some(QuotaAccount {
            incarnation,
            counters: Arc::new(UserQuotaCounters::from_snapshot(&snapshot)),
        });
    }

    /// Retires quota ownership without affecting a newer incarnation.
    pub(crate) fn retire_through(&self, user: &str, incarnation: UserIncarnation) {
        let slot = self.slot(user);
        let mut state = slot.state.lock();
        if incarnation < state.high_water {
            return;
        }
        state.high_water = incarnation;
        state.current = None;
        state.startup_seed = None;
    }

    pub(crate) fn used(&self, user: &str) -> u64 {
        self.users
            .get(user)
            .and_then(|slot| {
                let state = slot.state.lock();
                state
                    .current
                    .as_ref()
                    .map(|account| account.counters.used())
                    .or_else(|| state.startup_seed.as_ref().map(|seed| seed.used_bytes))
            })
            .unwrap_or(0)
    }

    pub(crate) fn load(&self, user: &str, used_bytes: u64, last_reset_epoch_secs: u64) {
        let slot = self.slot(user);
        let mut state = slot.state.lock();
        let snapshot = UserQuotaSnapshot {
            used_bytes,
            last_reset_epoch_secs,
        };
        if let Some(account) = &state.current {
            account.replace_from_snapshot(&snapshot);
        } else {
            state.startup_seed = Some(snapshot);
        }
    }

    pub(crate) fn reset(&self, user: &str, now_epoch_secs: u64) -> UserQuotaSnapshot {
        self.current_or_legacy_handle(user).reset(now_epoch_secs)
    }

    pub(crate) fn remove(&self, user: &str) {
        let slot = self.slot(user);
        let mut state = slot.state.lock();
        state.high_water = state.high_water.saturating_add(1);
        state.current = None;
        state.startup_seed = None;
    }

    pub(crate) fn snapshot(&self) -> HashMap<String, UserQuotaSnapshot> {
        let mut out = HashMap::new();
        for entry in self.users.iter() {
            let state = entry.value().state.lock();
            let snapshot = if let Some(account) = state.current.as_ref() {
                account.counters.snapshot()
            } else if let Some(seed) = state.startup_seed.as_ref() {
                seed.clone()
            } else {
                continue;
            };
            if snapshot.used_bytes == 0 && snapshot.last_reset_epoch_secs == 0 {
                continue;
            }
            out.insert(entry.key().clone(), snapshot);
        }
        out
    }
}

impl Default for UserQuotaCounters {
    fn default() -> Self {
        Self {
            generation: ArcSwap::from_pointee(QuotaGeneration {
                used_bytes: AtomicU64::new(0),
                last_reset_epoch_secs: 0,
            }),
        }
    }
}

impl UserQuotaCounters {
    fn from_snapshot(snapshot: &UserQuotaSnapshot) -> Self {
        Self {
            generation: ArcSwap::from_pointee(QuotaGeneration {
                used_bytes: AtomicU64::new(snapshot.used_bytes),
                last_reset_epoch_secs: snapshot.last_reset_epoch_secs,
            }),
        }
    }

    fn snapshot(&self) -> UserQuotaSnapshot {
        let generation = self.generation.load_full();
        UserQuotaSnapshot {
            used_bytes: generation.used_bytes.load(Ordering::Relaxed),
            last_reset_epoch_secs: generation.last_reset_epoch_secs,
        }
    }

    fn replace(&self, used_bytes: u64, last_reset_epoch_secs: u64) {
        self.generation.store(Arc::new(QuotaGeneration {
            used_bytes: AtomicU64::new(used_bytes),
            last_reset_epoch_secs,
        }));
    }

    #[inline]
    pub(crate) fn used(&self) -> u64 {
        self.generation.load().used_bytes.load(Ordering::Relaxed)
    }

    #[inline]
    pub(crate) fn charge(&self, bytes: u64) -> u64 {
        self.generation
            .load_full()
            .used_bytes
            .fetch_add(bytes, Ordering::Relaxed)
            .saturating_add(bytes)
    }

    #[inline]
    pub(crate) fn try_reserve(
        &self,
        bytes: u64,
        limit: u64,
    ) -> Result<QuotaReservation, QuotaReserveError> {
        let generation = self.generation.load_full();
        let current = generation.used_bytes.load(Ordering::Relaxed);
        if bytes > limit.saturating_sub(current) {
            return Err(QuotaReserveError::LimitExceeded);
        }

        let next = current.saturating_add(bytes);
        match generation.used_bytes.compare_exchange_weak(
            current,
            next,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => Ok(QuotaReservation {
                generation,
                reserved_bytes: bytes,
                total_after_reserve: next,
            }),
            Err(_) => Err(QuotaReserveError::Contended),
        }
    }
}

impl QuotaAccount {
    fn replace_from_snapshot(&self, snapshot: &UserQuotaSnapshot) {
        self.counters
            .replace(snapshot.used_bytes, snapshot.last_reset_epoch_secs);
    }
}

impl UserQuotaHandle {
    /// Returns the immutable incarnation owned by this handle.
    pub(crate) fn incarnation(&self) -> UserIncarnation {
        self.incarnation
    }

    #[inline]
    pub(crate) fn used(&self) -> u64 {
        self.counters.used()
    }

    #[inline]
    pub(crate) fn charge(&self, bytes: u64) -> u64 {
        self.counters.charge(bytes)
    }

    #[inline]
    pub(crate) fn try_reserve(
        &self,
        bytes: u64,
        limit: u64,
    ) -> Result<QuotaReservation, QuotaReserveError> {
        self.counters.try_reserve(bytes, limit)
    }

    /// Resets only the quota incarnation captured by this handle.
    pub(crate) fn reset(&self, now_epoch_secs: u64) -> UserQuotaSnapshot {
        self.counters.replace(0, now_epoch_secs);
        UserQuotaSnapshot {
            used_bytes: 0,
            last_reset_epoch_secs: now_epoch_secs,
        }
    }
}

impl QuotaReservation {
    /// Returns the number of bytes held by this reservation.
    pub(crate) fn reserved_bytes(&self) -> u64 {
        self.reserved_bytes
    }

    /// Commits the complete reservation and returns the generation-local total.
    pub(crate) fn commit(mut self) -> u64 {
        self.reserved_bytes = 0;
        self.total_after_reserve
    }

    /// Commits part of the reservation and refunds the remainder.
    pub(crate) fn settle(mut self, committed_bytes: u64) {
        let committed_bytes = committed_bytes.min(self.reserved_bytes);
        refund_generation(
            self.generation.as_ref(),
            self.reserved_bytes - committed_bytes,
        );
        self.reserved_bytes = 0;
    }
}

impl Drop for QuotaReservation {
    fn drop(&mut self) {
        refund_generation(self.generation.as_ref(), self.reserved_bytes);
    }
}

fn refund_generation(generation: &QuotaGeneration, bytes: u64) {
    if bytes == 0 {
        return;
    }
    let mut current = generation.used_bytes.load(Ordering::Relaxed);
    loop {
        let next = current.saturating_sub(bytes);
        match generation.used_bytes.compare_exchange_weak(
            current,
            next,
            Ordering::Relaxed,
            Ordering::Relaxed,
        ) {
            Ok(_) => return,
            Err(observed) => current = observed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats::Stats;
    use std::sync::Barrier;

    #[test]
    fn quota_counters_are_shared_across_stats_generations() {
        let store = Arc::new(QuotaStore::default());
        let first = Stats::with_quota_store(store.clone());
        store.user("alice").charge(512);
        assert_eq!(first.get_user_quota_used("alice"), 512);

        let second = Stats::with_quota_store(store);
        assert_eq!(second.get_user_quota_used("alice"), 512);
        second.reset_user_quota("alice");
        assert_eq!(first.get_user_quota_used("alice"), 0);
    }

    #[test]
    fn quota_snapshot_never_combines_different_generations() {
        const ITERATIONS: u64 = 10_000;

        let store = Arc::new(QuotaStore::default());
        store.load("alice", 1, 1);
        let barrier = Arc::new(Barrier::new(2));
        let writer_store = Arc::clone(&store);
        let writer_barrier = Arc::clone(&barrier);
        let writer = std::thread::spawn(move || {
            writer_barrier.wait();
            for generation in 2..=ITERATIONS {
                writer_store.load("alice", generation, generation);
            }
        });

        barrier.wait();
        for _ in 0..ITERATIONS {
            let snapshot = store.snapshot().remove("alice").unwrap();
            assert_eq!(snapshot.used_bytes, snapshot.last_reset_epoch_secs);
        }
        writer.join().unwrap();
    }

    #[test]
    fn repeated_old_generation_refunds_leave_new_usage_intact() {
        const ITERATIONS: u64 = 10_000;

        let store = QuotaStore::default();
        let state = store.user("alice");
        for generation in 1..=ITERATIONS {
            let reservation = state.try_reserve(80, 100).unwrap();
            store.load("alice", 40, generation);
            drop(reservation);
            assert_eq!(store.used("alice"), 40);
            store.reset("alice", generation);
        }
    }

    #[test]
    fn retired_incarnation_cannot_charge_recreated_username() {
        let store = QuotaStore::default();
        store.activate_fresh("alice", 1);
        let retired = store.handle_exact("alice", 1).unwrap();
        retired.charge(40);
        store.retire_through("alice", 2);
        store.activate_fresh("alice", 3);

        retired.charge(20);

        assert_eq!(retired.used(), 60);
        assert_eq!(store.handle_exact("alice", 3).unwrap().used(), 0);
    }

    #[test]
    fn credential_rotation_preserves_usage_without_sharing_future_charges() {
        let store = QuotaStore::default();
        store.activate_fresh("alice", 1);
        let old = store.handle_exact("alice", 1).unwrap();
        old.charge(40);
        store.advance_preserving_usage("alice", 2);
        let current = store.handle_exact("alice", 2).unwrap();

        old.charge(20);

        assert_eq!(old.used(), 60);
        assert_eq!(current.used(), 40);
    }

    #[test]
    fn captured_reset_handle_cannot_reset_a_new_incarnation() {
        let store = QuotaStore::default();
        store.activate_fresh("alice", 1);
        let reset_target = store.handle_exact("alice", 1).unwrap();
        reset_target.charge(40);
        store.advance_preserving_usage("alice", 2);
        let current = store.handle_exact("alice", 2).unwrap();
        current.charge(20);

        reset_target.reset(7);

        assert_eq!(reset_target.used(), 0);
        assert_eq!(current.used(), 60);
    }

    #[test]
    fn stale_retirement_cannot_remove_newer_quota_owner() {
        let store = QuotaStore::default();
        store.activate_fresh("alice", 1);
        store.retire_through("alice", 2);
        store.activate_fresh("alice", 3);

        store.retire_through("alice", 2);

        assert!(store.handle_exact("alice", 3).is_some());
    }

    #[test]
    fn old_reservation_refund_does_not_debit_recreated_username() {
        let store = QuotaStore::default();
        store.activate_fresh("alice", 1);
        let old = store.handle_exact("alice", 1).unwrap();
        let reservation = old.try_reserve(80, 100).unwrap();
        store.retire_through("alice", 2);
        store.activate_fresh("alice", 3);
        let current = store.handle_exact("alice", 3).unwrap();
        current.charge(50);

        drop(reservation);

        assert_eq!(old.used(), 0);
        assert_eq!(current.used(), 50);
    }
}
