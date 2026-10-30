use super::*;

impl ReserveCasBudget {
    pub(super) fn new() -> Self {
        Self {
            remaining: RESERVE_CAS_ATTEMPT_LIMIT,
        }
    }

    fn take(&mut self) -> bool {
        if self.remaining == 0 {
            return false;
        }
        self.remaining -= 1;
        true
    }

    pub(super) fn is_exhausted(&self) -> bool {
        self.remaining == 0
    }
}

impl AtomicRatePair {
    pub(super) fn new(revision: u64, limits: RateLimitBps) -> Self {
        let rates = Self::default();
        rates.set(revision, limits);
        rates
    }

    pub(super) fn set(&self, revision: u64, limits: RateLimitBps) {
        let mut current_revision = self.revision.lock();
        if revision < *current_revision {
            return;
        }
        self.up_bps.store(limits.up_bps, Ordering::Release);
        self.down_bps.store(limits.down_bps, Ordering::Release);
        *current_revision = revision;
    }

    pub(super) fn get(&self, direction: RateDirection) -> u64 {
        match direction {
            RateDirection::Up => self.up_bps.load(Ordering::Acquire),
            RateDirection::Down => self.down_bps.load(Ordering::Acquire),
        }
    }
}

impl DirectionBucket {
    fn new(contention: Arc<CasContentionMetrics>) -> Self {
        Self {
            state: AtomicU64::new(0),
            contention,
            #[cfg(test)]
            forced_reserve_failures: AtomicU64::new(0),
            #[cfg(test)]
            forced_refund_failures: AtomicU64::new(0),
            #[cfg(test)]
            reserve_cas_attempts: AtomicU64::new(0),
            #[cfg(test)]
            refund_cas_attempts: AtomicU64::new(0),
        }
    }

    #[inline(always)]
    fn compare_exchange_reserve(&self, current: u64, next: u64) -> Result<u64, u64> {
        #[cfg(test)]
        if self.should_force_reserve_failure() {
            return Err(current);
        }
        self.state
            .compare_exchange(current, next, Ordering::Relaxed, Ordering::Relaxed)
    }

    #[inline(always)]
    fn compare_exchange_refund(&self, current: u64, next: u64) -> Result<u64, u64> {
        #[cfg(test)]
        if self.should_force_refund_failure() {
            return Err(current);
        }
        self.state
            .compare_exchange(current, next, Ordering::Relaxed, Ordering::Relaxed)
    }

    fn unpack(state: u64) -> (u64, u64) {
        (state >> PACKED_USAGE_BITS, state & PACKED_USAGE_MASK)
    }

    fn pack(epoch: u64, used: u64) -> Option<u64> {
        if epoch > PACKED_EPOCH_MAX || used > PACKED_USAGE_MASK {
            return None;
        }
        Some((epoch << PACKED_USAGE_BITS) | used)
    }

    #[cfg(test)]
    pub(super) fn used_at(&self, epoch: u64) -> Option<u64> {
        if epoch > PACKED_EPOCH_MAX {
            return None;
        }
        let (current_epoch, used) = Self::unpack(self.state.load(Ordering::Relaxed));
        (current_epoch == epoch).then_some(used)
    }

    fn used_in_epoch(&self, epoch: u64) -> Result<u64, BucketReserveError> {
        let (observed_epoch, used) = Self::unpack(self.state.load(Ordering::Relaxed));
        if observed_epoch != epoch {
            return Err(BucketReserveError::StaleEpoch);
        }
        Ok(used)
    }

    pub(super) fn try_reserve_at(
        self: &Arc<Self>,
        epoch: u64,
        cap: u64,
        requested: u64,
        budget: &mut ReserveCasBudget,
    ) -> Result<Option<DirectionDebit>, BucketReserveError> {
        if requested == 0 || cap == 0 {
            return Ok(None);
        }
        if epoch > PACKED_EPOCH_MAX {
            return Err(BucketReserveError::StaleEpoch);
        }
        let cap = cap.min(PACKED_USAGE_MASK);

        let mut observed = self.state.load(Ordering::Relaxed);
        // The transaction-owned budget bounds retries across every participating bucket.
        loop {
            let (observed_epoch, observed_used) = Self::unpack(observed);
            if observed_epoch > epoch {
                return Err(BucketReserveError::StaleEpoch);
            }
            let used = if observed_epoch == epoch {
                observed_used
            } else {
                0
            };
            if used >= cap {
                return Ok(None);
            }
            let remaining = cap - used;
            let grant = requested.min(remaining);
            if grant == 0 {
                return Ok(None);
            }
            let Some(next) = Self::pack(epoch, used + grant) else {
                return Err(BucketReserveError::StaleEpoch);
            };
            if !budget.take() {
                return Err(BucketReserveError::Contended);
            }
            match self.compare_exchange_reserve(observed, next) {
                Ok(_) => {
                    return Ok(Some(DirectionDebit {
                        bucket: Arc::clone(self),
                        epoch,
                        refundable: grant,
                    }));
                }
                Err(actual) => observed = actual,
            }
        }
    }

    fn refund_at(&self, epoch: u64, bytes: u64) -> BucketRefundOutcome {
        if bytes == 0 || epoch > PACKED_EPOCH_MAX {
            return BucketRefundOutcome::Complete;
        }
        let mut observed = self.state.load(Ordering::Relaxed);
        for _ in 0..REFUND_CAS_ATTEMPT_LIMIT {
            let (observed_epoch, used) = Self::unpack(observed);
            if observed_epoch != epoch || used == 0 {
                return BucketRefundOutcome::Complete;
            }
            let next = Self::pack(epoch, used.saturating_sub(bytes)).unwrap_or(observed);
            match self.compare_exchange_refund(observed, next) {
                Ok(_) => return BucketRefundOutcome::Complete,
                Err(actual) => observed = actual,
            }
        }
        let (observed_epoch, used) = Self::unpack(observed);
        if observed_epoch != epoch || used == 0 {
            return BucketRefundOutcome::Complete;
        }
        // Retain the charge after bounded contention so accounting cannot under-enforce.
        self.contention
            .refund_exhausted_total
            .fetch_add(1, Ordering::Relaxed);
        BucketRefundOutcome::Contended
    }
}
impl DirectionDebit {
    fn granted(&self) -> u64 {
        self.refundable
    }

    pub(super) fn shrink_to(&mut self, retained: u64) -> BucketRefundOutcome {
        let retained = retained.min(self.refundable);
        let outcome = self
            .bucket
            .refund_at(self.epoch, self.refundable - retained);
        // Never retry the attempted delta in Drop; failed refunds remain charged.
        self.refundable = retained;
        outcome
    }

    fn refund_all(&mut self) -> BucketRefundOutcome {
        self.shrink_to(0)
    }

    pub(super) fn settle(&mut self, committed: u64) {
        let _ = self.shrink_to(committed);
        self.refundable = 0;
    }

    pub(super) fn commit_all(&mut self) -> u64 {
        let committed = self.refundable;
        self.refundable = 0;
        committed
    }
}

impl Drop for DirectionDebit {
    fn drop(&mut self) {
        let _ = self.bucket.refund_at(self.epoch, self.refundable);
    }
}

impl UserBucket {
    pub(super) fn new(
        revision: u64,
        limits: RateLimitBps,
        up_contention: Arc<CasContentionMetrics>,
        down_contention: Arc<CasContentionMetrics>,
    ) -> Self {
        Self {
            rates: AtomicRatePair::new(revision, limits),
            up: Arc::new(DirectionBucket::new(up_contention)),
            down: Arc::new(DirectionBucket::new(down_contention)),
            active_leases: AtomicU64::new(0),
        }
    }

    pub(super) fn set_rates(&self, revision: u64, limits: RateLimitBps) {
        self.rates.set(revision, limits);
    }

    pub(super) fn try_reserve(
        &self,
        direction: RateDirection,
        epoch: u64,
        requested: u64,
        budget: &mut ReserveCasBudget,
    ) -> Result<BucketReservation, BucketReserveError> {
        let cap_bps = self.rates.get(direction);
        if cap_bps == 0 {
            return Ok(BucketReservation {
                granted: requested,
                debit: None,
            });
        }
        let cap = bytes_per_epoch(cap_bps);
        let debit = match direction {
            RateDirection::Up => self.up.try_reserve_at(epoch, cap, requested, budget)?,
            RateDirection::Down => self.down.try_reserve_at(epoch, cap, requested, budget)?,
        };
        let granted = debit.as_ref().map(DirectionDebit::granted).unwrap_or(0);
        Ok(BucketReservation { granted, debit })
    }
}

impl CidrDirectionBucket {
    fn new(contention: Arc<CasContentionMetrics>) -> Self {
        Self {
            used: Arc::new(DirectionBucket::new(Arc::clone(&contention))),
            active_users: Arc::new(DirectionBucket::new(contention)),
        }
    }

    pub(super) fn try_reserve(
        &self,
        user_state: &CidrUserDirectionState,
        epoch: u64,
        cap_epoch: u64,
        requested: u64,
        budget: &mut ReserveCasBudget,
    ) -> Result<CidrReservation, BucketReserveError> {
        if requested == 0 || cap_epoch == 0 {
            return Ok(CidrReservation {
                granted: 0,
                aggregate_debit: None,
                user_debit: None,
            });
        }

        if !user_state.ensure_active(epoch, &self.active_users, budget)? {
            return Ok(CidrReservation {
                granted: 0,
                aggregate_debit: None,
                user_debit: None,
            });
        }
        let active_users = self.active_users.used_in_epoch(epoch)?;
        let active_users = active_users.max(1);
        let fair_share = cap_epoch.saturating_div(active_users).max(1);

        let user_used = user_state.used.used_in_epoch(epoch)?;
        let guaranteed_remaining = fair_share.saturating_sub(user_used);
        let (user_cap, desired) = if guaranteed_remaining > 0 {
            (fair_share, requested.min(guaranteed_remaining))
        } else {
            (PACKED_USAGE_MASK, requested.min(MAX_BORROW_CHUNK_BYTES))
        };
        let mut user_debit = user_state
            .used
            .try_reserve_at(epoch, user_cap, desired, budget)?;

        // A competing reservation can consume the guaranteed share between the snapshot and CAS.
        if user_debit.is_none() && guaranteed_remaining > 0 {
            let refreshed_used = user_state.used.used_in_epoch(epoch)?;
            if refreshed_used >= fair_share {
                user_debit = user_state.used.try_reserve_at(
                    epoch,
                    PACKED_USAGE_MASK,
                    requested.min(MAX_BORROW_CHUNK_BYTES),
                    budget,
                )?;
            } else {
                user_debit = user_state.used.try_reserve_at(
                    epoch,
                    fair_share,
                    requested.min(fair_share - refreshed_used),
                    budget,
                )?;
            }
            if user_debit.is_none() {
                return Err(BucketReserveError::FairShareContended);
            }
        }

        let Some(mut user_debit) = user_debit else {
            return Ok(CidrReservation {
                granted: 0,
                aggregate_debit: None,
                user_debit: None,
            });
        };
        let user_granted = user_debit.granted();
        let Some(aggregate_debit) =
            self.used
                .try_reserve_at(epoch, cap_epoch, user_granted, budget)?
        else {
            return Ok(CidrReservation {
                granted: 0,
                aggregate_debit: None,
                user_debit: None,
            });
        };
        let granted = aggregate_debit.granted();
        if granted < user_granted {
            let _ = user_debit.shrink_to(granted);
        }
        Ok(CidrReservation {
            granted,
            aggregate_debit: Some(aggregate_debit),
            user_debit: Some(user_debit),
        })
    }
}

#[cfg(test)]
impl Default for CidrDirectionBucket {
    fn default() -> Self {
        Self::new(Arc::new(CasContentionMetrics::default()))
    }
}

impl CidrUserDirectionState {
    fn new(contention: Arc<CasContentionMetrics>) -> Self {
        Self {
            used: Arc::new(DirectionBucket::new(contention)),
        }
    }

    pub(super) fn ensure_active(
        &self,
        epoch: u64,
        active_users: &Arc<DirectionBucket>,
        budget: &mut ReserveCasBudget,
    ) -> Result<bool, BucketReserveError> {
        if epoch > PACKED_EPOCH_MAX {
            return Err(BucketReserveError::StaleEpoch);
        }
        let mut observed = self.used.state.load(Ordering::Relaxed);
        // Every retry spends shared reserve budget before publishing the user epoch.
        loop {
            let (observed_epoch, _) = DirectionBucket::unpack(observed);
            if observed_epoch == epoch {
                return Ok(true);
            }
            if observed_epoch > epoch {
                return Err(BucketReserveError::StaleEpoch);
            }
            let Some(mut active_debit) =
                active_users.try_reserve_at(epoch, PACKED_USAGE_MASK, 1, budget)?
            else {
                return Ok(false);
            };
            let Some(next) = DirectionBucket::pack(epoch, 0) else {
                return Err(BucketReserveError::StaleEpoch);
            };
            if !budget.take() {
                if active_debit.refund_all() == BucketRefundOutcome::Contended {
                    return Err(BucketReserveError::ReserveAndRefundContended);
                }
                return Err(BucketReserveError::Contended);
            }
            match self.used.compare_exchange_reserve(observed, next) {
                Ok(_) => {
                    active_debit.commit_all();
                    return Ok(true);
                }
                Err(actual) => {
                    let refund = active_debit.refund_all();
                    let (actual_epoch, _) = DirectionBucket::unpack(actual);
                    if refund == BucketRefundOutcome::Contended {
                        return Err(if budget.is_exhausted() {
                            BucketReserveError::ReserveAndRefundContended
                        } else {
                            BucketReserveError::RefundContended
                        });
                    }
                    if actual_epoch == epoch {
                        return Ok(true);
                    }
                    observed = actual;
                }
            }
        }
    }
}

#[cfg(test)]
impl Default for CidrUserDirectionState {
    fn default() -> Self {
        Self::new(Arc::new(CasContentionMetrics::default()))
    }
}

impl CidrUserShare {
    pub(super) fn new(
        up_contention: Arc<CasContentionMetrics>,
        down_contention: Arc<CasContentionMetrics>,
    ) -> Self {
        Self {
            active_conns: AtomicU64::new(0),
            up: CidrUserDirectionState::new(up_contention),
            down: CidrUserDirectionState::new(down_contention),
        }
    }
}

impl CidrBucket {
    pub(super) fn new(
        revision: u64,
        limits: RateLimitBps,
        up_contention: Arc<CasContentionMetrics>,
        down_contention: Arc<CasContentionMetrics>,
    ) -> Self {
        Self {
            rates: AtomicRatePair::new(revision, limits),
            up: CidrDirectionBucket::new(up_contention),
            down: CidrDirectionBucket::new(down_contention),
            users: ShardedRegistry::new(REGISTRY_SHARDS),
            active_leases: AtomicU64::new(0),
        }
    }

    pub(super) fn set_rates(&self, revision: u64, limits: RateLimitBps) {
        self.rates.set(revision, limits);
    }

    pub(super) fn acquire_user_share(&self, user: &str) -> Arc<CidrUserShare> {
        let up_contention = Arc::clone(&self.up.used.contention);
        let down_contention = Arc::clone(&self.down.used.contention);
        self.users.get_or_insert_with(
            user,
            || CidrUserShare::new(up_contention, down_contention),
            |share| {
                share.active_conns.fetch_add(1, Ordering::Relaxed);
            },
        )
    }

    pub(super) fn release_user_share(&self, user: &str, share: &Arc<CidrUserShare>) {
        decrement_atomic_saturating(&share.active_conns, 1);
        let share_for_remove = Arc::clone(share);
        let _ = self.users.remove_if(user, |candidate| {
            Arc::ptr_eq(candidate, &share_for_remove)
                && candidate.active_conns.load(Ordering::Relaxed) == 0
        });
    }

    pub(super) fn try_reserve_for_user(
        &self,
        direction: RateDirection,
        share: &CidrUserShare,
        epoch: u64,
        requested: u64,
        budget: &mut ReserveCasBudget,
    ) -> Result<CidrReservation, BucketReserveError> {
        let cap_bps = self.rates.get(direction);
        if cap_bps == 0 {
            return Ok(CidrReservation {
                granted: requested,
                aggregate_debit: None,
                user_debit: None,
            });
        }
        let cap_epoch = bytes_per_epoch(cap_bps);
        match direction {
            RateDirection::Up => self
                .up
                .try_reserve(&share.up, epoch, cap_epoch, requested, budget),
            RateDirection::Down => {
                self.down
                    .try_reserve(&share.down, epoch, cap_epoch, requested, budget)
            }
        }
    }

    pub(super) fn cleanup_idle_users(&self) {
        self.users
            .retain(|_, share| share.active_conns.load(Ordering::Relaxed) > 0);
    }
}
