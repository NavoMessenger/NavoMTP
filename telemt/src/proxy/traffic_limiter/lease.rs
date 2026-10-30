use super::*;

impl TrafficLease {
    fn current_binding(&self) -> Arc<TrafficLeaseBinding> {
        let policy = self.limiter.policy.load();
        let current = self.binding.load_full();
        if current.revision == policy.revision {
            return current;
        }
        drop(policy);

        let _refresh = self.refresh.lock();
        let policy = self.limiter.policy.load_full();
        let current = self.binding.load_full();
        if current.revision == policy.revision {
            return current;
        }
        let next = self
            .limiter
            .build_binding(&self.user, self.client_ip, &policy);
        self.binding.store(Arc::clone(&next));
        next
    }

    /// Reserves shaping budget until the associated I/O result is settled.
    pub(crate) fn try_reserve(
        &self,
        direction: RateDirection,
        requested: u64,
    ) -> TrafficReservation {
        let binding = self.current_binding();
        if requested == 0 {
            return TrafficReservation {
                result: TrafficConsumeResult {
                    granted: 0,
                    blocked_user: false,
                    blocked_cidr: false,
                },
                _binding: binding,
                user: None,
                cidr: None,
                cidr_user: None,
            };
        }
        if binding.user_bucket.is_none() && binding.cidr_bucket.is_none() {
            return TrafficReservation {
                result: TrafficConsumeResult {
                    granted: requested,
                    blocked_user: false,
                    blocked_cidr: false,
                },
                _binding: binding,
                user: None,
                cidr: None,
                cidr_user: None,
            };
        }

        let epoch = current_epoch();
        let mut budget = ReserveCasBudget::new();
        let mut granted = requested;
        let mut user_debit = None;
        if let Some(user_bucket) = binding.user_bucket.as_ref() {
            let user_reservation =
                match user_bucket.try_reserve(direction, epoch, granted, &mut budget) {
                    Ok(reservation) => reservation,
                    Err(error) => {
                        if error.exhausted_reserve_budget() {
                            self.limiter
                                .user_scope
                                .reserve_cas_retry_exhausted(direction);
                        }
                        return TrafficReservation {
                            result: TrafficConsumeResult {
                                granted: 0,
                                blocked_user: false,
                                blocked_cidr: false,
                            },
                            _binding: binding,
                            user: None,
                            cidr: None,
                            cidr_user: None,
                        };
                    }
                };
            user_debit = user_reservation.debit;
            if user_reservation.granted == 0 {
                self.limiter.observe_throttle(direction, true, false);
                return TrafficReservation {
                    result: TrafficConsumeResult {
                        granted: 0,
                        blocked_user: true,
                        blocked_cidr: false,
                    },
                    _binding: binding,
                    user: user_debit,
                    cidr: None,
                    cidr_user: None,
                };
            }
            granted = user_reservation.granted;
        }

        let mut cidr_debit = None;
        let mut cidr_user_debit = None;
        if let (Some(cidr_bucket), Some(cidr_user_share)) = (
            binding.cidr_bucket.as_ref(),
            binding.cidr_user_share.as_ref(),
        ) {
            let cidr_reservation = match cidr_bucket.try_reserve_for_user(
                direction,
                cidr_user_share,
                epoch,
                granted,
                &mut budget,
            ) {
                Ok(reservation) => reservation,
                Err(error) => {
                    if error.exhausted_reserve_budget() {
                        self.limiter
                            .cidr_scope
                            .reserve_cas_retry_exhausted(direction);
                    }
                    return TrafficReservation {
                        result: TrafficConsumeResult {
                            granted: 0,
                            blocked_user: false,
                            blocked_cidr: false,
                        },
                        _binding: binding,
                        user: user_debit,
                        cidr: None,
                        cidr_user: None,
                    };
                }
            };
            cidr_debit = cidr_reservation.aggregate_debit;
            cidr_user_debit = cidr_reservation.user_debit;
            if cidr_reservation.granted < granted
                && let Some(debit) = user_debit.as_mut()
            {
                let _ = debit.shrink_to(cidr_reservation.granted);
            }
            if cidr_reservation.granted == 0 {
                self.limiter.observe_throttle(direction, false, true);
                return TrafficReservation {
                    result: TrafficConsumeResult {
                        granted: 0,
                        blocked_user: false,
                        blocked_cidr: true,
                    },
                    _binding: binding,
                    user: user_debit,
                    cidr: cidr_debit,
                    cidr_user: cidr_user_debit,
                };
            }
            granted = cidr_reservation.granted;
        }

        TrafficReservation {
            result: TrafficConsumeResult {
                granted,
                blocked_user: false,
                blocked_cidr: false,
            },
            _binding: binding,
            user: user_debit,
            cidr: cidr_debit,
            cidr_user: cidr_user_debit,
        }
    }

    /// Immediately consumes the budget granted by all applicable limits.
    pub fn try_consume(&self, direction: RateDirection, requested: u64) -> TrafficConsumeResult {
        let reservation = self.try_reserve(direction, requested);
        let result = reservation.result();
        reservation.settle_written(result.granted);
        result
    }

    /// Records caller-observed limiter wait time for the blocking scopes.
    pub fn observe_wait_ms(
        &self,
        direction: RateDirection,
        blocked_user: bool,
        blocked_cidr: bool,
        wait_ms: u64,
    ) {
        if wait_ms == 0 {
            return;
        }
        self.limiter
            .observe_wait(direction, blocked_user, blocked_cidr, wait_ms);
    }
}

impl TrafficReservation {
    /// Returns the shaping decision associated with this reservation.
    pub(crate) fn result(&self) -> TrafficConsumeResult {
        self.result
    }

    /// Commits written bytes and refunds the uncommitted remainder.
    pub(crate) fn settle_written(mut self, committed: u64) {
        let committed = committed.min(self.result.granted);
        if let Some(debit) = self.user.as_mut() {
            debit.settle(committed);
        }
        if let Some(debit) = self.cidr.as_mut() {
            debit.settle(committed);
        }
        if let Some(debit) = self.cidr_user.as_mut() {
            debit.settle(committed);
        }
    }
}

impl Drop for TrafficLeaseBinding {
    fn drop(&mut self) {
        if let Some(bucket) = self.user_bucket.as_ref() {
            decrement_atomic_saturating(&bucket.active_leases, 1);
            decrement_atomic_saturating(&self.limiter.user_scope.active_leases, 1);
        }

        if let Some(bucket) = self.cidr_bucket.as_ref() {
            if let (Some(user_key), Some(share)) =
                (self.cidr_user_key.as_ref(), self.cidr_user_share.as_ref())
            {
                bucket.release_user_share(user_key, share);
            }
            decrement_atomic_saturating(&bucket.active_leases, 1);
            decrement_atomic_saturating(&self.limiter.cidr_scope.active_leases, 1);
        }
    }
}
