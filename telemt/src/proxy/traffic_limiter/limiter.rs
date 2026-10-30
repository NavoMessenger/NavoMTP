use crate::config::CidrRateLimitKey;

use super::*;

impl ScopeMetrics {
    pub(super) fn throttle(&self, direction: RateDirection) {
        match direction {
            RateDirection::Up => {
                self.throttle_up_total.fetch_add(1, Ordering::Relaxed);
            }
            RateDirection::Down => {
                self.throttle_down_total.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    pub(super) fn wait_ms(&self, direction: RateDirection, wait_ms: u64) {
        match direction {
            RateDirection::Up => {
                self.wait_up_ms_total.fetch_add(wait_ms, Ordering::Relaxed);
            }
            RateDirection::Down => {
                self.wait_down_ms_total
                    .fetch_add(wait_ms, Ordering::Relaxed);
            }
        }
    }

    pub(super) fn contention(&self, direction: RateDirection) -> Arc<CasContentionMetrics> {
        match direction {
            RateDirection::Up => Arc::clone(&self.contention_up),
            RateDirection::Down => Arc::clone(&self.contention_down),
        }
    }

    pub(super) fn reserve_cas_retry_exhausted(&self, direction: RateDirection) {
        let metrics = match direction {
            RateDirection::Up => self.contention_up.as_ref(),
            RateDirection::Down => self.contention_down.as_ref(),
        };
        metrics
            .reserve_exhausted_total
            .fetch_add(1, Ordering::Relaxed);
    }
}

impl TrafficLimiter {
    /// Creates an empty limiter with no active rate-limit policy.
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            policy: ArcSwap::from_pointee(PolicySnapshot::default()),
            policy_update: ParkingMutex::new(()),
            user_buckets: ShardedRegistry::new(REGISTRY_SHARDS),
            cidr_buckets: ShardedRegistry::new(REGISTRY_SHARDS),
            user_scope: ScopeMetrics::default(),
            cidr_scope: ScopeMetrics::default(),
            last_cleanup_epoch_secs: AtomicU64::new(0),
        })
    }

    #[cfg(test)]
    /// Replaces the in-memory policy for isolated limiter tests.
    pub fn apply_policy(
        &self,
        user_limits: HashMap<String, RateLimitBps>,
        cidr_limits: HashMap<CidrRateLimitKey, RateLimitBps>,
    ) {
        let _ = self.apply_policy_inner(None, user_limits, cidr_limits);
    }

    /// Publishes policy only when the source runtime is not older than the active source.
    pub(crate) fn apply_policy_from_source(
        &self,
        source_generation: u64,
        user_limits: HashMap<String, RateLimitBps>,
        cidr_limits: HashMap<CidrRateLimitKey, RateLimitBps>,
    ) -> bool {
        self.apply_policy_inner(Some(source_generation), user_limits, cidr_limits)
    }

    fn apply_policy_inner(
        &self,
        source_generation: Option<u64>,
        user_limits: HashMap<String, RateLimitBps>,
        cidr_limits: HashMap<CidrRateLimitKey, RateLimitBps>,
    ) -> bool {
        let filtered_users = user_limits
            .into_iter()
            .filter(|(_, limit)| limit.up_bps > 0 || limit.down_bps > 0)
            .collect::<HashMap<_, _>>();

        let mut cidr_rules_v4 = Vec::new();
        let mut cidr_rules_v6 = Vec::new();
        let mut cidr_auto_rules_v4 = Vec::new();
        let mut cidr_auto_rules_v6 = Vec::new();
        let mut cidr_rule_keys = HashSet::new();
        for (key, limits) in cidr_limits {
            if limits.up_bps == 0 && limits.down_bps == 0 {
                continue;
            }
            match key {
                CidrRateLimitKey::Network(cidr) => {
                    let key = cidr.to_string();
                    let rule = CidrRule {
                        key: key.clone(),
                        cidr,
                        limits,
                        prefix_len: cidr.prefix(),
                    };
                    cidr_rule_keys.insert(key);
                    match rule.cidr {
                        IpNetwork::V4(_) => cidr_rules_v4.push(rule),
                        IpNetwork::V6(_) => cidr_rules_v6.push(rule),
                    }
                }
                CidrRateLimitKey::AutoV4(prefix_len) => {
                    cidr_auto_rules_v4.push(CidrAutoRule { prefix_len, limits });
                }
                CidrRateLimitKey::AutoV6(prefix_len) => {
                    cidr_auto_rules_v6.push(CidrAutoRule { prefix_len, limits });
                }
                CidrRateLimitKey::AutoDual(prefix_len) => {
                    cidr_auto_rules_v4.push(CidrAutoRule { prefix_len, limits });
                    cidr_auto_rules_v6.push(CidrAutoRule {
                        prefix_len: prefix_len.saturating_mul(4),
                        limits,
                    });
                }
            }
        }

        cidr_rules_v4.sort_by(|a, b| b.prefix_len.cmp(&a.prefix_len));
        cidr_rules_v6.sort_by(|a, b| b.prefix_len.cmp(&a.prefix_len));
        cidr_auto_rules_v4.sort_by(|a, b| b.prefix_len.cmp(&a.prefix_len));
        cidr_auto_rules_v6.sort_by(|a, b| b.prefix_len.cmp(&a.prefix_len));
        let cidr_policy_entries =
            cidr_rule_keys.len() + cidr_auto_rules_v4.len() + cidr_auto_rules_v6.len();

        let policy_update = self.policy_update.lock();
        let current = self.policy.load_full();
        if source_generation.is_some_and(|source| source < current.source_generation) {
            return false;
        }
        // Revision wrap could otherwise let an old lease restore stale rates.
        let Some(revision) = current.revision.checked_add(1) else {
            return false;
        };
        let source_generation = source_generation.unwrap_or(current.source_generation);

        self.user_scope
            .policy_entries
            .store(filtered_users.len() as u64, Ordering::Relaxed);
        self.cidr_scope
            .policy_entries
            .store(cidr_policy_entries as u64, Ordering::Relaxed);

        self.policy.store(Arc::new(PolicySnapshot {
            revision,
            source_generation,
            user_limits: filtered_users,
            cidr_rules_v4,
            cidr_rules_v6,
            cidr_auto_rules_v4,
            cidr_auto_rules_v6,
            cidr_rule_keys,
        }));

        drop(policy_update);
        self.maybe_cleanup();
        true
    }

    /// Creates a lease that follows policy revisions for one client identity.
    pub fn acquire_lease(
        self: &Arc<Self>,
        user: &str,
        client_ip: IpAddr,
    ) -> Option<Arc<TrafficLease>> {
        let policy = self.policy.load_full();
        let binding = self.build_binding(user, client_ip, &policy);
        Some(Arc::new(TrafficLease {
            limiter: Arc::clone(self),
            user: user.to_string(),
            client_ip,
            binding: ArcSwap::from(binding),
            refresh: ParkingMutex::new(()),
        }))
    }

    pub(super) fn build_binding(
        self: &Arc<Self>,
        user: &str,
        client_ip: IpAddr,
        policy: &PolicySnapshot,
    ) -> Arc<TrafficLeaseBinding> {
        let mut user_bucket = None;
        if let Some(limit) = policy.user_limits.get(user).copied() {
            let bucket = self.user_buckets.get_or_insert_with(
                user,
                || {
                    UserBucket::new(
                        policy.revision,
                        limit,
                        self.user_scope.contention(RateDirection::Up),
                        self.user_scope.contention(RateDirection::Down),
                    )
                },
                |bucket| {
                    bucket.active_leases.fetch_add(1, Ordering::Relaxed);
                },
            );
            bucket.set_rates(policy.revision, limit);
            self.user_scope
                .active_leases
                .fetch_add(1, Ordering::Relaxed);
            user_bucket = Some(bucket);
        }

        let mut cidr_bucket = None;
        let mut cidr_user_key = None;
        let mut cidr_user_share = None;
        if let Some(rule_match) = policy.match_cidr(client_ip) {
            let (key, limits) = match &rule_match {
                CidrPolicyMatch::Explicit(rule) => (rule.key.as_str(), rule.limits),
                CidrPolicyMatch::Auto { key, limits } => (key.as_str(), *limits),
            };
            let bucket = self.cidr_buckets.get_or_insert_with(
                key,
                || {
                    CidrBucket::new(
                        policy.revision,
                        limits,
                        self.cidr_scope.contention(RateDirection::Up),
                        self.cidr_scope.contention(RateDirection::Down),
                    )
                },
                |bucket| {
                    bucket.active_leases.fetch_add(1, Ordering::Relaxed);
                },
            );
            bucket.set_rates(policy.revision, limits);
            self.cidr_scope
                .active_leases
                .fetch_add(1, Ordering::Relaxed);
            let share = bucket.acquire_user_share(user);
            cidr_user_key = Some(user.to_string());
            cidr_user_share = Some(share);
            cidr_bucket = Some(bucket);
        }

        Arc::new(TrafficLeaseBinding {
            limiter: Arc::clone(self),
            revision: policy.revision,
            user_bucket,
            cidr_bucket,
            cidr_user_key,
            cidr_user_share,
        })
    }

    /// Captures limiter telemetry without locking bucket registries.
    pub fn metrics_snapshot(&self) -> TrafficLimiterMetricsSnapshot {
        TrafficLimiterMetricsSnapshot {
            user_throttle_up_total: self.user_scope.throttle_up_total.load(Ordering::Relaxed),
            user_throttle_down_total: self.user_scope.throttle_down_total.load(Ordering::Relaxed),
            cidr_throttle_up_total: self.cidr_scope.throttle_up_total.load(Ordering::Relaxed),
            cidr_throttle_down_total: self.cidr_scope.throttle_down_total.load(Ordering::Relaxed),
            user_wait_up_ms_total: self.user_scope.wait_up_ms_total.load(Ordering::Relaxed),
            user_wait_down_ms_total: self.user_scope.wait_down_ms_total.load(Ordering::Relaxed),
            cidr_wait_up_ms_total: self.cidr_scope.wait_up_ms_total.load(Ordering::Relaxed),
            cidr_wait_down_ms_total: self.cidr_scope.wait_down_ms_total.load(Ordering::Relaxed),
            user_reserve_cas_retry_exhausted_up_total: self
                .user_scope
                .contention_up
                .reserve_exhausted_total
                .load(Ordering::Relaxed),
            user_reserve_cas_retry_exhausted_down_total: self
                .user_scope
                .contention_down
                .reserve_exhausted_total
                .load(Ordering::Relaxed),
            user_refund_cas_retry_exhausted_up_total: self
                .user_scope
                .contention_up
                .refund_exhausted_total
                .load(Ordering::Relaxed),
            user_refund_cas_retry_exhausted_down_total: self
                .user_scope
                .contention_down
                .refund_exhausted_total
                .load(Ordering::Relaxed),
            cidr_reserve_cas_retry_exhausted_up_total: self
                .cidr_scope
                .contention_up
                .reserve_exhausted_total
                .load(Ordering::Relaxed),
            cidr_reserve_cas_retry_exhausted_down_total: self
                .cidr_scope
                .contention_down
                .reserve_exhausted_total
                .load(Ordering::Relaxed),
            cidr_refund_cas_retry_exhausted_up_total: self
                .cidr_scope
                .contention_up
                .refund_exhausted_total
                .load(Ordering::Relaxed),
            cidr_refund_cas_retry_exhausted_down_total: self
                .cidr_scope
                .contention_down
                .refund_exhausted_total
                .load(Ordering::Relaxed),
            user_active_leases: self.user_scope.active_leases.load(Ordering::Relaxed),
            cidr_active_leases: self.cidr_scope.active_leases.load(Ordering::Relaxed),
            user_policy_entries: self.user_scope.policy_entries.load(Ordering::Relaxed),
            cidr_policy_entries: self.cidr_scope.policy_entries.load(Ordering::Relaxed),
        }
    }

    /// Sets fixed contention counters for renderer mapping tests.
    #[cfg(test)]
    pub(crate) fn set_cas_contention_metrics_for_test(&self, values: [u64; 8]) {
        let [
            user_reserve_up,
            user_reserve_down,
            user_refund_up,
            user_refund_down,
            cidr_reserve_up,
            cidr_reserve_down,
            cidr_refund_up,
            cidr_refund_down,
        ] = values;
        for (counter, value) in [
            (
                &self.user_scope.contention_up.reserve_exhausted_total,
                user_reserve_up,
            ),
            (
                &self.user_scope.contention_down.reserve_exhausted_total,
                user_reserve_down,
            ),
            (
                &self.user_scope.contention_up.refund_exhausted_total,
                user_refund_up,
            ),
            (
                &self.user_scope.contention_down.refund_exhausted_total,
                user_refund_down,
            ),
            (
                &self.cidr_scope.contention_up.reserve_exhausted_total,
                cidr_reserve_up,
            ),
            (
                &self.cidr_scope.contention_down.reserve_exhausted_total,
                cidr_reserve_down,
            ),
            (
                &self.cidr_scope.contention_up.refund_exhausted_total,
                cidr_refund_up,
            ),
            (
                &self.cidr_scope.contention_down.refund_exhausted_total,
                cidr_refund_down,
            ),
        ] {
            counter.store(value, Ordering::Relaxed);
        }
    }

    pub(super) fn observe_throttle(
        &self,
        direction: RateDirection,
        blocked_user: bool,
        blocked_cidr: bool,
    ) {
        if blocked_user {
            self.user_scope.throttle(direction);
        }
        if blocked_cidr {
            self.cidr_scope.throttle(direction);
        }
    }

    pub(super) fn observe_wait(
        &self,
        direction: RateDirection,
        blocked_user: bool,
        blocked_cidr: bool,
        wait_ms: u64,
    ) {
        if blocked_user {
            self.user_scope.wait_ms(direction, wait_ms);
        }
        if blocked_cidr {
            self.cidr_scope.wait_ms(direction, wait_ms);
        }
    }

    pub(super) fn maybe_cleanup(&self) {
        let now_epoch_secs = now_epoch_secs();
        let last = self.last_cleanup_epoch_secs.load(Ordering::Relaxed);
        if now_epoch_secs.saturating_sub(last) < CLEANUP_INTERVAL_SECS {
            return;
        }
        if self
            .last_cleanup_epoch_secs
            .compare_exchange(last, now_epoch_secs, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        let policy = self.policy.load_full();
        self.user_buckets.retain(|user, bucket| {
            bucket.active_leases.load(Ordering::Relaxed) > 0
                || policy.user_limits.contains_key(user)
        });
        self.cidr_buckets.retain(|cidr_key, bucket| {
            bucket.cleanup_idle_users();
            bucket.active_leases.load(Ordering::Relaxed) > 0
                || policy.cidr_rule_keys.contains(cidr_key)
        });
    }
}
