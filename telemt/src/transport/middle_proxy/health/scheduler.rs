use super::*;
use std::collections::VecDeque;
use tokio::task::Id;
#[cfg(test)]
mod tests;

/// Exact fairness and single-owner domain; DC sign remains part of the identity.
pub(super) type Group = (i32, IpFamily);

/// Immutable observation is fenced again before dispatch and when accepting completion.
pub(super) struct HealthObservation {
    /// Endpoint and floor-policy revisions used to derive this plan.
    pub(super) authority: (u64, u64),
    /// Active generation whose writers contribute coverage.
    pub(super) generation: u64,
    /// Family-local targets and global capacity projection.
    pub(super) floor: FamilyFloorPlan,
    /// Current non-draining writer IDs grouped by DC and endpoint.
    pub(super) ids: HashMap<(i32, SocketAddr), Vec<u64>>,
    /// Registry idle timestamps used only for refresh selection.
    pub(super) idle: HashMap<u64, u64>,
    /// Captured bindings; commit revalidates victim idleness when required.
    pub(super) bound: HashMap<u64, usize>,
}

/// Mutually exclusive network work selected for one group quantum.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum JobKind {
    /// Restores one missing writer through ordinary bounded admission.
    Recover,
    /// Restores coverage by replacing an eligible donor.
    Transfer,
    /// Replaces an idle writer before upstream expiry.
    Refresh,
    /// Applies the configured single-endpoint rotation cadence.
    Shadow,
}

/// Resource deferral consumes no network retry budget and preserves the eligibility deadline.
pub(super) enum JobOutcome {
    /// Work consumed its quantum and may return a refresh or shadow deadline.
    Completed(Option<Instant>),
    /// Capacity or authority prevented an operation; do not charge network backoff.
    Deferred,
}

/// Captured authority accompanies both successful results and JoinError ownership.
#[derive(Clone)]
pub(super) struct HealthJob {
    /// Group holding the unique inflight slot.
    pub(super) key: Group,
    /// Determines which deadline or round may change on completion.
    pub(super) kind: JobKind,
    /// Immutable selection evidence shared by jobs from one observation.
    pub(super) observation: Arc<HealthObservation>,
    /// The selected group's target and endpoint candidates.
    pub(super) entry: DcFloorPlanEntry,
    /// Recovery round identity; refresh and shadow operations do not consume it.
    pub(super) round: u64,
}

/// Retry and cooldown state owned exclusively by the monitor.
#[derive(Default)]
pub(super) struct GroupState {
    /// Endpoint, policy and generation fence for every mutable field below.
    pub(super) authority: Option<((u64, u64), u64)>,
    /// Earliest recovery eligibility; resource deferral leaves it unchanged.
    pub(super) due: Option<Instant>,
    /// Idle-refresh cooldown independent of missing-floor recovery.
    pub(super) refresh_due: Option<Instant>,
    /// Single-endpoint rotation cooldown.
    pub(super) shadow_due: Option<Instant>,
    /// Backoff advances once per completed recovery round.
    pub(super) backoff_ms: u64,
    /// Remaining writer operations in the current round.
    pub(super) round_left: usize,
    /// Distinguishes a finalized round from one that has no operations left yet.
    pub(super) round_active: bool,
    /// Monotonic identity prevents late outcomes from changing a newer round.
    pub(super) round: u64,
    /// Alternates independently eligible refresh and recovery work.
    pub(super) prefer_refresh: bool,
    /// Selects the single-endpoint outage retry namespace.
    pub(super) outage: bool,
    /// Rate limit for missing-floor warnings.
    pub(super) warn_due: Option<Instant>,
    /// Resource-blocked groups wait until the next health tick.
    pub(super) deferred: bool,
}

/// One queue and one owner table bound work across both address families.
#[derive(Default)]
pub(super) struct HealthScheduler {
    /// Persistent cursor order survives observations and worker completions.
    pub(super) queue: VecDeque<Group>,
    /// Coalesced work and deadlines for configured groups only.
    pub(super) groups: HashMap<Group, GroupState>,
    /// Task IDs release group ownership even after panic or abort.
    pub(super) owners: HashMap<Id, HealthJob>,
}

impl HealthScheduler {
    /// Refreshes desired groups without resetting the round-robin cursor.
    pub(super) fn observe(&mut self, observations: &HashMap<IpFamily, Arc<HealthObservation>>) {
        let mut current = HashSet::new();
        for (family, observation) in observations {
            for dc in observation.floor.by_dc.keys() {
                let key = (*dc, *family);
                current.insert(key);
                let state = self.groups.entry(key).or_default();
                let authority = (observation.authority, observation.generation);
                if state.authority != Some(authority) {
                    *state = GroupState {
                        authority: Some(authority),
                        ..GroupState::default()
                    };
                }
                if !self.queue.contains(&key) {
                    self.queue.push_back(key);
                }
            }
        }
        self.queue.retain(|key| current.contains(key));
        self.groups.retain(|key, _| current.contains(key));
    }

    /// Includes obsolete tasks until their actual completion releases ownership.
    pub(super) fn busy(&self, key: Group) -> bool {
        self.owners.values().any(|job| job.key == key)
    }

    /// Accepts only an authoritative outcome from a still-active recovery round.
    pub(super) fn completed(&mut self, pool: &Arc<MePool>, job: HealthJob, outcome: JobOutcome) {
        let Some(state) = self.groups.get_mut(&job.key) else {
            return;
        };
        if state.authority != Some((job.observation.authority, job.observation.generation))
            || pool.floor_authority() != job.observation.authority
            || pool.current_generation() != job.observation.generation
        {
            return;
        }
        if matches!(job.kind, JobKind::Recover | JobKind::Transfer)
            && (!state.round_active || state.round != job.round)
        {
            return;
        }
        let JobOutcome::Completed(deadline) = outcome else {
            state.deferred = true;
            return;
        };
        match job.kind {
            JobKind::Refresh => {
                state.refresh_due = Some(deadline.unwrap_or_else(|| {
                    Instant::now() + Duration::from_secs(IDLE_REFRESH_RETRY_SECS)
                }))
            }
            JobKind::Shadow => {
                state.shadow_due = Some(deadline.unwrap_or_else(|| {
                    Instant::now() + Duration::from_secs(SHADOW_ROTATE_RETRY_SECS)
                }))
            }
            JobKind::Recover | JobKind::Transfer => {
                state.round_left = state.round_left.saturating_sub(1);
                // Round finalization uses the next fresh observation, never the job's old count.
                state.due = None;
            }
        }
    }
}

/// Finds refresh work without waiting for another group's network operation.
pub(super) fn idle_refresh_ready(
    observation: &HealthObservation,
    entry: &DcFloorPlanEntry,
) -> bool {
    let now = MePool::now_epoch_secs();
    entry.endpoints.iter().any(|endpoint| {
        observation
            .ids
            .get(&(entry.dc, *endpoint))
            .is_some_and(|ids| {
                ids.iter().any(|id| {
                    observation.bound.get(id).copied().unwrap_or(0) == 0
                        && observation.idle.get(id).is_some_and(|since| {
                            now.saturating_sub(*since)
                                >= IDLE_REFRESH_TRIGGER_BASE_SECS
                                    + id % (IDLE_REFRESH_TRIGGER_JITTER_SECS + 1)
                        })
                })
            })
    })
}

/// Executes at most one bounded writer operation, never a whole missing-writer batch.
pub(super) async fn run_job(
    pool: Arc<MePool>,
    rng: Arc<SecureRandom>,
    job: HealthJob,
) -> JobOutcome {
    if pool.floor_authority() != job.observation.authority
        || pool.current_generation() != job.observation.generation
    {
        return JobOutcome::Deferred;
    }
    let key = job.key;
    let entry = &job.entry;
    let observation = &job.observation;
    let mut deadlines = HashMap::new();
    match job.kind {
        JobKind::Refresh => {
            maybe_refresh_idle_writer_for_dc(
                &pool,
                &rng,
                key,
                key.0,
                key.1,
                &entry.endpoints,
                entry.alive,
                entry.target_required,
                &observation.ids,
                &observation.idle,
                &observation.bound,
                &mut deadlines,
            )
            .await
        }
        JobKind::Shadow => {
            maybe_rotate_single_endpoint_shadow(
                &pool,
                &rng,
                key,
                key.0,
                key.1,
                &entry.endpoints,
                entry.alive,
                entry.target_required,
                &observation.ids,
                &observation.bound,
                &mut deadlines,
            )
            .await
        }
        JobKind::Transfer => {
            if coverage::transfer_coverage(
                &pool,
                &rng,
                key.0,
                entry.endpoints[0],
                entry.target_required,
            )
            .await
            .is_none()
            {
                return JobOutcome::Deferred;
            }
        }
        JobKind::Recover => {
            let outage = entry.endpoints.len() == 1
                && entry.alive == 0
                && pool.single_endpoint_outage_mode_enabled();
            pool.stats.increment_me_reconnect_attempt();
            if outage {
                pool.stats
                    .increment_me_single_endpoint_outage_reconnect_attempt_total();
            }
            let base = pool.required_writers_for_dc_with_floor_mode(entry.endpoints.len(), false);
            let intent = if entry.alive < base {
                WriterOpenIntent::Coverage
            } else {
                WriterOpenIntent::Normal
            };
            let connected = tokio::time::timeout(pool.reconnect_runtime.me_one_timeout, async {
                if outage && pool.single_endpoint_outage_disable_quarantine() {
                    pool.stats
                        .increment_me_single_endpoint_quarantine_bypass_total();
                    pool.connect_one_with_generation_contour_for_dc_with_intent(
                        entry.endpoints[0],
                        rng.as_ref(),
                        observation.generation,
                        WriterContour::Active,
                        key.0,
                        intent,
                    )
                    .await
                    .is_ok()
                } else {
                    pool.connect_endpoints_round_robin_with_generation_contour(
                        key.0,
                        &entry.endpoints,
                        rng.as_ref(),
                        observation.generation,
                        WriterContour::Active,
                        intent,
                    )
                    .await
                }
            })
            .await
            .unwrap_or(false);
            if connected {
                pool.stats.increment_me_reconnect_success();
                if outage {
                    pool.stats
                        .increment_me_single_endpoint_outage_reconnect_success_total();
                }
            }
        }
    }
    JobOutcome::Completed(deadlines.remove(&key))
}
