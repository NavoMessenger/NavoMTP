use std::collections::{BTreeSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Instant;

use serde::Serialize;

use super::status::immutable_matches;
use super::{SessionFilter, WebProcessRuntime};
use crate::web::session::SessionCloseReason;

const OPERATION_REF_VERSION: &str = "wo1";
const OPERATION_RETENTION: usize = 32;
const CLOSE_CHUNK: usize = 128;

/// Validated bulk-close selector.
#[derive(Clone)]
pub(crate) enum CloseOperationSelector {
    /// Exact logical session references resolved by the API.
    Refs(Vec<u64>),
    /// Point-in-time sessions matching a bounded filter.
    Filter(SessionFilter),
    /// Every logical session at or below the submission high-water mark.
    All,
}

/// Stable close-operation state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ControlOperationState {
    /// Accepted but not yet executing.
    Queued,
    /// Scanning the bounded point-in-time registry.
    Running,
    /// Finished the complete bounded scan.
    Completed,
    /// Stopped because process shutdown began.
    Cancelled,
    /// Stopped on one sanitized internal failure.
    Failed,
}

/// Retained status for one asynchronous close operation.
#[derive(Clone, Serialize)]
pub(crate) struct ControlOperationStatus {
    /// Opaque process-fenced operation reference.
    pub(crate) operation_id: String,
    /// Current lifecycle state.
    pub(crate) state: ControlOperationState,
    /// Highest logical session eligible for this point-in-time operation.
    pub(crate) high_water_session_ref: Option<String>,
    /// Exact submitted reference count, or zero for filter/all selectors.
    pub(crate) requested: usize,
    /// Registry candidates visited so far.
    pub(crate) scanned: usize,
    /// Candidates that matched the complete selector.
    pub(crate) matched: usize,
    /// Matching session incarnations sent a close signal.
    pub(crate) close_signalled: usize,
    /// Matching candidates replaced or closed before signalling.
    pub(crate) conflicted: usize,
    /// Wall-clock creation timestamp for operator correlation.
    pub(crate) created_epoch_millis: u64,
    /// Wall-clock timestamp of the latest status mutation.
    pub(crate) updated_epoch_millis: u64,
    /// Stable sanitized failure token.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) failure: Option<&'static str>,
}

/// Runtime control validation failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ControlError {
    /// The supplied process-instance fence is stale.
    StaleInstance,
    /// The selector is empty or exceeds its bound.
    InvalidSelector,
    /// Close-all was requested before issuance stopped.
    IssuanceEnabled,
    /// The single operation slot is occupied.
    OperationInProgress,
    /// The operation reference is not canonical.
    InvalidOperation,
    /// The canonical operation is outside retained history.
    OperationNotFound,
    /// Process shutdown has closed the mutation gate.
    Closed,
}

/// Single-slot execution gate with bounded terminal history.
#[derive(Default)]
pub(super) struct ControlOperationRegistry {
    active: Option<u64>,
    retained: VecDeque<(u64, ControlOperationStatus)>,
    closed: bool,
}

struct WorkCandidate {
    trace_session_id: u64,
    session: Arc<crate::web::session::WebSession>,
    bootstrap_hash: super::TokenHash,
}

impl WebProcessRuntime {
    /// Acquires the process mutation gate without permitting post-shutdown work.
    pub(super) fn control_mutation_guard(
        &self,
    ) -> Result<parking_lot::MutexGuard<'_, ControlOperationRegistry>, ControlError> {
        let operations = self.control_operations.lock();
        if operations.closed || self.shutdown.is_cancelled() {
            return Err(ControlError::Closed);
        }
        Ok(operations)
    }

    /// Clears debug records under the process mutation gate.
    pub(crate) fn clear_debug(&self) -> Result<crate::web::trace::TraceClearOutcome, ControlError> {
        let _control = self.control_mutation_guard()?;
        Ok(self.trace.clear())
    }

    /// Starts one bounded point-in-time close sweep.
    pub(crate) fn start_close_operation(
        self: &Arc<Self>,
        runtime_instance: &str,
        selector: CloseOperationSelector,
    ) -> Result<ControlOperationStatus, ControlError> {
        if runtime_instance != self.runtime_instance() {
            return Err(ControlError::StaleInstance);
        }
        if matches!(&selector, CloseOperationSelector::Refs(refs) if refs.is_empty() || refs.len() > 200)
            || matches!(&selector, CloseOperationSelector::Filter(filter) if filter.is_empty())
        {
            return Err(ControlError::InvalidSelector);
        }
        let generation = self.active_generation();
        let web_enabled = generation.config().web.enabled;
        let (high_water, issuance_enabled) = {
            let mut state = self.state.lock();
            state.apply_issuance_policy(generation.id, web_enabled);
            (
                state.session_index.last_key_value().map(|(id, _)| *id),
                state.issuance_enabled,
            )
        };
        if matches!(selector, CloseOperationSelector::All) && issuance_enabled {
            return Err(ControlError::IssuanceEnabled);
        }
        if self.shutdown.is_cancelled() {
            return Err(ControlError::Closed);
        }
        let sequence = self
            .next_control_operation_id
            .fetch_add(1, Ordering::Relaxed);
        let operation_id = self.operation_ref(sequence);
        let now = crate::web::trace::store_epoch_millis();
        let requested = match &selector {
            CloseOperationSelector::Refs(refs) => refs.len(),
            CloseOperationSelector::Filter(_) | CloseOperationSelector::All => 0,
        };
        let status = ControlOperationStatus {
            operation_id,
            state: ControlOperationState::Queued,
            high_water_session_ref: high_water.map(|id| self.session_ref(id)),
            requested,
            scanned: 0,
            matched: 0,
            close_signalled: 0,
            conflicted: 0,
            created_epoch_millis: now,
            updated_epoch_millis: now,
            failure: None,
        };
        let tracked = {
            let mut operations = self.control_operations.lock();
            if operations.closed || self.shutdown.is_cancelled() {
                return Err(ControlError::Closed);
            }
            if operations.active.is_some() {
                return Err(ControlError::OperationInProgress);
            }
            operations.active = Some(sequence);
            operations.retained.push_back((sequence, status.clone()));
            trim_operations(&mut operations);
            let weak = Arc::downgrade(self);
            self.tasks.track_future(async move {
                if let Some(runtime) = weak.upgrade() {
                    runtime
                        .run_close_operation(sequence, high_water, selector)
                        .await;
                }
            })
        };
        drop(tokio::spawn(tracked));
        Ok(status)
    }

    /// Returns one retained operation status under the process-instance fence.
    pub(crate) fn control_operation(
        &self,
        operation_id: &str,
    ) -> Result<ControlOperationStatus, ControlError> {
        let sequence = self.parse_operation_ref(operation_id)?;
        self.control_operations
            .lock()
            .retained
            .iter()
            .find_map(|(id, status)| (*id == sequence).then(|| status.clone()))
            .ok_or(ControlError::OperationNotFound)
    }

    /// Prevents new control work from racing process-runtime shutdown.
    pub(super) fn close_control_submission_gate(&self) {
        self.control_operations.lock().closed = true;
    }

    async fn run_close_operation(
        self: &Arc<Self>,
        sequence: u64,
        high_water: Option<u64>,
        selector: CloseOperationSelector,
    ) {
        self.update_operation(sequence, |status| {
            status.state = ControlOperationState::Running
        });
        let refs = match &selector {
            CloseOperationSelector::Refs(refs) => {
                Some(refs.iter().copied().collect::<BTreeSet<_>>())
            }
            CloseOperationSelector::Filter(_) | CloseOperationSelector::All => None,
        };
        let filter = match &selector {
            CloseOperationSelector::Filter(filter) => Some(filter),
            CloseOperationSelector::Refs(_) | CloseOperationSelector::All => None,
        };
        let mut cursor = None;
        loop {
            if self.shutdown.is_cancelled() {
                self.finish_operation(sequence, ControlOperationState::Cancelled, None);
                return;
            }
            let mut direct = Vec::new();
            let mut state_filtered = Vec::new();
            let (scanned, next_cursor, reached_end) = {
                let mut state = self.state.lock();
                let mut scanned = 0usize;
                let mut next_cursor = cursor;
                let mut reached_end = true;
                let ids = state
                    .session_index
                    .range((
                        cursor.map_or(std::ops::Bound::Unbounded, std::ops::Bound::Excluded),
                        std::ops::Bound::Unbounded,
                    ))
                    .take(CLOSE_CHUNK)
                    .map(|(id, _)| *id)
                    .collect::<Vec<_>>();
                for trace_session_id in ids {
                    if high_water.is_some_and(|high_water| trace_session_id > high_water) {
                        break;
                    }
                    scanned += 1;
                    next_cursor = Some(trace_session_id);
                    let Some(index) = state.session_index.get(&trace_session_id) else {
                        continue;
                    };
                    let selected = refs
                        .as_ref()
                        .is_none_or(|refs| refs.contains(&trace_session_id));
                    let Some(session) = selected
                        .then(|| state.sessions.get(&index.session_hash).cloned())
                        .flatten()
                    else {
                        continue;
                    };
                    if filter.is_some_and(|filter| !immutable_matches(&session, index, filter)) {
                        continue;
                    }
                    let candidate = WorkCandidate {
                        trace_session_id,
                        session,
                        bootstrap_hash: index.bootstrap_hash,
                    };
                    if filter.and_then(|filter| filter.state.as_ref()).is_some() {
                        state_filtered.push(candidate);
                    } else {
                        mark_close_locked(&mut state, &candidate);
                        direct.push(candidate);
                    }
                }
                if scanned == CLOSE_CHUNK {
                    reached_end = false;
                }
                (scanned, next_cursor, reached_end)
            };
            self.update_operation(sequence, |status| {
                status.scanned = status.scanned.saturating_add(scanned);
                status.matched = status.matched.saturating_add(direct.len());
            });
            for candidate in direct {
                candidate.session.close(SessionCloseReason::ApiClose);
                self.update_operation(sequence, |status| {
                    status.close_signalled = status.close_signalled.saturating_add(1)
                });
            }
            if let Some(expected_state) = filter.and_then(|filter| filter.state.as_deref()) {
                for candidate in state_filtered {
                    let matches_state = candidate
                        .session
                        .try_status(Instant::now())
                        .is_some_and(|status| status.state == expected_state);
                    if !matches_state {
                        continue;
                    }
                    let session = {
                        let mut state = self.state.lock();
                        let current = state
                            .session_index
                            .get(&candidate.trace_session_id)
                            .and_then(|index| state.sessions.get(&index.session_hash))
                            .filter(|current| Arc::ptr_eq(current, &candidate.session))
                            .cloned();
                        if current.is_some() {
                            mark_close_locked(&mut state, &candidate);
                        }
                        current
                    };
                    if let Some(session) = session {
                        session.close(SessionCloseReason::ApiClose);
                        self.update_operation(sequence, |status| {
                            status.matched = status.matched.saturating_add(1);
                            status.close_signalled = status.close_signalled.saturating_add(1);
                        });
                    } else {
                        self.update_operation(sequence, |status| {
                            status.matched = status.matched.saturating_add(1);
                            status.conflicted = status.conflicted.saturating_add(1);
                        });
                    }
                }
            }
            cursor = next_cursor;
            if reached_end || cursor.is_none() {
                break;
            }
            tokio::task::yield_now().await;
        }
        self.finish_operation(sequence, ControlOperationState::Completed, None);
    }

    fn update_operation(&self, sequence: u64, update: impl FnOnce(&mut ControlOperationStatus)) {
        let mut operations = self.control_operations.lock();
        if let Some((_, status)) = operations
            .retained
            .iter_mut()
            .find(|(id, _)| *id == sequence)
        {
            update(status);
            status.updated_epoch_millis = crate::web::trace::store_epoch_millis();
        }
    }

    fn finish_operation(
        &self,
        sequence: u64,
        state: ControlOperationState,
        failure: Option<&'static str>,
    ) {
        let mut operations = self.control_operations.lock();
        if let Some((_, status)) = operations
            .retained
            .iter_mut()
            .find(|(id, _)| *id == sequence)
        {
            status.state = failure.map_or(state, |_| ControlOperationState::Failed);
            status.failure = failure;
            status.updated_epoch_millis = crate::web::trace::store_epoch_millis();
        }
        if operations.active == Some(sequence) {
            operations.active = None;
        }
    }

    fn operation_ref(&self, sequence: u64) -> String {
        format!(
            "{OPERATION_REF_VERSION}.{}.{sequence:016x}",
            self.runtime_instance()
        )
    }

    fn parse_operation_ref(&self, value: &str) -> Result<u64, ControlError> {
        let mut parts = value.split('.');
        if parts.next() != Some(OPERATION_REF_VERSION) {
            return Err(ControlError::InvalidOperation);
        }
        let instance = parts.next().ok_or(ControlError::InvalidOperation)?;
        if instance.len() != 32
            || !instance
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ControlError::InvalidOperation);
        }
        let sequence = parts
            .next()
            .filter(|value| {
                value.len() == 16
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            .and_then(|value| u64::from_str_radix(value, 16).ok())
            .filter(|value| *value != 0)
            .ok_or(ControlError::InvalidOperation)?;
        if parts.next().is_some() {
            return Err(ControlError::InvalidOperation);
        }
        if instance != self.runtime_instance() {
            return Err(ControlError::StaleInstance);
        }
        Ok(sequence)
    }
}

fn mark_close_locked(state: &mut super::state::ManagerState, candidate: &WorkCandidate) {
    if let Some(bootstrap) = state.bootstraps.get_mut(&candidate.bootstrap_hash) {
        bootstrap.close_requested = true;
    }
}

fn trim_operations(operations: &mut ControlOperationRegistry) {
    while operations.retained.len() > OPERATION_RETENTION {
        if operations
            .retained
            .front()
            .is_some_and(|(id, _)| Some(*id) == operations.active)
        {
            break;
        }
        operations.retained.pop_front();
    }
}
