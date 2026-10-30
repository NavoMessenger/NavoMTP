use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use parking_lot::Mutex;
use tokio::sync::{Notify, OwnedSemaphorePermit};

use super::{ProfileKey, WebProcessRuntime};
use crate::config::WebLimitsConfig;
use crate::web::session::QUEUE_ITEM_COST;
use crate::web::telemetry::WebRejectionReason;

/// WebSocket allocation class with a distinct pressure watermark.
#[derive(Clone, Copy)]
pub(super) enum WebSocketBudgetClass {
    /// Long-lived codec and driver memory acquired before an upgrade commits.
    Base,
    /// One bounded inbound message or outbound write staging allocation.
    Data,
}

#[derive(Default)]
struct BudgetState {
    queue_bytes: usize,
    queue_items: usize,
    queue_control_bytes: usize,
    queue_control_items: usize,
    websocket_bytes: usize,
    owner_bytes: HashMap<ProfileKey, usize>,
    high_water_bytes: usize,
    closed: bool,
}

/// Process-owned byte and item governor shared by queues and WebSocket I/O.
pub(super) struct WebDataBudget {
    limits: WebLimitsConfig,
    state: Mutex<BudgetState>,
    notify: Arc<Notify>,
    pressured: AtomicBool,
}

/// One exact WebSocket allocation released on every cancellation path.
pub(crate) struct WebSocketBudgetLease {
    budget: Arc<WebDataBudget>,
    owner: ProfileKey,
    bytes: usize,
}

/// Lock-free diagnostic snapshot of one short locked budget state.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct WebDataBudgetSnapshot {
    /// Total queue bytes currently retained.
    pub(crate) queue_bytes: usize,
    /// Total queue items currently retained.
    pub(crate) queue_items: usize,
    /// Control bytes included in the queue total.
    pub(crate) queue_control_bytes: usize,
    /// Control items included in the queue total.
    pub(crate) queue_control_items: usize,
    /// Total WebSocket bytes currently retained.
    pub(crate) websocket_bytes: usize,
    /// Largest combined byte usage observed since process start.
    pub(crate) high_water_bytes: usize,
    /// Distinct profile owners currently charged.
    pub(crate) owners: usize,
    /// Whether shutdown closed this allocation authority.
    pub(crate) closed: bool,
}

/// Bounded owner-usage view captured before WebSocket registry selection.
pub(super) struct WebSocketFairnessSnapshot {
    /// Equal byte share at the admission watermark for captured owners.
    pub(super) fair_share: usize,
    /// Captured shared-budget use indexed by profile owner.
    pub(super) owner_bytes: HashMap<ProfileKey, usize>,
}

impl WebSocketFairnessSnapshot {
    /// Returns the captured byte usage for one quota owner.
    pub(super) fn owner_usage(&self, owner: ProfileKey) -> usize {
        self.owner_bytes.get(&owner).copied().unwrap_or(0)
    }
}

impl WebDataBudget {
    pub(super) fn new(limits: WebLimitsConfig) -> Arc<Self> {
        Arc::new(Self {
            limits,
            state: Mutex::new(BudgetState::default()),
            notify: Arc::new(Notify::new()),
            pressured: AtomicBool::new(false),
        })
    }

    pub(super) fn try_reserve_queue(
        &self,
        owner: ProfileKey,
        bytes: usize,
        items: usize,
        control: bool,
        downlink: bool,
    ) -> bool {
        let mut state = self.state.lock();
        if state.closed {
            return false;
        }
        let control_item_reserve = control_item_reserve(&self.limits);
        let data_byte_limit = self
            .limits
            .pending_bytes_global
            .saturating_sub(self.limits.control_bytes_global);
        let data_item_limit = self
            .limits
            .pending_items_global
            .saturating_sub(control_item_reserve);
        let (fits, websocket_byte_pressure) = if control {
            let byte_pressure = state.websocket_bytes != 0
                && state.queue_bytes.saturating_add(state.websocket_bytes)
                    > self.limits.pending_bytes_global.saturating_sub(bytes);
            let fits = bytes <= self.limits.control_bytes_global
                && items <= control_item_reserve
                && state.queue_bytes.saturating_add(state.websocket_bytes)
                    <= self.limits.pending_bytes_global.saturating_sub(bytes)
                && state.queue_items <= self.limits.pending_items_global.saturating_sub(items)
                && state.queue_control_bytes
                    <= self.limits.control_bytes_global.saturating_sub(bytes)
                && state.queue_control_items <= control_item_reserve.saturating_sub(items);
            (fits, byte_pressure)
        } else {
            let queue_data_bytes = state.queue_bytes.saturating_sub(state.queue_control_bytes);
            let queue_data_items = state.queue_items.saturating_sub(state.queue_control_items);
            let (byte_limit, item_limit) = if downlink {
                let uplink_bytes = self.limits.max_body_bytes.saturating_add(
                    self.limits
                        .max_frames_per_body
                        .saturating_mul(QUEUE_ITEM_COST),
                );
                (
                    data_byte_limit
                        .saturating_sub(uplink_bytes)
                        .saturating_sub(self.limits.carrier_batch_bytes),
                    data_item_limit.saturating_sub(self.limits.max_frames_per_body),
                )
            } else {
                (data_byte_limit, data_item_limit)
            };
            let byte_pressure = state.websocket_bytes != 0
                && queue_data_bytes.saturating_add(state.websocket_bytes)
                    > byte_limit.saturating_sub(bytes);
            let fits = bytes <= byte_limit
                && items <= item_limit
                && queue_data_bytes.saturating_add(state.websocket_bytes)
                    <= byte_limit.saturating_sub(bytes)
                && queue_data_items <= item_limit.saturating_sub(items);
            (fits, byte_pressure)
        };
        if !fits {
            if websocket_byte_pressure {
                self.pressured.store(true, Ordering::Release);
            }
            return false;
        }
        state.queue_bytes += bytes;
        state.queue_items += items;
        if control {
            state.queue_control_bytes += bytes;
            state.queue_control_items += items;
        }
        add_owner(&mut state.owner_bytes, owner, bytes);
        update_high_water(&mut state);
        true
    }

    pub(super) fn release_queue(
        &self,
        owner: ProfileKey,
        bytes: usize,
        items: usize,
        control: bool,
    ) {
        let notify = self.release_queue_quiet(owner, bytes, items, control);
        notify.notify_waiters();
    }

    /// Releases queue accounting and returns the notification capability uninvoked.
    pub(super) fn release_queue_quiet(
        &self,
        owner: ProfileKey,
        bytes: usize,
        items: usize,
        control: bool,
    ) -> Arc<Notify> {
        let mut state = self.state.lock();
        state.queue_bytes = state.queue_bytes.saturating_sub(bytes);
        state.queue_items = state.queue_items.saturating_sub(items);
        if control {
            state.queue_control_bytes = state.queue_control_bytes.saturating_sub(bytes);
            state.queue_control_items = state.queue_control_items.saturating_sub(items);
        }
        remove_owner(&mut state.owner_bytes, owner, bytes);
        drop(state);
        Arc::clone(&self.notify)
    }

    pub(super) fn try_reserve_websocket(
        self: &Arc<Self>,
        owner: ProfileKey,
        bytes: usize,
        class: WebSocketBudgetClass,
    ) -> Option<WebSocketBudgetLease> {
        let mut state = self.state.lock();
        if state.closed || bytes == 0 {
            return None;
        }
        let websocket_limit = match class {
            WebSocketBudgetClass::Base => watermark(
                self.limits.websocket_bytes_global,
                self.limits.websocket_admission_watermark_pct,
            ),
            WebSocketBudgetClass::Data => watermark(
                self.limits.websocket_bytes_global,
                self.limits.websocket_eviction_watermark_pct,
            ),
        };
        let data_byte_limit = self
            .limits
            .pending_bytes_global
            .saturating_sub(self.limits.control_bytes_global);
        let queue_data_bytes = state.queue_bytes.saturating_sub(state.queue_control_bytes);
        if state.websocket_bytes > websocket_limit.saturating_sub(bytes)
            || queue_data_bytes.saturating_add(state.websocket_bytes)
                > data_byte_limit.saturating_sub(bytes)
        {
            self.pressured.store(true, Ordering::Release);
            return None;
        }
        state.websocket_bytes += bytes;
        add_owner(&mut state.owner_bytes, owner, bytes);
        update_high_water(&mut state);
        Some(WebSocketBudgetLease {
            budget: Arc::clone(self),
            owner,
            bytes,
        })
    }

    pub(super) fn notify(&self) -> Arc<Notify> {
        Arc::clone(&self.notify)
    }

    pub(super) fn take_pressure(&self) -> bool {
        self.pressured.swap(false, Ordering::AcqRel)
    }

    pub(super) fn restore_pressure(&self) {
        self.pressured.store(true, Ordering::Release);
    }

    pub(super) fn fairness_snapshot(
        &self,
        additional_owner: Option<ProfileKey>,
    ) -> WebSocketFairnessSnapshot {
        let state = self.state.lock();
        let mut owners = state.owner_bytes.len();
        if additional_owner.is_some_and(|owner| !state.owner_bytes.contains_key(&owner)) {
            owners += 1;
        }
        let admission = watermark(
            self.limits.websocket_bytes_global,
            self.limits.websocket_admission_watermark_pct,
        );
        WebSocketFairnessSnapshot {
            fair_share: admission / owners.max(1),
            owner_bytes: state.owner_bytes.clone(),
        }
    }

    pub(super) fn snapshot(&self) -> WebDataBudgetSnapshot {
        let state = self.state.lock();
        WebDataBudgetSnapshot {
            queue_bytes: state.queue_bytes,
            queue_items: state.queue_items,
            queue_control_bytes: state.queue_control_bytes,
            queue_control_items: state.queue_control_items,
            websocket_bytes: state.websocket_bytes,
            high_water_bytes: state.high_water_bytes,
            owners: state.owner_bytes.len(),
            closed: state.closed,
        }
    }

    pub(super) fn try_snapshot(&self) -> Option<WebDataBudgetSnapshot> {
        let state = self.state.try_lock()?;
        Some(WebDataBudgetSnapshot {
            queue_bytes: state.queue_bytes,
            queue_items: state.queue_items,
            queue_control_bytes: state.queue_control_bytes,
            queue_control_items: state.queue_control_items,
            websocket_bytes: state.websocket_bytes,
            high_water_bytes: state.high_water_bytes,
            owners: state.owner_bytes.len(),
            closed: state.closed,
        })
    }

    pub(super) fn close(&self) {
        self.state.lock().closed = true;
        self.notify.notify_waiters();
    }

    fn release_websocket(&self, owner: ProfileKey, bytes: usize) {
        let mut state = self.state.lock();
        state.websocket_bytes = state.websocket_bytes.saturating_sub(bytes);
        remove_owner(&mut state.owner_bytes, owner, bytes);
        drop(state);
        self.notify.notify_waiters();
    }
}

impl WebSocketBudgetLease {
    /// Releases unused worst-case capacity after one message is assembled.
    pub(crate) fn shrink_to(&mut self, bytes: usize) {
        let bytes = bytes.min(self.bytes);
        let released = self.bytes - bytes;
        if released == 0 {
            return;
        }
        self.bytes = bytes;
        self.budget.release_websocket(self.owner, released);
    }
}

impl Drop for WebSocketBudgetLease {
    fn drop(&mut self) {
        self.budget.release_websocket(self.owner, self.bytes);
    }
}

impl WebProcessRuntime {
    /// Reserves a parked future uplink without consuming the head request's capacity.
    pub(crate) fn try_conveyor_waiter(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.conveyor_waiters).try_acquire_owned().ok()
    }

    /// Reserves one body reader and its declared bounded body allocation.
    pub(crate) fn try_body_budget(
        &self,
        bytes: usize,
    ) -> Option<(OwnedSemaphorePermit, OwnedSemaphorePermit)> {
        let Some(bytes) = u32::try_from(bytes).ok() else {
            self.record_limit_hit();
            self.telemetry
                .record_rejection(WebRejectionReason::BodyBytesCapacity);
            return None;
        };
        let Some(reader) = Arc::clone(&self.body_readers).try_acquire_owned().ok() else {
            self.record_limit_hit();
            self.telemetry
                .record_rejection(WebRejectionReason::BodyReaderCapacity);
            return None;
        };
        let Some(body) = Arc::clone(&self.body_bytes)
            .try_acquire_many_owned(bytes)
            .ok()
        else {
            self.record_limit_hit();
            self.telemetry
                .record_rejection(WebRejectionReason::BodyBytesCapacity);
            return None;
        };
        Some((reader, body))
    }

    /// Reserves transient bytes while one downlink batch replaces queued frames.
    pub(crate) fn try_downlink_staging_budget(&self, bytes: usize) -> Option<OwnedSemaphorePermit> {
        let bytes = u32::try_from(bytes).ok()?;
        let permit = Arc::clone(&self.body_bytes)
            .try_acquire_many_owned(bytes)
            .ok();
        if permit.is_none() {
            self.record_limit_hit();
            self.telemetry
                .record_rejection(WebRejectionReason::BodyBytesCapacity);
        }
        permit
    }

    /// Reserves bounded process-wide queue capacity for data or control traffic.
    pub(crate) fn try_reserve_pending(
        &self,
        owner: ProfileKey,
        bytes: usize,
        items: usize,
        control: bool,
        downlink: bool,
    ) -> bool {
        if !self
            .data_budget
            .try_reserve_queue(owner, bytes, items, control, downlink)
        {
            self.record_limit_hit();
            self.telemetry
                .record_rejection(WebRejectionReason::QueueGlobalCapacity);
            return false;
        }
        true
    }

    /// Releases process-wide queue capacity and wakes blocked relay writers.
    pub(crate) fn release_pending(
        &self,
        owner: ProfileKey,
        bytes: usize,
        items: usize,
        control: bool,
    ) {
        self.data_budget.release_queue(owner, bytes, items, control);
    }

    /// Releases queue accounting without invoking wake callbacks in the caller's lock scope.
    pub(crate) fn release_pending_quiet(
        &self,
        owner: ProfileKey,
        bytes: usize,
        items: usize,
        control: bool,
    ) -> Arc<Notify> {
        self.data_budget
            .release_queue_quiet(owner, bytes, items, control)
    }

    /// Returns the shared notification source for global queue capacity changes.
    pub(crate) fn budget_notify(&self) -> Arc<Notify> {
        self.data_budget.notify()
    }

    /// Reserves fixed WebSocket driver memory below the admission watermark.
    pub(crate) fn try_websocket_base_budget(
        &self,
        owner: ProfileKey,
        bytes: usize,
    ) -> Option<WebSocketBudgetLease> {
        self.data_budget
            .try_reserve_websocket(owner, bytes, WebSocketBudgetClass::Base)
    }

    /// Reserves one transient WebSocket message below the eviction watermark.
    pub(crate) fn try_websocket_data_budget(
        &self,
        owner: ProfileKey,
        bytes: usize,
    ) -> Option<WebSocketBudgetLease> {
        self.data_budget
            .try_reserve_websocket(owner, bytes, WebSocketBudgetClass::Data)
    }
}

fn watermark(limit: usize, percentage: u8) -> usize {
    limit.saturating_mul(usize::from(percentage)) / 100
}

pub(super) fn control_item_reserve(limits: &WebLimitsConfig) -> usize {
    limits
        .max_sessions_global
        .saturating_mul(16usize.saturating_add(limits.max_streams_per_session.saturating_mul(3)))
}

fn add_owner(values: &mut HashMap<ProfileKey, usize>, owner: ProfileKey, bytes: usize) {
    *values.entry(owner).or_insert(0) += bytes;
}

fn remove_owner(values: &mut HashMap<ProfileKey, usize>, owner: ProfileKey, bytes: usize) {
    let remove = if let Some(value) = values.get_mut(&owner) {
        *value = value.saturating_sub(bytes);
        *value == 0
    } else {
        false
    };
    if remove {
        values.remove(&owner);
    }
}

fn update_high_water(state: &mut BudgetState) {
    state.high_water_bytes = state
        .high_water_bytes
        .max(state.queue_bytes.saturating_add(state.websocket_bytes));
}

#[cfg(test)]
#[path = "budget/tests.rs"]
mod tests;
