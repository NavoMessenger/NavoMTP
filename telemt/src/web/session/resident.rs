use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use bytes::Bytes;

use super::WebSession;
use crate::web::manager::{ProfileKey, WebProcessRuntime};

#[derive(Clone, Copy, Default)]
pub(super) struct PendingCounts {
    pub(super) data_bytes: usize,
    pub(super) data_items: usize,
    pub(super) control_bytes: usize,
    pub(super) control_items: usize,
}

impl PendingCounts {
    pub(super) fn bytes(self) -> usize {
        self.data_bytes.saturating_add(self.control_bytes)
    }

    pub(super) fn items(self) -> usize {
        self.data_items.saturating_add(self.control_items)
    }
}

#[derive(Default)]
pub(super) struct ResidentCounters {
    data_bytes: AtomicUsize,
    data_items: AtomicUsize,
    control_bytes: AtomicUsize,
    control_items: AtomicUsize,
}

impl ResidentCounters {
    pub(super) fn snapshot(&self) -> PendingCounts {
        PendingCounts {
            data_bytes: self.data_bytes.load(Ordering::Acquire),
            data_items: self.data_items.load(Ordering::Acquire),
            control_bytes: self.control_bytes.load(Ordering::Acquire),
            control_items: self.control_items.load(Ordering::Acquire),
        }
    }

    fn add(&self, counts: PendingCounts) {
        self.data_bytes
            .fetch_add(counts.data_bytes, Ordering::AcqRel);
        self.data_items
            .fetch_add(counts.data_items, Ordering::AcqRel);
        self.control_bytes
            .fetch_add(counts.control_bytes, Ordering::AcqRel);
        self.control_items
            .fetch_add(counts.control_items, Ordering::AcqRel);
    }

    fn remove(&self, counts: PendingCounts) {
        self.data_bytes
            .fetch_sub(counts.data_bytes, Ordering::AcqRel);
        self.data_items
            .fetch_sub(counts.data_items, Ordering::AcqRel);
        self.control_bytes
            .fetch_sub(counts.control_bytes, Ordering::AcqRel);
        self.control_items
            .fetch_sub(counts.control_items, Ordering::AcqRel);
    }
}

pub(super) struct PendingResponseLease {
    manager: std::sync::Weak<WebProcessRuntime>,
    owner: ProfileKey,
    counts: PendingCounts,
    session: Arc<ResidentCounters>,
    lane: Option<Arc<ResidentCounters>>,
    detached: AtomicBool,
}

impl PendingResponseLease {
    pub(super) fn new(
        session: &WebSession,
        counts: PendingCounts,
        lane: Option<Arc<ResidentCounters>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            manager: session.manager.clone(),
            owner: session.profile_key,
            counts,
            session: Arc::clone(&session.resident),
            lane,
            detached: AtomicBool::new(false),
        })
    }

    pub(super) fn detach(&self) {
        if self
            .detached
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        self.session.add(self.counts);
        if let Some(lane) = &self.lane {
            lane.add(self.counts);
        }
    }
}

impl Drop for PendingResponseLease {
    fn drop(&mut self) {
        if self.detached.load(Ordering::Acquire) {
            self.session.remove(self.counts);
            if let Some(lane) = &self.lane {
                lane.remove(self.counts);
            }
        }
        if let Some(manager) = self.manager.upgrade() {
            manager.release_pending(
                self.owner,
                self.counts.data_bytes,
                self.counts.data_items,
                false,
            );
            manager.release_pending(
                self.owner,
                self.counts.control_bytes,
                self.counts.control_items,
                true,
            );
        }
    }
}

pub(super) struct OwnedBatchBody {
    bytes: Bytes,
    _lease: Arc<PendingResponseLease>,
}

impl OwnedBatchBody {
    pub(super) fn new(bytes: Bytes, lease: Arc<PendingResponseLease>) -> Self {
        Self {
            bytes,
            _lease: lease,
        }
    }
}

impl AsRef<[u8]> for OwnedBatchBody {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}
