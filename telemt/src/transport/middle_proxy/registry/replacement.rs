use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use super::{ConnRegistry, WriterReplacementState};

/// Result of atomically committing a client-to-writer binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::transport::middle_proxy) enum WriterBindOutcome {
    /// The client route was bound to the selected writer.
    Bound,
    /// The client route disappeared before the binding commit.
    RouteMissing,
    /// The selected writer disappeared before the binding commit.
    WriterMissing,
    /// The selected writer is retiring and no longer accepts new clients.
    WriterRetiring,
}

/// Cancellation-safe ownership of one prospective writer replacement.
pub(in crate::transport::middle_proxy) struct WriterReplacementReservation<'a> {
    registry: &'a ConnRegistry,
    writer_id: u64,
    state: Arc<AtomicU8>,
    require_idle: bool,
    committed: bool,
}

impl WriterReplacementReservation<'_> {
    /// Returns the stable identifier of the prospective victim.
    pub(in crate::transport::middle_proxy) fn writer_id(&self) -> u64 {
        self.writer_id
    }

    /// Returns the registry whose binding lock linearizes this reservation.
    pub(super) fn registry(&self) -> &ConnRegistry {
        self.registry
    }

    /// Returns the writer-local replacement state identity captured at reservation time.
    pub(super) fn state(&self) -> &Arc<AtomicU8> {
        &self.state
    }

    /// Reports whether commit must revalidate that the victim remains unbound.
    pub(super) fn requires_idle(&self) -> bool {
        self.require_idle
    }

    /// Transfers retirement ownership to the published replacement.
    pub(in crate::transport::middle_proxy) fn mark_committed(&mut self) {
        self.committed = true;
    }
}

impl Drop for WriterReplacementReservation<'_> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let preparing = WriterReplacementState::Preparing as u8;
        let open = WriterReplacementState::Open as u8;
        let _ = self
            .state
            .compare_exchange(preparing, open, Ordering::AcqRel, Ordering::Acquire);
    }
}

impl ConnRegistry {
    /// Claims an idle writer as a prospective replacement victim.
    ///
    /// Preparing prevents duplicate replacement work but intentionally permits new client binds.
    /// Commit revalidates idleness under the existing binding lock before blocking future binds.
    pub(in crate::transport::middle_proxy) async fn try_reserve_writer_replacement(
        &self,
        writer_id: u64,
    ) -> Option<WriterReplacementReservation<'_>> {
        self.reserve_writer_replacement(writer_id, true).await
    }

    /// Claims a writer while retaining its existing client associations through replacement.
    pub(in crate::transport::middle_proxy) async fn try_reserve_writer_replacement_preserving_clients(
        &self,
        writer_id: u64,
    ) -> Option<WriterReplacementReservation<'_>> {
        self.reserve_writer_replacement(writer_id, false).await
    }

    async fn reserve_writer_replacement(
        &self,
        writer_id: u64,
        require_idle: bool,
    ) -> Option<WriterReplacementReservation<'_>> {
        let binding = self.binding.inner.lock().await;
        let state = self
            .writers
            .map
            .get(&writer_id)
            .map(|route| Arc::clone(&route.replacement_state))?;
        if require_idle
            && binding
                .conns_for_writer
                .get(&writer_id)
                .is_none_or(|conn_ids| !conn_ids.is_empty())
        {
            return None;
        }
        state
            .compare_exchange(
                WriterReplacementState::Open as u8,
                WriterReplacementState::Preparing as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .ok()?;

        Some(WriterReplacementReservation {
            registry: self,
            writer_id,
            state,
            require_idle,
            committed: false,
        })
    }

    /// Returns fixed-cardinality gauges for preparing and retiring replacements.
    pub(in crate::transport::middle_proxy) fn writer_replacement_counts(&self) -> (usize, usize) {
        let mut preparing = 0usize;
        let mut retiring = 0usize;
        for route in &self.writers.map {
            match route.replacement_state.load(Ordering::Acquire) {
                state if state == WriterReplacementState::Preparing as u8 => {
                    preparing = preparing.saturating_add(1);
                }
                state if state == WriterReplacementState::Retiring as u8 => {
                    retiring = retiring.saturating_add(1);
                }
                _ => {}
            }
        }
        (preparing, retiring)
    }
}
