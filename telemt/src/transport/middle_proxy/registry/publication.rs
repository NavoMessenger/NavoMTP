use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use tokio::sync::{MutexGuard, Semaphore, mpsc};

use super::super::codec::WriterCommand;
use super::replacement::WriterReplacementReservation;
use super::{BindingInner, ConnRegistry, WriterReplacementState, WriterRoute};

/// Holds registry binding ownership until pool writer visibility is published.
pub(in crate::transport::middle_proxy) struct WriterRegistrationGuard<'a> {
    registry: &'a ConnRegistry,
    binding: MutexGuard<'a, BindingInner>,
}

impl ConnRegistry {
    /// Acquires the only cancellation point required for writer registration.
    pub(in crate::transport::middle_proxy) async fn prepare_writer_registration(
        &self,
    ) -> WriterRegistrationGuard<'_> {
        WriterRegistrationGuard {
            registry: self,
            binding: self.binding.inner.lock().await,
        }
    }
}

impl WriterRegistrationGuard<'_> {
    /// Prevents new bindings while preserving all existing writer associations.
    pub(in crate::transport::middle_proxy) fn retire(&mut self, writer_id: u64) -> bool {
        let Some(state) = self
            .registry
            .writers
            .map
            .get(&writer_id)
            .map(|route| Arc::clone(&route.replacement_state))
        else {
            return false;
        };
        loop {
            let current = state.load(Ordering::Acquire);
            if current == WriterReplacementState::Retiring as u8
                || current == WriterReplacementState::Draining as u8
            {
                return true;
            }
            if state
                .compare_exchange_weak(
                    current,
                    WriterReplacementState::Draining as u8,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                )
                .is_ok()
            {
                return true;
            }
        }
    }

    /// Revalidates an idle replacement victim and prevents subsequent client bindings.
    pub(in crate::transport::middle_proxy) fn prepare_replacement_commit(
        &mut self,
        reservation: &WriterReplacementReservation<'_>,
    ) -> bool {
        let Some(route_state) = self
            .registry
            .writers
            .map
            .get(&reservation.writer_id())
            .map(|route| Arc::clone(&route.replacement_state))
        else {
            return false;
        };
        if !std::ptr::eq(self.registry, reservation.registry())
            || !Arc::ptr_eq(&route_state, reservation.state())
            || reservation.requires_idle()
                && self
                    .binding
                    .conns_for_writer
                    .get(&reservation.writer_id())
                    .is_none_or(|conn_ids| !conn_ids.is_empty())
        {
            return false;
        }
        route_state
            .compare_exchange(
                WriterReplacementState::Preparing as u8,
                WriterReplacementState::Retiring as u8,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }

    /// Installs registry state while retaining binding ownership for pool publication.
    pub(in crate::transport::middle_proxy) fn install(
        &mut self,
        writer_id: u64,
        tx: mpsc::Sender<WriterCommand>,
        byte_budget: Arc<Semaphore>,
    ) {
        self.install_with_lifetime(
            writer_id,
            tx,
            byte_budget,
            super::super::pool_writer::overlap::ReplacementHandoff::new(),
        );
    }

    /// Retrieves the physical lifetime while binding ownership fences victim replacement.
    pub(in crate::transport::middle_proxy) fn writer_lifetime(
        &self,
        writer_id: u64,
    ) -> Option<Arc<super::super::pool_writer::overlap::ReplacementHandoff>> {
        self.registry
            .writers
            .map
            .get(&writer_id)
            .map(|route| route.lifetime.clone())
    }

    /// Publishes a route associated with its transport destruction authority.
    pub(in crate::transport::middle_proxy) fn install_with_lifetime(
        &mut self,
        writer_id: u64,
        tx: mpsc::Sender<WriterCommand>,
        byte_budget: Arc<Semaphore>,
        lifetime: Arc<super::super::pool_writer::overlap::ReplacementHandoff>,
    ) {
        self.binding.conns_for_writer.entry(writer_id).or_default();
        self.registry
            .binding
            .bound_clients_by_writer
            .entry(writer_id)
            .or_insert(0);
        self.registry
            .binding
            .writer_idle_since_epoch_secs
            .entry(writer_id)
            .or_insert_with(ConnRegistry::now_epoch_secs);
        self.registry.writers.map.insert(
            writer_id,
            WriterRoute {
                tx,
                byte_budget,
                replacement_state: Arc::new(AtomicU8::new(WriterReplacementState::Open as u8)),
                lifetime,
            },
        );
    }
}
