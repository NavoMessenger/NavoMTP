#![allow(clippy::too_many_arguments)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{OwnedSemaphorePermit, TryAcquireError};
use tracing::{debug, warn};

use super::MePool;
use super::codec::WriterCommand;
use super::registry::{ConnMeta, WriterBindOutcome};
use super::wire::build_proxy_req_payload;
use crate::config::MeRouteNoWriterMode;
use crate::error::{ProxyError, Result};
use rand::seq::SliceRandom;

use self::bound::BoundWriterSendOutcome;
use self::reservation::{
    LEGACY_PROXY_REQ_SOURCE_CAPACITY_OVERHEAD_BYTES, WriterByteReserveError,
    WriterCommandReserveError, proxy_req_resident_permits, reserve_writer_bytes,
    reserve_writer_command_slot, try_reserve_writer_bytes, writer_send_deadline,
};

const IDLE_WRITER_PENALTY_MID_SECS: u64 = 45;
const IDLE_WRITER_PENALTY_HIGH_SECS: u64 = 55;
const HYBRID_GLOBAL_BURST_PERIOD_ROUNDS: u32 = 4;
const HYBRID_RECENT_SUCCESS_WINDOW_MS: u64 = 120_000;
const HYBRID_TIMEOUT_WARN_RATE_LIMIT_MS: u64 = 5_000;
const HYBRID_RECOVERY_TRIGGER_MIN_INTERVAL_MS: u64 = 5_000;
const PICK_PENALTY_WARM: u64 = 200;
const PICK_PENALTY_DRAINING: u64 = 600;
const PICK_PENALTY_STALE: u64 = 300;
const PICK_PENALTY_DEGRADED: u64 = 250;

// Send-path submodules isolate delivery, close handling, recovery, reservations, and selection.
mod bound;
mod close;
mod pooled;
mod recovery;
mod reservation;
mod selection;

impl MePool {
    /// Send RPC_PROXY_REQ. `tag_override`: per-user ad_tag (from access.user_ad_tags); if None, uses pool default.
    /// `payload_permit` keeps optional client byte accounting alive until the writer consumes the command.
    pub async fn send_proxy_req(
        self: &Arc<Self>,
        conn_id: u64,
        target_dc: i16,
        client_addr: SocketAddr,
        our_addr: SocketAddr,
        data: &[u8],
        proto_flags: u32,
        tag_override: Option<&[u8]>,
        mut payload_permit: Option<OwnedSemaphorePermit>,
    ) -> Result<()> {
        let tag = tag_override.or(self.proxy_tag.as_deref());
        let Some(source_capacity) = data
            .len()
            .checked_add(LEGACY_PROXY_REQ_SOURCE_CAPACITY_OVERHEAD_BYTES)
        else {
            self.stats.increment_me_writer_byte_budget_oversize_total();
            return Err(ProxyError::Proxy(
                "ME writer payload residency calculation overflow".into(),
            ));
        };
        let Some((writer_byte_permits, writer_reserved_bytes)) =
            proxy_req_resident_permits(source_capacity, data.len(), tag, proto_flags)
        else {
            self.stats.increment_me_writer_byte_budget_oversize_total();
            return Err(ProxyError::Proxy(
                "ME writer payload residency calculation overflow".into(),
            ));
        };
        if writer_byte_permits as usize > self.writer_lifecycle.writer_byte_budget_permits {
            self.stats.increment_me_writer_byte_budget_oversize_total();
            return Err(ProxyError::Proxy(
                "ME writer payload exceeds configured byte budget".into(),
            ));
        }
        let build_routed_payload = |effective_our_addr: SocketAddr| {
            (
                build_proxy_req_payload(
                    conn_id,
                    client_addr,
                    effective_our_addr,
                    data,
                    tag,
                    proto_flags,
                ),
                ConnMeta {
                    target_dc,
                    client_addr,
                    our_addr: effective_our_addr,
                    proto_flags,
                },
            )
        };
        let no_writer_mode = MeRouteNoWriterMode::from_u8(
            self.route_runtime
                .me_route_no_writer_mode
                .load(Ordering::Relaxed),
        );
        let (routed_dc, unknown_target_dc) =
            self.resolve_target_dc_for_routing(target_dc as i32).await;
        let mut no_writer_deadline: Option<Instant> = None;
        let mut emergency_attempts = 0u32;
        let mut async_recovery_triggered = false;
        let mut hybrid_recovery_round = 0u32;
        let mut hybrid_last_recovery_at: Option<Instant> = None;
        let mut hybrid_total_deadline: Option<Instant> = None;
        let hybrid_wait_step = self
            .route_runtime
            .me_route_no_writer_wait
            .max(Duration::from_millis(50));
        let mut hybrid_wait_current = hybrid_wait_step;

        loop {
            match self
                .try_send_bound_writer(
                    conn_id,
                    client_addr,
                    data,
                    proto_flags,
                    tag,
                    writer_byte_permits,
                    writer_reserved_bytes,
                    payload_permit,
                )
                .await?
            {
                BoundWriterSendOutcome::Sent => return Ok(()),
                BoundWriterSendOutcome::Retry(retry_permit) => {
                    payload_permit = retry_permit;
                }
            }

            let mut writers_snapshot = {
                let ws = self.writers.snapshot();
                if ws.is_empty() {
                    match no_writer_mode {
                        MeRouteNoWriterMode::AsyncRecoveryFailfast => {
                            let deadline = *no_writer_deadline.get_or_insert_with(|| {
                                Instant::now() + self.route_runtime.me_route_no_writer_wait
                            });
                            if !async_recovery_triggered && !unknown_target_dc {
                                let triggered =
                                    self.trigger_async_recovery_for_target_dc(routed_dc).await;
                                if !triggered {
                                    self.trigger_async_recovery_global().await;
                                }
                                async_recovery_triggered = true;
                            }
                            if self.wait_for_writer_until(deadline).await {
                                continue;
                            }
                            self.stats.increment_me_no_writer_failfast_total();
                            return Err(ProxyError::Proxy(
                                "No ME writer available in failfast window".into(),
                            ));
                        }
                        MeRouteNoWriterMode::InlineRecoveryLegacy => {
                            self.stats.increment_me_inline_recovery_total();
                            if !unknown_target_dc {
                                for _ in
                                    0..self.route_runtime.me_route_inline_recovery_attempts.max(1)
                                {
                                    let endpoint_snapshot = self.endpoint_snapshot.load_full();
                                    for (dc, addrs) in &endpoint_snapshot.preferred_endpoints_by_dc
                                    {
                                        for addr in addrs {
                                            let _ = self
                                                .connect_one_for_dc(*addr, *dc, self.rng.as_ref())
                                                .await;
                                        }
                                    }
                                    if !self.writers.snapshot().is_empty() {
                                        break;
                                    }
                                }
                            }

                            if !self.writers.snapshot().is_empty() {
                                continue;
                            }
                            let deadline = *no_writer_deadline.get_or_insert_with(|| {
                                Instant::now() + self.route_runtime.me_route_inline_recovery_wait
                            });
                            if !self.wait_for_writer_until(deadline).await {
                                if !self.writers.snapshot().is_empty() {
                                    continue;
                                }
                                self.stats.increment_me_no_writer_failfast_total();
                                return Err(ProxyError::Proxy(
                                    "All ME connections dead (legacy wait timeout)".into(),
                                ));
                            }
                            continue;
                        }
                        MeRouteNoWriterMode::HybridAsyncPersistent => {
                            let total_deadline = *hybrid_total_deadline.get_or_insert_with(|| {
                                Instant::now() + self.hybrid_total_wait_budget()
                            });
                            if Instant::now() >= total_deadline {
                                self.on_hybrid_timeout(total_deadline, routed_dc);
                                return Err(ProxyError::Proxy(
                                    "ME writer not available within hybrid timeout".into(),
                                ));
                            }
                            if !unknown_target_dc {
                                self.maybe_trigger_hybrid_recovery(
                                    routed_dc,
                                    &mut hybrid_recovery_round,
                                    &mut hybrid_last_recovery_at,
                                    hybrid_wait_current,
                                )
                                .await;
                            }
                            let deadline = Instant::now() + hybrid_wait_current;
                            let _ = self.wait_for_writer_until(deadline).await;
                            hybrid_wait_current = (hybrid_wait_current.saturating_mul(2))
                                .min(Duration::from_millis(400));
                            continue;
                        }
                    }
                }
                ws
            };

            let mut candidate_indices = self
                .candidate_indices_for_dc(&writers_snapshot, routed_dc, false)
                .await;
            if candidate_indices.is_empty() {
                candidate_indices = self
                    .candidate_indices_for_dc(&writers_snapshot, routed_dc, true)
                    .await;
            }
            if candidate_indices.is_empty() {
                let pick_mode = self.writer_pick_mode();
                match no_writer_mode {
                    MeRouteNoWriterMode::AsyncRecoveryFailfast => {
                        let deadline = *no_writer_deadline.get_or_insert_with(|| {
                            Instant::now() + self.route_runtime.me_route_no_writer_wait
                        });
                        if !async_recovery_triggered && !unknown_target_dc {
                            let triggered =
                                self.trigger_async_recovery_for_target_dc(routed_dc).await;
                            if !triggered {
                                self.trigger_async_recovery_global().await;
                            }
                            async_recovery_triggered = true;
                        }
                        if self.wait_for_candidate_until(routed_dc, deadline).await {
                            continue;
                        }
                        self.stats
                            .increment_me_writer_pick_no_candidate_total(pick_mode);
                        self.stats.increment_me_no_writer_failfast_total();
                        return Err(ProxyError::Proxy(
                            "No ME writers available for target DC in failfast window".into(),
                        ));
                    }
                    MeRouteNoWriterMode::InlineRecoveryLegacy => {
                        self.stats.increment_me_inline_recovery_total();
                        if unknown_target_dc {
                            let deadline = *no_writer_deadline.get_or_insert_with(|| {
                                Instant::now() + self.route_runtime.me_route_inline_recovery_wait
                            });
                            if self.wait_for_candidate_until(routed_dc, deadline).await {
                                continue;
                            }
                            self.stats
                                .increment_me_writer_pick_no_candidate_total(pick_mode);
                            self.stats.increment_me_no_writer_failfast_total();
                            return Err(ProxyError::Proxy(
                                "No ME writers available for target DC".into(),
                            ));
                        }
                        if emergency_attempts
                            >= self.route_runtime.me_route_inline_recovery_attempts.max(1)
                        {
                            self.stats
                                .increment_me_writer_pick_no_candidate_total(pick_mode);
                            self.stats.increment_me_no_writer_failfast_total();
                            return Err(ProxyError::Proxy(
                                "No ME writers available for target DC".into(),
                            ));
                        }
                        emergency_attempts += 1;
                        let mut endpoints = self
                            .endpoint_snapshot
                            .load()
                            .preferred_endpoints_by_dc
                            .get(&routed_dc)
                            .cloned()
                            .unwrap_or_default();
                        endpoints.shuffle(&mut rand::rng());
                        for addr in endpoints {
                            if self
                                .connect_one_for_dc(addr, routed_dc, self.rng.as_ref())
                                .await
                                .is_ok()
                            {
                                break;
                            }
                        }
                        tokio::time::sleep(Duration::from_millis(100 * emergency_attempts as u64))
                            .await;
                        writers_snapshot = self.writers.snapshot();
                        candidate_indices = self
                            .candidate_indices_for_dc(&writers_snapshot, routed_dc, false)
                            .await;
                        if candidate_indices.is_empty() {
                            candidate_indices = self
                                .candidate_indices_for_dc(&writers_snapshot, routed_dc, true)
                                .await;
                        }
                        if candidate_indices.is_empty() {
                            self.stats
                                .increment_me_writer_pick_no_candidate_total(pick_mode);
                            return Err(ProxyError::Proxy(
                                "No ME writers available for target DC".into(),
                            ));
                        }
                    }
                    MeRouteNoWriterMode::HybridAsyncPersistent => {
                        let total_deadline = *hybrid_total_deadline.get_or_insert_with(|| {
                            Instant::now() + self.hybrid_total_wait_budget()
                        });
                        if Instant::now() >= total_deadline {
                            self.on_hybrid_timeout(total_deadline, routed_dc);
                            return Err(ProxyError::Proxy(
                                "No ME writers available for target DC within hybrid timeout"
                                    .into(),
                            ));
                        }
                        if !unknown_target_dc {
                            self.maybe_trigger_hybrid_recovery(
                                routed_dc,
                                &mut hybrid_recovery_round,
                                &mut hybrid_last_recovery_at,
                                hybrid_wait_current,
                            )
                            .await;
                        }
                        let deadline = Instant::now() + hybrid_wait_current;
                        let _ = self.wait_for_candidate_until(routed_dc, deadline).await;
                        hybrid_wait_current =
                            (hybrid_wait_current.saturating_mul(2)).min(Duration::from_millis(400));
                        continue;
                    }
                }
            }
            hybrid_wait_current = hybrid_wait_step;
            let pick_mode = self.writer_pick_mode();
            let ordered_candidate_indices = self
                .ordered_candidate_indices(candidate_indices, &writers_snapshot, pick_mode)
                .await;
            let mut fallback_blocking_idx: Option<usize> = None;

            for idx in ordered_candidate_indices {
                let w = &writers_snapshot[idx];
                if !self.writer_accepts_new_binding(w) {
                    continue;
                }
                let writer_permit = match try_reserve_writer_bytes(
                    &w.byte_budget,
                    writer_byte_permits,
                    writer_reserved_bytes,
                    &self.stats,
                ) {
                    Ok(permit) => permit,
                    Err(TryAcquireError::NoPermits) => {
                        if fallback_blocking_idx.is_none() {
                            fallback_blocking_idx = Some(idx);
                        }
                        continue;
                    }
                    Err(TryAcquireError::Closed) => {
                        self.stats.increment_me_writer_pick_closed_total(pick_mode);
                        warn!(writer_id = w.id, "ME writer byte budget closed");
                        self.remove_writer_and_close_clients(w.id).await;
                        continue;
                    }
                };
                match w.tx.clone().try_reserve_owned() {
                    Ok(permit) => {
                        // Keep the advertised proxy IP aligned with the selected ME writer source.
                        let effective_our_addr = SocketAddr::new(w.source_ip, our_addr.port());
                        let (payload, meta) = build_routed_payload(effective_our_addr);
                        let bind_outcome = self
                            .registry
                            .bind_writer_with_outcome(conn_id, w.id, meta)
                            .await;
                        if bind_outcome != WriterBindOutcome::Bound {
                            drop(permit);
                            if bind_outcome == WriterBindOutcome::WriterRetiring {
                                debug!(
                                    conn_id,
                                    writer_id = w.id,
                                    "ME writer entered replacement retirement before bind commit"
                                );
                                continue;
                            }
                            if bind_outcome == WriterBindOutcome::RouteMissing {
                                return Err(ProxyError::Proxy(
                                    "ME client route disappeared before writer bind".into(),
                                ));
                            }
                            debug!(
                                conn_id,
                                writer_id = w.id,
                                "ME writer disappeared before bind commit, pruning stale writer"
                            );
                            self.remove_writer_and_close_clients(w.id).await;
                            continue;
                        }
                        permit.send(WriterCommand::Data {
                            payload,
                            _permit: payload_permit.take(),
                            writer_permit,
                        });
                        self.stats
                            .increment_me_writer_pick_success_try_total(pick_mode);
                        if w.generation < self.current_generation() {
                            self.stats.increment_pool_stale_pick_total();
                            debug!(
                                conn_id,
                                writer_id = w.id,
                                writer_generation = w.generation,
                                current_generation = self.current_generation(),
                                "Selected stale ME writer for fallback bind"
                            );
                        }
                        self.note_hybrid_route_success();
                        return Ok(());
                    }
                    Err(TrySendError::Full(_)) => {
                        if fallback_blocking_idx.is_none() {
                            fallback_blocking_idx = Some(idx);
                        }
                    }
                    Err(TrySendError::Closed(_)) => {
                        self.stats.increment_me_writer_pick_closed_total(pick_mode);
                        warn!(writer_id = w.id, "ME writer channel closed");
                        self.remove_writer_and_close_clients(w.id).await;
                        continue;
                    }
                }
            }

            let Some(blocking_idx) = fallback_blocking_idx else {
                self.stats.increment_me_writer_pick_full_total(pick_mode);
                continue;
            };

            let w = writers_snapshot[blocking_idx].clone();
            if !self.writer_accepts_new_binding(&w) {
                self.stats.increment_me_writer_pick_full_total(pick_mode);
                continue;
            }
            self.stats
                .increment_me_writer_pick_blocking_fallback_total();
            let deadline = writer_send_deadline(self.route_runtime.me_route_blocking_send_timeout);
            let writer_permit = match reserve_writer_bytes(
                &w.byte_budget,
                writer_byte_permits,
                writer_reserved_bytes,
                deadline,
                &self.stats,
            )
            .await
            {
                Ok(permit) => permit,
                Err(WriterByteReserveError::TimedOut) => {
                    self.stats.increment_me_writer_pick_full_total(pick_mode);
                    continue;
                }
                Err(WriterByteReserveError::Closed) => {
                    self.stats.increment_me_writer_pick_closed_total(pick_mode);
                    warn!(writer_id = w.id, "ME writer byte budget closed (blocking)");
                    self.remove_writer_and_close_clients(w.id).await;
                    continue;
                }
            };
            let permit = match reserve_writer_command_slot(&w.tx, deadline).await {
                Ok(permit) => permit,
                Err(WriterCommandReserveError::TimedOut) => {
                    self.stats.increment_me_writer_pick_full_total(pick_mode);
                    continue;
                }
                Err(WriterCommandReserveError::Closed) => {
                    self.stats.increment_me_writer_pick_closed_total(pick_mode);
                    warn!(writer_id = w.id, "ME writer channel closed (blocking)");
                    self.remove_writer_and_close_clients(w.id).await;
                    continue;
                }
            };
            // Keep the advertised proxy IP aligned with the selected ME writer source.
            let effective_our_addr = SocketAddr::new(w.source_ip, our_addr.port());
            let (payload, meta) = build_routed_payload(effective_our_addr);
            let bind_outcome = self
                .registry
                .bind_writer_with_outcome(conn_id, w.id, meta)
                .await;
            if bind_outcome != WriterBindOutcome::Bound {
                drop(permit);
                if bind_outcome == WriterBindOutcome::WriterRetiring {
                    debug!(
                        conn_id,
                        writer_id = w.id,
                        "ME writer entered replacement retirement before fallback bind commit"
                    );
                    continue;
                }
                if bind_outcome == WriterBindOutcome::RouteMissing {
                    return Err(ProxyError::Proxy(
                        "ME client route disappeared before writer bind".into(),
                    ));
                }
                debug!(
                    conn_id,
                    writer_id = w.id,
                    "ME writer disappeared before fallback bind commit, pruning stale writer"
                );
                self.remove_writer_and_close_clients(w.id).await;
                continue;
            }
            permit.send(WriterCommand::Data {
                payload,
                _permit: payload_permit.take(),
                writer_permit,
            });
            self.stats
                .increment_me_writer_pick_success_fallback_total(pick_mode);
            if w.generation < self.current_generation() {
                self.stats.increment_pool_stale_pick_total();
            }
            self.note_hybrid_route_success();
            return Ok(());
        }
    }
}
