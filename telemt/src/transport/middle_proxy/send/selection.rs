use std::cmp::Reverse;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;

use super::super::MePool;
use super::super::pool::WriterContour;
use super::{
    IDLE_WRITER_PENALTY_HIGH_SECS, IDLE_WRITER_PENALTY_MID_SECS, PICK_PENALTY_DEGRADED,
    PICK_PENALTY_DRAINING, PICK_PENALTY_STALE, PICK_PENALTY_WARM,
};
use crate::config::MeWriterPickMode;

struct WriterSelectionKey {
    index: usize,
    contour_rank: usize,
    stale: usize,
    degraded: usize,
    idle_rank: usize,
    queue_remaining: usize,
    addr: SocketAddr,
    id: u64,
    pick_score: u64,
}

impl MePool {
    pub(super) async fn candidate_indices_for_dc(
        &self,
        writers: &[super::super::pool::MeWriter],
        routed_dc: i32,
        include_warm: bool,
    ) -> Vec<usize> {
        let endpoint_snapshot = self.endpoint_snapshot.load();
        let preferred_snapshot = &endpoint_snapshot.preferred_endpoints_by_dc;
        let mut out = Vec::new();
        if let Some(preferred) = preferred_snapshot
            .get(&routed_dc)
            .filter(|preferred| !preferred.is_empty())
        {
            for (idx, w) in writers.iter().enumerate() {
                if !self.writer_eligible_for_selection(w, include_warm) {
                    continue;
                }
                if w.writer_dc == routed_dc && preferred.binary_search(&w.addr).is_ok() {
                    out.push(idx);
                }
            }
        }
        if !out.is_empty() || !include_warm {
            return out;
        }

        // A map update publishes desired endpoints before replacement coverage is
        // guaranteed. Preserve the existing same-DC writer as the final tier so
        // the data plane remains available while the pool-owned reinit converges.
        for (idx, w) in writers.iter().enumerate() {
            let family_enabled = if w.addr.is_ipv4() {
                self.decision.ipv4_me
            } else {
                self.decision.ipv6_me
            };
            if family_enabled
                && w.writer_dc == routed_dc
                && self.writer_eligible_for_selection(w, true)
            {
                out.push(idx);
            }
        }
        out
    }

    pub(super) fn writer_eligible_for_selection(
        &self,
        writer: &super::super::pool::MeWriter,
        include_warm: bool,
    ) -> bool {
        if !self.writer_accepts_new_binding(writer) {
            return false;
        }

        match WriterContour::from_u8(writer.contour.load(Ordering::Relaxed)) {
            WriterContour::Active => true,
            WriterContour::Warm => include_warm,
            WriterContour::Draining => true,
        }
    }

    fn writer_contour_rank_for_selection(contour: WriterContour) -> usize {
        match contour {
            WriterContour::Active => 0,
            WriterContour::Warm => 1,
            WriterContour::Draining => 2,
        }
    }

    fn writer_idle_rank_for_selection(
        writer_id: u64,
        idle_since_by_writer: &HashMap<u64, u64>,
        now_epoch_secs: u64,
    ) -> usize {
        let Some(idle_since) = idle_since_by_writer.get(&writer_id).copied() else {
            return 0;
        };
        let idle_age_secs = now_epoch_secs.saturating_sub(idle_since);
        if idle_age_secs >= IDLE_WRITER_PENALTY_HIGH_SECS {
            2
        } else if idle_age_secs >= IDLE_WRITER_PENALTY_MID_SECS {
            1
        } else {
            0
        }
    }

    fn capture_writer_selection_key(
        &self,
        index: usize,
        writer: &super::super::pool::MeWriter,
        idle_since_by_writer: &HashMap<u64, u64>,
        now_epoch_secs: u64,
        current_generation: u64,
    ) -> WriterSelectionKey {
        let contour = WriterContour::from_u8(writer.contour.load(Ordering::Relaxed));
        let contour_rank = Self::writer_contour_rank_for_selection(contour);
        let contour_penalty = match contour {
            WriterContour::Active => 0,
            WriterContour::Warm => PICK_PENALTY_WARM,
            WriterContour::Draining => PICK_PENALTY_DRAINING,
        };
        let stale = (writer.generation < current_generation) as usize;
        let stale_penalty = if stale != 0 { PICK_PENALTY_STALE } else { 0 };
        let degraded = writer.degraded.load(Ordering::Relaxed) as usize;
        let degraded_penalty = if degraded != 0 {
            PICK_PENALTY_DEGRADED
        } else {
            0
        };
        let idle_rank =
            Self::writer_idle_rank_for_selection(writer.id, idle_since_by_writer, now_epoch_secs);
        let idle_penalty = (idle_rank as u64) * 100;
        let queue_cap = self.writer_lifecycle.writer_cmd_channel_capacity.max(1) as u64;
        let queue_remaining = writer.tx.capacity();
        let queue_used = queue_cap.saturating_sub((queue_remaining as u64).min(queue_cap));
        let queue_util_pct = queue_used.saturating_mul(100) / queue_cap;
        let queue_penalty = queue_util_pct.saturating_mul(4);
        let rtt_penalty =
            ((writer.rtt_ema_ms_x10.load(Ordering::Relaxed) as u64).saturating_add(5) / 10)
                .min(400);

        let pick_score = contour_penalty
            .saturating_add(stale_penalty)
            .saturating_add(degraded_penalty)
            .saturating_add(idle_penalty)
            .saturating_add(queue_penalty)
            .saturating_add(rtt_penalty);
        WriterSelectionKey {
            index,
            contour_rank,
            stale,
            degraded,
            idle_rank,
            queue_remaining,
            addr: writer.addr,
            id: writer.id,
            pick_score,
        }
    }

    pub(super) fn p2c_ordered_candidate_indices(
        &self,
        mut candidate_indices: Vec<usize>,
        writers_snapshot: &[super::super::pool::MeWriter],
        idle_since_by_writer: &HashMap<u64, u64>,
        now_epoch_secs: u64,
        start: usize,
        sample_size: usize,
    ) -> Vec<usize> {
        let total = candidate_indices.len();
        if total == 0 {
            return Vec::new();
        }

        candidate_indices.rotate_left(start % total);
        let current_generation = self.current_generation();
        let sample_size = sample_size.min(total);
        let mut sampled = candidate_indices[..sample_size]
            .iter()
            .map(|idx| {
                self.capture_writer_selection_key(
                    *idx,
                    &writers_snapshot[*idx],
                    idle_since_by_writer,
                    now_epoch_secs,
                    current_generation,
                )
            })
            .collect::<Vec<_>>();
        sampled.sort_by_key(|candidate| (candidate.pick_score, candidate.addr, candidate.id));
        for (target, candidate) in candidate_indices[..sample_size].iter_mut().zip(sampled) {
            *target = candidate.index;
        }
        candidate_indices
    }

    pub(super) async fn ordered_candidate_indices(
        &self,
        mut candidate_indices: Vec<usize>,
        writers_snapshot: &[super::super::pool::MeWriter],
        pick_mode: MeWriterPickMode,
    ) -> Vec<usize> {
        let pick_sample_size = self.writer_pick_sample_size();
        let writer_ids: Vec<u64> = candidate_indices
            .iter()
            .map(|idx| writers_snapshot[*idx].id)
            .collect();
        let writer_idle_since = self
            .registry
            .writer_idle_since_for_writer_ids(&writer_ids)
            .await;
        let now_epoch_secs = Self::now_epoch_secs();
        let start = self.rr.fetch_add(1, Ordering::Relaxed) as usize % candidate_indices.len();
        if pick_mode == MeWriterPickMode::P2c {
            return self.p2c_ordered_candidate_indices(
                candidate_indices,
                writers_snapshot,
                &writer_idle_since,
                now_epoch_secs,
                start,
                pick_sample_size,
            );
        }

        if self
            .writer_selection_policy
            .me_deterministic_writer_sort
            .load(Ordering::Relaxed)
        {
            let current_generation = self.current_generation();
            let mut captured = candidate_indices
                .iter()
                .map(|idx| {
                    self.capture_writer_selection_key(
                        *idx,
                        &writers_snapshot[*idx],
                        &writer_idle_since,
                        now_epoch_secs,
                        current_generation,
                    )
                })
                .collect::<Vec<_>>();
            captured.sort_by_key(|candidate| {
                (
                    candidate.contour_rank,
                    candidate.stale,
                    candidate.degraded,
                    candidate.idle_rank,
                    Reverse(candidate.queue_remaining),
                    candidate.addr,
                    candidate.id,
                )
            });
            for (target, candidate) in candidate_indices.iter_mut().zip(captured) {
                *target = candidate.index;
            }
        } else {
            let current_generation = self.current_generation();
            let mut captured = candidate_indices
                .iter()
                .map(|idx| {
                    self.capture_writer_selection_key(
                        *idx,
                        &writers_snapshot[*idx],
                        &writer_idle_since,
                        now_epoch_secs,
                        current_generation,
                    )
                })
                .collect::<Vec<_>>();
            captured.sort_by_key(|candidate| {
                (
                    candidate.contour_rank,
                    candidate.stale,
                    candidate.degraded,
                    candidate.idle_rank,
                    Reverse(candidate.queue_remaining),
                )
            });
            for (target, candidate) in candidate_indices.iter_mut().zip(captured) {
                *target = candidate.index;
            }
        }

        if !candidate_indices.is_empty() {
            let len = candidate_indices.len();
            candidate_indices.rotate_left(start % len);
        }
        candidate_indices
    }
}
