use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use tracing::warn;

use super::pool::{MePool, WriterContour, WriterRole};
use super::pool_writer::WriterReplacementPurpose;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotApplyOutcome {
    AppliedChanged,
    AppliedNoDelta,
    RejectedEmpty,
}

impl SnapshotApplyOutcome {
    pub fn changed(self) -> bool {
        matches!(self, SnapshotApplyOutcome::AppliedChanged)
    }
}

impl MePool {
    pub async fn update_proxy_maps(
        &self,
        new_v4: HashMap<i32, Vec<(IpAddr, u16)>>,
        new_v6: Option<HashMap<i32, Vec<(IpAddr, u16)>>>,
    ) -> SnapshotApplyOutcome {
        if new_v4.is_empty() && new_v6.as_ref().is_none_or(|v| v.is_empty()) {
            return SnapshotApplyOutcome::RejectedEmpty;
        }

        let changed = {
            // Endpoint publication and reinit commit share this barrier.
            let mut coordinator = self.reinit.coordinator.lock();
            let current = self.endpoint_snapshot.load_full();
            let map_v4 = if new_v4.is_empty() {
                current.map_v4.clone()
            } else {
                new_v4
            };
            let map_v6 = match new_v6 {
                Some(map) if !map.is_empty() => map,
                _ => current.map_v6.clone(),
            };
            let candidate = Self::build_endpoint_snapshot(
                &self.decision,
                map_v4,
                map_v6,
                current.revision.saturating_add(1),
            );
            if candidate.map_v4 == current.map_v4 && candidate.map_v6 == current.map_v6 {
                false
            } else {
                coordinator.endpoint_revision = candidate.revision;
                self.endpoint_snapshot.store(Arc::new(candidate));
                true
            }
        };
        if changed {
            self.prune_endpoint_runtime_state().await;
            self.notify_writer_epoch();
        }
        if changed {
            SnapshotApplyOutcome::AppliedChanged
        } else {
            SnapshotApplyOutcome::AppliedNoDelta
        }
    }

    pub async fn update_secret(self: &Arc<Self>, new_secret: Vec<u8>) -> bool {
        if new_secret.len() < 32 {
            warn!(
                len = new_secret.len(),
                "proxy-secret update ignored (too short)"
            );
            return false;
        }
        let mut guard = self.proxy_secret.write().await;
        if guard.secret != new_secret {
            guard.secret = new_secret;
            guard.key_selector = if guard.secret.len() >= 4 {
                u32::from_le_bytes([
                    guard.secret[0],
                    guard.secret[1],
                    guard.secret[2],
                    guard.secret[3],
                ])
            } else {
                0
            };
            guard.epoch = guard.epoch.saturating_add(1);
            drop(guard);
            self.reconnect_all().await;
            return true;
        }
        false
    }

    pub async fn reconnect_all(self: &Arc<Self>) {
        let ws = self.writers.read().await.clone();
        for w in ws.iter() {
            let role = WriterRole::from_writer(w);
            if w.draining.load(std::sync::atomic::Ordering::Acquire)
                || role.contour == WriterContour::Draining
            {
                continue;
            }
            let Some(mut reservation) = self
                .registry
                .try_reserve_writer_replacement_preserving_clients(w.id)
                .await
            else {
                continue;
            };
            if self
                .replace_writer_with_generation_contour_for_dc(
                    w.addr,
                    self.rng.as_ref(),
                    role.generation,
                    role.contour,
                    role.dc,
                    role,
                    WriterReplacementPurpose::SecretRotation,
                    &mut reservation,
                )
                .await
                .is_ok()
            {
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
}
