use std::sync::atomic::Ordering;

use serde::Serialize;

use super::WebTelemetry;

/// Terminal capability-routing work selected for one WEB root request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub(crate) enum WebDecoyFastTrackDisposition {
    /// Shadow mode identified a request that enforce mode would bypass.
    ShadowWouldFastTrack,
    /// Shadow mode retained a full scan for a plausible capability request.
    ShadowCandidateFullScan,
    /// Enforce mode bypassed a structurally impossible capability request.
    EnforceFastTrack,
    /// Enforce mode retained a full scan for a plausible capability request.
    EnforceCandidateFullScan,
}

impl WebDecoyFastTrackDisposition {
    /// Complete fixed disposition set in stable API and metric order.
    pub(crate) const ALL: [Self; 4] = [
        Self::ShadowWouldFastTrack,
        Self::ShadowCandidateFullScan,
        Self::EnforceFastTrack,
        Self::EnforceCandidateFullScan,
    ];

    /// Returns the stable API and Prometheus label token.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::ShadowWouldFastTrack => "shadow_would_fasttrack",
            Self::ShadowCandidateFullScan => "shadow_candidate_full_scan",
            Self::EnforceFastTrack => "enforce_fasttrack",
            Self::EnforceCandidateFullScan => "enforce_candidate_full_scan",
        }
    }
}

/// Fixed storage width for process-owned decoy fast-track counters.
pub(super) const DECOY_FASTTRACK_SLOTS: usize = WebDecoyFastTrackDisposition::ALL.len();

/// API-safe fixed decoy fast-track counter.
#[derive(Clone, Serialize)]
pub(crate) struct WebDecoyFastTrackCounter {
    /// Stable capability-routing disposition token.
    pub(crate) disposition: &'static str,
    /// Process-lifetime event count.
    pub(crate) total: u64,
}

impl WebTelemetry {
    /// Records one shadow or enforce capability-routing disposition.
    pub(crate) fn record_decoy_fasttrack(&self, disposition: WebDecoyFastTrackDisposition) {
        self.decoy_fasttrack_requests[disposition as usize].fetch_add(1, Ordering::Relaxed);
    }

    /// Returns one fixed decoy fast-track counter.
    pub(crate) fn decoy_fasttrack_total(&self, disposition: WebDecoyFastTrackDisposition) -> u64 {
        self.decoy_fasttrack_requests[disposition as usize].load(Ordering::Relaxed)
    }

    /// Captures the complete decoy fast-track counter set.
    pub(crate) fn decoy_fasttrack_counters(&self) -> Vec<WebDecoyFastTrackCounter> {
        WebDecoyFastTrackDisposition::ALL
            .into_iter()
            .map(|disposition| WebDecoyFastTrackCounter {
                disposition: disposition.as_str(),
                total: self.decoy_fasttrack_total(disposition),
            })
            .collect()
    }
}
