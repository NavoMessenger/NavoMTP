use super::*;

const HTTP_FRESH_TTL: Duration = Duration::from_secs(600);
const HTTP_MAX_AGE: Duration = Duration::from_secs(1200);

/// A successful HTTP observation has an immutable monotonic timestamp.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::transport::middle_proxy) struct HttpNatObservation {
    /// Successful detector result, never updated by a failed refresh.
    pub(in crate::transport::middle_proxy) ip: IpAddr,
    /// Original observation time used for both freshness and bounded stale fallback.
    pub(super) observed_at: tokio::time::Instant,
}

impl HttpNatObservation {
    fn usable(self) -> Option<IpAddr> {
        (self.observed_at.elapsed() < HTTP_MAX_AGE).then_some(self.ip)
    }

    fn fresh(self) -> bool {
        self.observed_at.elapsed() < HTTP_FRESH_TTL
    }
}

impl MePool {
    /// Reads a bounded cache snapshot without discovery or data-plane waiting.
    pub(in crate::transport::middle_proxy) fn cached_http_nat_ip(&self) -> Option<IpAddr> {
        self.nat_runtime
            .nat_ip_detected
            .try_read()
            .ok()
            .and_then(|cache| cache.and_then(HttpNatObservation::usable))
    }

    /// Refreshes once per pool, retaining stale success only within its original grace period.
    pub(in crate::transport::middle_proxy) async fn maybe_detect_nat_ip(
        self: &Arc<Self>,
        local_ip: IpAddr,
    ) -> Option<IpAddr> {
        if self.nat_runtime.nat_ip_cfg.is_some() {
            return self.nat_runtime.nat_ip_cfg;
        }
        if !self.nat_runtime.nat_probe
            || !local_ip.is_ipv4()
            || !(is_bogon(local_ip) || local_ip.is_loopback() || local_ip.is_unspecified())
        {
            return None;
        }
        if let Some(cached) = *self.nat_runtime.nat_ip_detected.read().await
            && cached.fresh()
        {
            return Some(cached.ip);
        }
        let mut flight = self.nat_runtime.discovery.http.clone().lock_owned().await;
        let cached = *self.nat_runtime.nat_ip_detected.read().await;
        if let Some(cached) = cached
            && cached.fresh()
        {
            return Some(cached.ip);
        }
        if flight.is_some_and(|until| Instant::now() < until) {
            return cached.and_then(HttpNatObservation::usable);
        }
        let pool = self.clone();
        let (send, receive) = oneshot::channel();
        // Discovery owns the flight; cancellation of a handshake cannot cancel publication.
        self.lifecycle
            .spawn_producer(async move {
                let detected = detect_public_ipv4_http(&pool.nat_runtime.http_ip_detect_urls)
                    .await
                    .map(IpAddr::V4);
                if let Some(ip) = detected {
                    *pool.nat_runtime.nat_ip_detected.write().await = Some(HttpNatObservation {
                        ip,
                        observed_at: tokio::time::Instant::now(),
                    });
                    *flight = None;
                    info!(public_ip = %ip, "Auto-detected public IP for NAT translation");
                } else {
                    *flight = Some(Instant::now() + HTTP_FAILURE_TTL);
                }
                let _ = send.send(());
            })
            .ok()?;
        let _ = receive.await;
        self.cached_http_nat_ip()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn observation_age_is_not_renewed_by_reads_or_failure() {
        let cached = HttpNatObservation {
            ip: "91.108.56.1".parse().unwrap(),
            observed_at: tokio::time::Instant::now(),
        };
        tokio::time::advance(HTTP_FRESH_TTL).await;
        assert!(!cached.fresh());
        for _ in 0..100 {
            assert_eq!(cached.usable(), Some(cached.ip));
        }
        tokio::time::advance(HTTP_MAX_AGE - HTTP_FRESH_TTL).await;
        assert_eq!(cached.usable(), None);
    }
}
