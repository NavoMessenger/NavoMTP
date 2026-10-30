use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::{Mutex, oneshot};
use tokio_util::sync::CancellationToken;

use super::{IpFamily, MePool, STUN_CACHE_TTL};

// Context retirement and TTL tests use the same gates as production discovery.
#[cfg(test)]
mod tests;

/// Pool-local discovery gates; bound entries are limited to configured egress addresses.
#[derive(Default)]
pub(in crate::transport::middle_proxy) struct NatDiscovery {
    pub(super) http: Arc<Mutex<Option<Instant>>>,
    bound: Mutex<HashMap<(IpFamily, IpAddr), Arc<BoundDiscovery>>>,
}

#[derive(Default)]
struct BoundDiscovery {
    state: Arc<Mutex<BoundDiscoveryState>>,
    cancel: CancellationToken,
}

#[derive(Default)]
struct BoundDiscoveryState {
    reflection: Option<(Instant, SocketAddr)>,
    retry_after: Option<Instant>,
    attempt: u8,
}

impl NatDiscovery {
    async fn bound_context(
        &self,
        family: IpFamily,
        bind_ip: IpAddr,
        allowed: &BTreeSet<IpAddr>,
    ) -> Option<Arc<BoundDiscovery>> {
        let mut contexts = self.bound.lock().await;
        // Retired producers cannot republish into the map or a replacement context.
        contexts.retain(|(entry_family, ip), context| {
            let keep = *entry_family != family || allowed.contains(ip);
            if !keep {
                context.cancel.cancel();
            }
            keep
        });
        if !allowed.contains(&bind_ip) {
            return None;
        }
        Some(contexts.entry((family, bind_ip)).or_default().clone())
    }
}

impl MePool {
    /// Refreshes one configured source without borrowing another source's cached reflection.
    pub(super) async fn reflect_bound_addr(
        self: &Arc<Self>,
        family: IpFamily,
        bind_ip: IpAddr,
    ) -> Option<SocketAddr> {
        if bind_ip.is_ipv6() != matches!(family, IpFamily::V6) {
            return None;
        }
        let allowed = self
            .upstream
            .as_ref()?
            .direct_bind_ips_for_family(bind_ip.is_ipv6())
            .await;
        let context = self
            .nat_runtime
            .discovery
            .bound_context(family, bind_ip, &allowed)
            .await?;
        let mut flight = tokio::select! {
            biased;
            _ = context.cancel.cancelled() => return None,
            guard = context.state.clone().lock_owned() => guard,
        };
        if let Some((created, addr)) = flight.reflection
            && created.elapsed() < STUN_CACHE_TTL
        {
            return Some(addr);
        }
        if flight
            .retry_after
            .is_some_and(|until| Instant::now() < until)
        {
            return None;
        }

        let pool = self.clone();
        let (send, receive) = oneshot::channel();
        self.lifecycle.spawn_producer(async move {
            tokio::select! {
                biased;
                _ = context.cancel.cancelled() => {}
                _ = async {
                    let reflected = pool.refresh_stun(family, Some(bind_ip), flight.attempt).await;
                    if let Some(addr) = reflected {
                        flight.reflection = Some((Instant::now(), addr));
                        flight.retry_after = None;
                        flight.attempt = 0;
                    } else {
                        // Completed failures must also survive a short reconnect deadline.
                        let backoff = Duration::from_secs(60 * 2u64.pow(flight.attempt as u32));
                        flight.retry_after = Some(Instant::now() + backoff);
                        flight.attempt = flight.attempt.saturating_add(1).min(6);
                    }
                    let _ = send.send(reflected);
                } => {}
            }
        }).ok()?;
        receive.await.ok().flatten()
    }
}
