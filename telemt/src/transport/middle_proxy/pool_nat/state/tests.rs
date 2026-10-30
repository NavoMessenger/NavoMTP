use super::*;
use crate::transport::middle_proxy::pool_nat::tests::lifecycle::set_bind_addresses;
use crate::transport::middle_proxy::pool_nat::tests::{
    PUBLIC_IP, TEST_DEADLINE, nat_pool, stun_server,
};
use std::net::Ipv4Addr;
use std::sync::atomic::Ordering;
use tokio::time::timeout;

#[tokio::test]
async fn bound_positive_ttl_refreshes_without_publishing_to_default_cache() {
    let stun = stun_server("127.0.0.1:0".parse().unwrap(), PUBLIC_IP.into()).await;
    stun.release.add_permits(16);
    let mut pool = nat_pool(vec![stun.addr.to_string()], vec![]).await;
    set_bind_addresses(&mut pool, &["127.0.0.1"]);
    let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let allowed = BTreeSet::from([ip]);
    let context = pool
        .nat_runtime
        .discovery
        .bound_context(IpFamily::V4, ip, &allowed)
        .await
        .unwrap();
    assert!(
        pool.maybe_reflect_public_addr(IpFamily::V4, Some(ip))
            .await
            .is_some()
    );
    assert!(
        pool.maybe_reflect_public_addr(IpFamily::V4, Some(ip))
            .await
            .is_some()
    );
    assert_eq!(stun.requests.load(Ordering::Relaxed), 1);
    context.state.lock().await.reflection.as_mut().unwrap().0 = Instant::now() - STUN_CACHE_TTL;
    assert!(
        pool.maybe_reflect_public_addr(IpFamily::V4, Some(ip))
            .await
            .is_some()
    );
    assert_eq!(stun.requests.load(Ordering::Relaxed), 2);
    assert_eq!(pool.nat_runtime.nat_reflection_cache.lock().await.v4, None);
    assert!(pool.shutdown_until(TEST_DEADLINE).await);
}

#[tokio::test]
async fn context_churn_is_bounded_and_retirement_does_not_mix_families() {
    let discovery = NatDiscovery::default();
    let v6: IpAddr = "::1".parse().unwrap();
    let v6_context = discovery
        .bound_context(IpFamily::V6, v6, &BTreeSet::from([v6]))
        .await
        .unwrap();
    let mut previous: Option<Arc<BoundDiscovery>> = None;
    for suffix in 1..=1000u32 {
        let ip = IpAddr::V4(Ipv4Addr::from(0x7f000000 + suffix));
        let context = discovery
            .bound_context(IpFamily::V4, ip, &BTreeSet::from([ip]))
            .await
            .unwrap();
        if let Some(old) = previous.replace(context.clone()) {
            assert!(old.cancel.is_cancelled());
        }
        assert!(!context.cancel.is_cancelled());
        assert!(!v6_context.cancel.is_cancelled());
        assert_eq!(discovery.bound.lock().await.len(), 2);
    }
    let denied = IpAddr::V4(Ipv4Addr::LOCALHOST);
    assert!(
        discovery
            .bound_context(IpFamily::V4, denied, &BTreeSet::new())
            .await
            .is_none()
    );
    assert!(previous.unwrap().cancel.is_cancelled());
    assert_eq!(discovery.bound.lock().await.len(), 1);
}

#[tokio::test]
async fn retiring_bound_context_cancels_its_producer_and_prevents_late_publication() {
    let stun = stun_server("127.0.0.1:0".parse().unwrap(), PUBLIC_IP.into()).await;
    let mut pool = nat_pool(vec![stun.addr.to_string()], vec![]).await;
    set_bind_addresses(&mut pool, &["127.0.0.1"]);
    let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let context = pool
        .nat_runtime
        .discovery
        .bound_context(IpFamily::V4, ip, &BTreeSet::from([ip]))
        .await
        .unwrap();
    let waiter_pool = pool.clone();
    let waiter = tokio::spawn(async move {
        waiter_pool
            .maybe_reflect_public_addr(IpFamily::V4, Some(ip))
            .await
    });
    stun.received().await;
    assert!(
        pool.nat_runtime
            .discovery
            .bound_context(IpFamily::V4, ip, &BTreeSet::new())
            .await
            .is_none()
    );
    assert_eq!(timeout(TEST_DEADLINE, waiter).await.unwrap().unwrap(), None);
    stun.release.add_permits(16);
    assert_eq!(context.state.lock().await.reflection, None);
    assert!(pool.nat_runtime.discovery.bound.lock().await.is_empty());
    assert!(pool.shutdown_until(TEST_DEADLINE).await);
}

#[tokio::test]
async fn bound_failure_retry_deadline_expires_and_success_resets_backoff() {
    let stun = stun_server("127.0.0.1:0".parse().unwrap(), PUBLIC_IP.into()).await;
    stun.release.add_permits(16);
    let mut pool = nat_pool(vec![stun.addr.to_string()], vec![]).await;
    set_bind_addresses(&mut pool, &["127.0.0.1"]);
    let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
    let context = pool
        .nat_runtime
        .discovery
        .bound_context(IpFamily::V4, ip, &BTreeSet::from([ip]))
        .await
        .unwrap();
    {
        let mut state = context.state.lock().await;
        state.retry_after = Some(Instant::now() + Duration::from_secs(60));
        state.attempt = 3;
    }
    assert!(
        pool.maybe_reflect_public_addr(IpFamily::V4, Some(ip))
            .await
            .is_none()
    );
    assert_eq!(stun.requests.load(Ordering::Relaxed), 0);
    context.state.lock().await.retry_after = Some(Instant::now() - Duration::from_secs(1));
    assert!(
        pool.maybe_reflect_public_addr(IpFamily::V4, Some(ip))
            .await
            .is_some()
    );
    assert_eq!(context.state.lock().await.attempt, 0);
    assert_eq!(context.state.lock().await.retry_after, None);
    assert_eq!(stun.requests.load(Ordering::Relaxed), 1);
    assert!(pool.shutdown_until(TEST_DEADLINE).await);
}
