use super::*;
use crate::config::{UpstreamConfig, UpstreamType};
use crate::transport::UpstreamManager;

/// Gives an isolated pool the same finite bind-address authority as production egress.
pub(in crate::transport::middle_proxy::pool_nat) fn set_bind_addresses(
    pool: &mut Arc<MePool>,
    addresses: &[&str],
) {
    let manager = UpstreamManager::new(
        vec![UpstreamConfig {
            upstream_type: UpstreamType::Direct {
                interface: None,
                bind_addresses: Some(addresses.iter().map(|value| value.to_string()).collect()),
                bindtodevice: None,
            },
            weight: 1,
            enabled: true,
            scopes: String::new(),
            selected_scope: String::new(),
            ipv4: None,
            ipv6: None,
            prefer: None,
        }],
        1,
        0,
        1000,
        1,
        1,
        true,
        pool.stats.clone(),
    );
    Arc::get_mut(pool).unwrap().upstream = Some(Arc::new(manager));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cancelled_waiter_storm_shares_one_http_and_stun_producer() {
    let http = http_server("91.108.56.1").await;
    let stun = stun_server("127.0.0.1:0".parse().unwrap(), PUBLIC_IP.into()).await;
    let pool = nat_pool(
        vec![stun.addr.to_string()],
        vec![format!("http://{}/", http.addr)],
    )
    .await;
    let mut waiters = JoinSet::new();
    for _ in 0..32 {
        let pool = pool.clone();
        waiters.spawn(async move {
            tokio::join!(
                pool.maybe_detect_nat_ip(Ipv4Addr::LOCALHOST.into()),
                pool.maybe_reflect_public_addr(IpFamily::V4, None),
            );
        });
    }
    http.received().await;
    stun.received().await;
    waiters.abort_all();
    while waiters.join_next().await.is_some() {}
    http.release.add_permits(64);
    stun.release.add_permits(64);
    assert_eq!(
        pool.maybe_detect_nat_ip(Ipv4Addr::LOCALHOST.into()).await,
        Some(PUBLIC_IP.into())
    );
    assert_eq!(
        pool.maybe_reflect_public_addr(IpFamily::V4, None)
            .await
            .unwrap()
            .ip(),
        PUBLIC_IP
    );
    assert_eq!(http.requests.load(Ordering::Relaxed), 1);
    assert_eq!(stun.requests.load(Ordering::Relaxed), 1);
    assert!(pool.shutdown_until(TEST_DEADLINE).await);
}

#[tokio::test]
async fn shutdown_cancels_discovery_and_releases_all_waiters() {
    let http = http_server("91.108.56.1").await;
    let stun = stun_server("127.0.0.1:0".parse().unwrap(), PUBLIC_IP.into()).await;
    let pool = nat_pool(
        vec![stun.addr.to_string()],
        vec![format!("http://{}/", http.addr)],
    )
    .await;
    let waiter_pool = pool.clone();
    let waiter = tokio::spawn(async move {
        tokio::join!(
            waiter_pool.maybe_detect_nat_ip(Ipv4Addr::LOCALHOST.into()),
            waiter_pool.maybe_reflect_public_addr(IpFamily::V4, None),
        )
    });
    http.received().await;
    stun.received().await;
    assert!(pool.shutdown_until(TEST_DEADLINE).await);
    assert_eq!(
        timeout(TEST_DEADLINE, waiter).await.unwrap().unwrap(),
        (None, None)
    );
    http.release.add_permits(64);
    stun.release.add_permits(64);
    assert_eq!(
        pool.maybe_detect_nat_ip(Ipv4Addr::LOCALHOST.into()).await,
        None
    );
    assert_eq!(
        pool.maybe_reflect_public_addr(IpFamily::V4, None).await,
        None
    );
    assert_eq!(*pool.nat_runtime.nat_ip_detected.read().await, None);
    assert_eq!(pool.nat_runtime.nat_reflection_cache.lock().await.v4, None);
    assert_eq!(http.requests.load(Ordering::Relaxed), 1);
    assert_eq!(stun.requests.load(Ordering::Relaxed), 1);
    assert!(
        pool.nat_runtime
            .nat_reflection_singleflight_v4
            .try_lock()
            .is_ok()
    );
    assert!(pool.nat_runtime.discovery.http.try_lock().is_ok());
}

#[tokio::test]
async fn bound_refresh_survives_cancellation_and_reuses_only_its_source() {
    let stun = stun_server("127.0.0.1:0".parse().unwrap(), PUBLIC_IP.into()).await;
    let mut pool = nat_pool(vec![stun.addr.to_string()], vec![]).await;
    set_bind_addresses(&mut pool, &["127.0.0.1", "127.0.0.2"]);
    let bind = Some(Ipv4Addr::LOCALHOST.into());
    let waiter_pool = pool.clone();
    let waiter = tokio::spawn(async move {
        waiter_pool
            .maybe_reflect_public_addr(IpFamily::V4, bind)
            .await
    });
    stun.received().await;
    waiter.abort();
    assert!(waiter.await.unwrap_err().is_cancelled());
    stun.release.add_permits(64);
    assert_eq!(
        pool.maybe_reflect_public_addr(IpFamily::V4, bind)
            .await
            .unwrap()
            .ip(),
        PUBLIC_IP
    );
    assert_eq!(stun.requests.load(Ordering::Relaxed), 1);
    assert_eq!(pool.nat_runtime.nat_reflection_cache.lock().await.v4, None);
    let other = Some("127.0.0.2".parse().unwrap());
    assert_eq!(
        pool.maybe_reflect_public_addr(IpFamily::V4, other)
            .await
            .unwrap()
            .ip(),
        PUBLIC_IP
    );
    assert_eq!(stun.requests.load(Ordering::Relaxed), 2);
    assert!(
        pool.maybe_reflect_public_addr(IpFamily::V4, Some("127.0.0.3".parse().unwrap()))
            .await
            .is_none()
    );
    assert!(
        pool.maybe_reflect_public_addr(IpFamily::V6, bind)
            .await
            .is_none()
    );
    assert_eq!(stun.requests.load(Ordering::Relaxed), 2);
    assert!(pool.shutdown_until(TEST_DEADLINE).await);
}

#[tokio::test]
async fn failed_bound_refresh_is_observable_after_caller_cancellation() {
    let stun = stun_server_response("127.0.0.1:0".parse().unwrap(), None, Duration::ZERO).await;
    let mut pool = nat_pool(vec![stun.addr.to_string()], vec![]).await;
    set_bind_addresses(&mut pool, &["127.0.0.1"]);
    let bind = Some(Ipv4Addr::LOCALHOST.into());
    let waiter_pool = pool.clone();
    let waiter = tokio::spawn(async move {
        waiter_pool
            .maybe_reflect_public_addr(IpFamily::V4, bind)
            .await
    });
    stun.received().await;
    waiter.abort();
    let _ = waiter.await;
    // One response completes the original probe; a restarted probe would block forever here.
    stun.release.add_permits(1);
    assert_eq!(
        timeout(
            TEST_DEADLINE,
            pool.maybe_reflect_public_addr(IpFamily::V4, bind)
        )
        .await
        .unwrap(),
        None
    );
    assert_eq!(
        timeout(
            TEST_DEADLINE,
            pool.maybe_reflect_public_addr(IpFamily::V4, bind)
        )
        .await
        .unwrap(),
        None
    );
    assert_eq!(stun.requests.load(Ordering::Relaxed), 1);
    assert!(pool.shutdown_until(TEST_DEADLINE).await);
}

#[tokio::test]
async fn http_negative_cache_expires_without_waiting_a_minute() {
    let http = http_server("invalid").await;
    http.release.add_permits(64);
    let pool = nat_pool(vec![], vec![format!("http://{}/", http.addr)]).await;
    assert_eq!(
        pool.maybe_detect_nat_ip(Ipv4Addr::LOCALHOST.into()).await,
        None
    );
    *pool.nat_runtime.discovery.http.lock().await = Some(Instant::now() - Duration::from_secs(1));
    assert_eq!(
        pool.maybe_detect_nat_ip(Ipv4Addr::LOCALHOST.into()).await,
        None
    );
    assert_eq!(http.requests.load(Ordering::Relaxed), 2);
    assert!(pool.shutdown_until(TEST_DEADLINE).await);
}

#[tokio::test]
async fn ipv6_refresh_is_independent_of_blocked_ipv4_refresh() {
    let v4 = stun_server("127.0.0.1:0".parse().unwrap(), PUBLIC_IP.into()).await;
    let public_v6: IpAddr = "2001:4860:4860::8888".parse().unwrap();
    let v6 = stun_server("[::1]:0".parse().unwrap(), public_v6).await;
    v6.release.add_permits(16);
    let pool = nat_pool(vec![v4.addr.to_string(), v6.addr.to_string()], vec![]).await;
    let waiter_pool = pool.clone();
    let waiter = tokio::spawn(async move {
        waiter_pool
            .maybe_reflect_public_addr(IpFamily::V4, None)
            .await
    });
    v4.received().await;
    assert_eq!(
        timeout(
            TEST_DEADLINE,
            pool.maybe_reflect_public_addr(IpFamily::V6, None)
        )
        .await
        .unwrap()
        .unwrap()
        .ip(),
        public_v6
    );
    assert!(!waiter.is_finished());
    v4.release.add_permits(16);
    assert_eq!(waiter.await.unwrap().unwrap().ip(), PUBLIC_IP);
    assert_eq!(
        pool.nat_runtime
            .nat_reflection_cache
            .lock()
            .await
            .v4
            .unwrap()
            .1
            .ip(),
        PUBLIC_IP
    );
    assert_eq!(
        pool.nat_runtime
            .nat_reflection_cache
            .lock()
            .await
            .v6
            .unwrap()
            .1
            .ip(),
        public_v6
    );
    assert!(pool.shutdown_until(TEST_DEADLINE).await);
}

#[tokio::test]
async fn failed_shared_refresh_publishes_backoff_after_caller_cancellation() {
    let stun = stun_server_response("127.0.0.1:0".parse().unwrap(), None, Duration::ZERO).await;
    let pool = nat_pool(vec![stun.addr.to_string()], vec![]).await;
    let waiter_pool = pool.clone();
    let waiter = tokio::spawn(async move {
        waiter_pool
            .maybe_reflect_public_addr(IpFamily::V4, None)
            .await
    });
    stun.received().await;
    waiter.abort();
    let _ = waiter.await;
    stun.release.add_permits(1);
    assert_eq!(
        timeout(
            TEST_DEADLINE,
            pool.maybe_reflect_public_addr(IpFamily::V4, None)
        )
        .await
        .unwrap(),
        None
    );
    assert!(pool.nat_runtime.stun_backoff_until.read().await.unwrap() > Instant::now());
    assert_eq!(
        pool.maybe_reflect_public_addr(IpFamily::V4, None).await,
        None
    );
    assert_eq!(stun.requests.load(Ordering::Relaxed), 1);
    assert!(pool.shutdown_until(TEST_DEADLINE).await);
}

#[tokio::test]
async fn shutdown_before_producer_first_poll_releases_owned_gates() {
    let http = http_server("91.108.56.1").await;
    let stun = stun_server("127.0.0.1:0".parse().unwrap(), PUBLIC_IP.into()).await;
    let pool = nat_pool(
        vec![stun.addr.to_string()],
        vec![format!("http://{}/", http.addr)],
    )
    .await;
    let mut http_waiter =
        tokio_test::task::spawn(pool.maybe_detect_nat_ip(Ipv4Addr::LOCALHOST.into()));
    let mut stun_waiter =
        tokio_test::task::spawn(pool.maybe_reflect_public_addr(IpFamily::V4, None));
    assert!(http_waiter.poll().is_pending());
    assert!(stun_waiter.poll().is_pending());
    // On this current-thread runtime neither producer can run before shutdown admission closes.
    pool.begin_shutdown();
    assert!(pool.shutdown_until(TEST_DEADLINE).await);
    assert_eq!(http_waiter.poll(), std::task::Poll::Ready(None));
    assert_eq!(stun_waiter.poll(), std::task::Poll::Ready(None));
    assert_eq!(http.requests.load(Ordering::Relaxed), 0);
    assert_eq!(stun.requests.load(Ordering::Relaxed), 0);
    assert!(pool.nat_runtime.discovery.http.try_lock().is_ok());
    assert!(
        pool.nat_runtime
            .nat_reflection_singleflight_v4
            .try_lock()
            .is_ok()
    );
}
