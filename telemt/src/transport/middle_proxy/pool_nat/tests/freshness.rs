use super::*;

#[tokio::test]
async fn failed_refresh_retains_original_age_but_never_expired_material() {
    let http = http_server("invalid address").await;
    http.release.add_permits(8);
    let pool = nat_pool(vec![], vec![format!("http://{}/", http.addr)]).await;
    let observed_at = tokio::time::Instant::now() - Duration::from_secs(601);
    *pool.nat_runtime.nat_ip_detected.write().await = Some(HttpNatObservation {
        ip: PUBLIC_IP.into(),
        observed_at,
    });
    assert_eq!(
        pool.maybe_detect_nat_ip(Ipv4Addr::LOCALHOST.into()).await,
        Some(PUBLIC_IP.into())
    );
    assert_eq!(
        pool.nat_runtime
            .nat_ip_detected
            .read()
            .await
            .unwrap()
            .observed_at,
        observed_at
    );
    assert_eq!(http.requests.load(Ordering::Acquire), 1);
    assert_eq!(
        pool.maybe_detect_nat_ip(Ipv4Addr::LOCALHOST.into()).await,
        Some(PUBLIC_IP.into())
    );
    assert_eq!(
        http.requests.load(Ordering::Acquire),
        1,
        "failure backoff remains singleflight"
    );
    pool.nat_runtime
        .nat_ip_detected
        .write()
        .await
        .as_mut()
        .unwrap()
        .observed_at = tokio::time::Instant::now() - Duration::from_secs(1201);
    assert_eq!(
        pool.maybe_detect_nat_ip(Ipv4Addr::LOCALHOST.into()).await,
        None
    );
    assert_eq!(
        pool.translate_ip_for_nat(Ipv4Addr::LOCALHOST.into()),
        IpAddr::V4(Ipv4Addr::LOCALHOST)
    );
    assert!(pool.shutdown_until(TEST_DEADLINE).await);
}

#[tokio::test]
async fn expired_http_observation_defers_handshake_before_sending_kdf_material() {
    let pool = nat_pool(vec![], vec![]).await;
    *pool.nat_runtime.nat_ip_detected.write().await = Some(HttpNatObservation {
        ip: PUBLIC_IP.into(),
        observed_at: tokio::time::Instant::now() - Duration::from_secs(1201),
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    let (mut peer, _) = listener.accept().await.unwrap();
    let error = pool
        .handshake_only(stream, addr, None, pool.rng.as_ref())
        .await
        .err()
        .unwrap();
    assert!(
        matches!(error, ProxyError::Io(ref error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
    assert_eq!(peer.read(&mut [0u8; 1]).await.unwrap(), 0);
    assert!(pool.shutdown_until(TEST_DEADLINE).await);
}
