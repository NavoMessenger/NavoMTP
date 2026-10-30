use super::*;
use crate::crypto::{SecureRandom, derive_middleproxy_keys};
use crate::transport::middle_proxy::codec::{
    RpcChecksumMode, build_handshake_payload, build_nonce_payload, build_rpc_frame,
    cbc_decrypt_inplace, cbc_encrypt_padded, parse_handshake_flags, parse_nonce_payload,
    read_rpc_frame_plaintext, rpc_crc,
};
use crate::transport::middle_proxy::me_health_monitor;
use crate::transport::middle_proxy::pool::MeFamilyRuntimeState;
use tokio::net::TcpStream;

struct MiddlePeer {
    addr: SocketAddr,
    handshakes: Arc<AtomicUsize>,
    cancelled: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Drop for MiddlePeer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl MiddlePeer {
    async fn new(server_ip: Ipv4Addr) -> Self {
        Self::with_bind("127.0.0.1:0", server_ip.into(), PUBLIC_IP.into()).await
    }

    async fn with_bind(bind: &str, server_ip: IpAddr, client_ip: IpAddr) -> Self {
        let listener = TcpListener::bind(bind).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handshakes = Arc::new(AtomicUsize::new(0));
        let cancelled = Arc::new(AtomicUsize::new(0));
        let succeeded = handshakes.clone();
        let closed = cancelled.clone();
        let task = tokio::spawn(async move {
            let mut pending = JoinSet::new();
            let mut established = Vec::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (stream, _) = accepted.unwrap();
                        pending.spawn(accept_handshake(stream, server_ip, client_ip));
                    }
                    completed = pending.join_next(), if !pending.is_empty() => {
                        match completed.unwrap().expect("fake ME handshake task must not panic") {
                            Some(stream) => {
                                established.push(stream);
                                succeeded.fetch_add(1, Ordering::Release);
                            }
                            None => { closed.fetch_add(1, Ordering::Release); }
                        }
                    }
                }
            }
        });
        Self {
            addr,
            handshakes,
            cancelled,
            task,
        }
    }
}

async fn accept_handshake(
    mut stream: TcpStream,
    server_ip: IpAddr,
    client_ip: IpAddr,
) -> Option<TcpStream> {
    let client_port = stream.peer_addr().unwrap().port();
    let server_port = stream.local_addr().unwrap().port();
    let (seq, payload) = match read_rpc_frame_plaintext(&mut stream).await {
        Ok(frame) => frame,
        // Reconnect may time out during NAT discovery, before sending any nonce.
        Err(ProxyError::Io(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => {
            return None;
        }
        Err(error) => panic!("invalid client nonce: {error}"),
    };
    assert_eq!(seq, -2);
    let (selector, _, timestamp, client_nonce) = parse_nonce_payload(&payload).unwrap();
    let server_nonce = [0x42u8; 16];
    let nonce = build_nonce_payload(selector, timestamp, &server_nonce);
    stream
        .write_all(&build_rpc_frame(-2, &nonce, RpcChecksumMode::Crc32))
        .await
        .unwrap();
    let split = |ip: IpAddr| match ip {
        IpAddr::V4(ip) => {
            let mut octets = ip.octets();
            octets.reverse();
            (Some(octets), None)
        }
        IpAddr::V6(ip) => (None, Some(ip.octets())),
    };
    let (client_v4, client_v6) = split(client_ip);
    let (server_v4, server_v6) = split(server_ip);
    let client_ip = client_v4.unwrap_or([0; 4]);
    let server_ip = server_v4.unwrap_or([0; 4]);
    let (read_key, read_iv) = derive_middleproxy_keys(
        &server_nonce,
        &client_nonce,
        &timestamp.to_le_bytes(),
        server_v4.as_ref().map(|ip| ip.as_slice()),
        &client_port.to_le_bytes(),
        b"CLIENT",
        client_v4.as_ref().map(|ip| ip.as_slice()),
        &server_port.to_le_bytes(),
        &[1u8; 32],
        client_v6.as_ref(),
        server_v6.as_ref(),
    );
    let (write_key, write_iv) = derive_middleproxy_keys(
        &server_nonce,
        &client_nonce,
        &timestamp.to_le_bytes(),
        server_v4.as_ref().map(|ip| ip.as_slice()),
        &client_port.to_le_bytes(),
        b"SERVER",
        client_v4.as_ref().map(|ip| ip.as_slice()),
        &server_port.to_le_bytes(),
        &[1u8; 32],
        client_v6.as_ref(),
        server_v6.as_ref(),
    );
    let mut encrypted = [0u8; 48];
    stream.read_exact(&mut encrypted).await.unwrap();
    cbc_decrypt_inplace(&read_key, &read_iv, &mut encrypted).unwrap();
    assert_eq!(u32::from_le_bytes(encrypted[..4].try_into().unwrap()), 44);
    assert_eq!(i32::from_le_bytes(encrypted[4..8].try_into().unwrap()), -1);
    assert_eq!(
        u32::from_le_bytes(encrypted[40..44].try_into().unwrap()),
        rpc_crc(RpcChecksumMode::Crc32, &encrypted[..40])
    );
    parse_handshake_flags(&encrypted[8..40]).unwrap();
    assert_eq!(&encrypted[16..20], &client_ip);
    assert_eq!(
        u16::from_le_bytes(encrypted[20..22].try_into().unwrap()),
        client_port
    );
    assert_eq!(
        u16::from_le_bytes(encrypted[32..34].try_into().unwrap()),
        server_port
    );
    let reply = build_handshake_payload(server_ip, server_port, client_ip, client_port, 0);
    let (encrypted, _) = cbc_encrypt_padded(
        &write_key,
        &write_iv,
        &build_rpc_frame(-1, &reply, RpcChecksumMode::Crc32),
    )
    .unwrap();
    stream.write_all(&encrypted).await.unwrap();
    Some(stream)
}

async fn suppressed_pool_recovers_after_delayed_discovery(http_slow: bool) {
    // Every lookup exceeds me_one_timeout_ms, not just the first request of the outage.
    let delay = Duration::from_millis(1500);
    let stun = stun_server_response(
        "127.0.0.1:0".parse().unwrap(),
        Some(PUBLIC_IP.into()),
        delay,
    )
    .await;
    let http = http_server_with_delay("91.108.56.1", delay).await;
    stun.release.add_permits(64);
    http.release.add_permits(64);
    // A valid STUN source bypasses HTTP; the peer remains the configured loopback endpoint.
    let peer = MiddlePeer::new(Ipv4Addr::LOCALHOST).await;
    let urls = if http_slow {
        vec![format!("http://{}/", http.addr)]
    } else {
        vec![]
    };
    let pool = nat_pool(vec![stun.addr.to_string()], urls).await;
    pool.health_runtime
        .me_health_interval_ms_unhealthy
        .store(10, Ordering::Relaxed);
    pool.health_runtime
        .me_health_interval_ms_healthy
        .store(10, Ordering::Relaxed);
    pool.single_endpoint_runtime
        .me_single_endpoint_outage_backoff_min_ms
        .store(100, Ordering::Relaxed);
    pool.single_endpoint_runtime
        .me_single_endpoint_outage_backoff_max_ms
        .store(100, Ordering::Relaxed);
    pool.single_endpoint_runtime
        .me_single_endpoint_shadow_writers
        .store(0, Ordering::Relaxed);
    pool.single_endpoint_runtime
        .me_single_endpoint_shadow_rotate_every_secs
        .store(0, Ordering::Relaxed);
    pool.update_proxy_maps(
        HashMap::from([(2, vec![(peer.addr.ip(), peer.addr.port())])]),
        None,
    )
    .await;
    let generation = pool.current_generation();
    let now = MePool::now_epoch_secs();
    pool.set_family_runtime_state(
        IpFamily::V4,
        MeFamilyRuntimeState::Suppressed,
        now,
        now + 3600,
        5,
        0,
    );
    pool.nat_runtime.nat_reflection_cache.lock().await.v4 = Some((
        if http_slow {
            Instant::now()
        } else {
            Instant::now() - Duration::from_secs(601)
        },
        SocketAddr::new(PUBLIC_IP.into(), 45678),
    ));
    let monitor = tokio::spawn(me_health_monitor(
        pool.clone(),
        Arc::new(SecureRandom::new()),
        0,
    ));
    if !http_slow {
        stun.received().await;
        timeout(Duration::from_secs(5), async {
            while peer.cancelled.load(Ordering::Acquire) == 0 {
                assert!(!peer.task.is_finished());
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the actual 1200ms reconnect must cancel a pre-KDF TCP connection");
        assert_eq!(peer.handshakes.load(Ordering::Acquire), 0);
    }
    let expected = 2 * pool.required_writers_for_dc(1);
    timeout(Duration::from_secs(10), async {
        while !pool.admission_ready_full_floor().await
            || peer.handshakes.load(Ordering::Acquire) < expected
        {
            assert!(
                !peer.task.is_finished(),
                "fake ME must validate every encrypted handshake"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("suppressed pool must autonomously regain its full floor without restart");
    monitor.abort();
    let _ = monitor.await;
    assert_eq!(pool.current_generation(), generation);
    assert_eq!(pool.reinit.status.load().pending_hardswap_generation, 0);
    assert_eq!(
        pool.writer_connect_active_reserved.load(Ordering::Acquire),
        0
    );
    assert_eq!(pool.writers.read().await.len(), expected);
    assert!(peer.handshakes.load(Ordering::Acquire) >= expected);
    assert_eq!(http.requests.load(Ordering::Relaxed), 0);
    assert_eq!(
        stun.requests.load(Ordering::Relaxed),
        usize::from(!http_slow)
    );
    assert!(pool.shutdown_until(TEST_DEADLINE).await);
}

#[tokio::test]
async fn suppressed_pool_recovers_full_floor_after_expired_stun_refresh() {
    suppressed_pool_recovers_after_delayed_discovery(false).await;
}

#[tokio::test]
async fn suppressed_pool_recovers_full_floor_after_slow_http_with_fresh_stun() {
    suppressed_pool_recovers_after_delayed_discovery(true).await;
}

#[tokio::test]
async fn stalled_ipv4_does_not_delay_real_ipv6_handshakes() {
    let stalled = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let stalled_addr = stalled.local_addr().unwrap();
    let healthy =
        MiddlePeer::with_bind("[::1]:0", "::1".parse().unwrap(), "::1".parse().unwrap()).await;
    let mut pool = make_pool_with_decision(NetworkDecision {
        ipv4_me: true,
        ipv6_me: true,
        ..NetworkDecision::default()
    })
    .await;
    Arc::get_mut(&mut Arc::get_mut(&mut pool).unwrap().reconnect_runtime)
        .unwrap()
        .me_one_timeout = Duration::from_secs(5);
    pool.health_runtime
        .me_health_interval_ms_unhealthy
        .store(10, Ordering::Relaxed);
    pool.single_endpoint_runtime
        .me_single_endpoint_shadow_rotate_every_secs
        .store(0, Ordering::Relaxed);
    pool.update_proxy_maps(
        HashMap::from([(2, vec![(stalled_addr.ip(), stalled_addr.port())])]),
        Some(HashMap::from([(
            2,
            vec![(healthy.addr.ip(), healthy.addr.port())],
        )])),
    )
    .await;
    let monitor = tokio::spawn(me_health_monitor(pool.clone(), pool.rng.clone(), 0));
    let (blocked_stream, _) = timeout(TEST_DEADLINE, stalled.accept())
        .await
        .unwrap()
        .unwrap();
    timeout(TEST_DEADLINE, async {
        while healthy.handshakes.load(Ordering::Acquire) < pool.required_writers_for_dc(1) {
            assert!(!healthy.task.is_finished());
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("IPv6 must restore coverage while IPv4 still owns a stalled handshake");
    monitor.abort();
    let _ = monitor.await;
    assert!(
        pool.shutdown_until(TEST_DEADLINE).await,
        "tracked child transports must join on shutdown"
    );
    drop(blocked_stream);
    assert_eq!(
        pool.writer_connect_active_reserved.load(Ordering::Acquire),
        0
    );
}
