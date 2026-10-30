use super::*;
use tokio::io::duplex;
use tokio::net::TcpListener;
use tokio::time::{Duration, Instant, timeout};

#[test]
fn masking_baseline_timing_normalization_budget_within_bounds() {
    let mut config = ProxyConfig::default();
    config.censorship.mask_timing_normalization_enabled = true;
    config.censorship.mask_timing_normalization_floor_ms = 120;
    config.censorship.mask_timing_normalization_ceiling_ms = 180;

    for _ in 0..256 {
        let budget = mask_outcome_target_budget(&config);
        assert!(budget >= Duration::from_millis(120));
        assert!(budget <= Duration::from_millis(180));
    }
}

#[tokio::test]
async fn masking_baseline_fallback_relays_to_mask_host() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();
    let initial = b"GET /baseline HTTP/1.1\r\nHost: x\r\n\r\n".to_vec();
    let reply = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK".to_vec();

    let accept_task = tokio::spawn({
        let initial = initial.clone();
        let reply = reply.clone();
        async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut seen = vec![0u8; initial.len()];
            stream.read_exact(&mut seen).await.unwrap();
            assert_eq!(seen, initial);
            stream.write_all(&reply).await.unwrap();
        }
    });

    let mut config = ProxyConfig::default();
    config.general.beobachten = false;
    config.censorship.mask = true;
    config.censorship.mask_host = Some("127.0.0.1".to_string());
    config.censorship.mask_port = backend_addr.port();
    config.censorship.mask_unix_sock = None;
    config.censorship.mask_proxy_protocol = 0;

    let peer: SocketAddr = "203.0.113.70:55070".parse().unwrap();
    let local_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();

    let (client_reader, _client_writer) = duplex(1024);
    let (mut visible_reader, visible_writer) = duplex(2048);
    let beobachten = BeobachtenStore::new();

    handle_bad_client(
        client_reader,
        visible_writer,
        &initial,
        peer,
        local_addr,
        &config,
        &beobachten,
    )
    .await;

    let mut observed = vec![0u8; reply.len()];
    visible_reader.read_exact(&mut observed).await.unwrap();
    assert_eq!(observed, reply);
    accept_task.await.unwrap();
}

#[test]
fn masking_baseline_no_normalization_returns_default_budget() {
    let mut config = ProxyConfig::default();
    config.censorship.mask_timing_normalization_enabled = false;
    let budget = mask_outcome_target_budget(&config);
    assert_eq!(budget, MASK_TIMEOUT);
}

#[tokio::test]
async fn masking_baseline_unreachable_mask_host_silent_failure() {
    let mut config = ProxyConfig::default();
    config.general.beobachten = false;
    config.censorship.mask = true;
    config.censorship.mask_unix_sock = None;
    config.censorship.mask_host = Some("127.0.0.1".to_string());
    config.censorship.mask_port = 1;
    config.censorship.mask_timing_normalization_enabled = false;

    let peer: SocketAddr = "203.0.113.71:55071".parse().unwrap();
    let local_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let beobachten = BeobachtenStore::new();

    let (client_reader, _client_writer) = duplex(1024);
    let (mut visible_reader, visible_writer) = duplex(1024);

    let started = Instant::now();
    handle_bad_client(
        client_reader,
        visible_writer,
        b"GET / HTTP/1.1\r\n\r\n",
        peer,
        local_addr,
        &config,
        &beobachten,
    )
    .await;
    let elapsed = started.elapsed();

    assert!(elapsed < Duration::from_secs(1));

    let mut buf = [0u8; 1];
    let read_res = timeout(Duration::from_millis(50), visible_reader.read(&mut buf)).await;
    match read_res {
        Ok(Ok(0)) | Err(_) => {}
        Ok(Ok(n)) => panic!("expected no response bytes, got {n}"),
        Ok(Err(e)) => panic!("unexpected client-side read error: {e}"),
    }
}

#[tokio::test]
async fn masking_baseline_light_fuzz_initial_data_no_panic() {
    let mut config = ProxyConfig::default();
    config.general.beobachten = false;
    config.censorship.mask = false;

    let peer: SocketAddr = "203.0.113.72:55072".parse().unwrap();
    let local_addr: SocketAddr = "127.0.0.1:443".parse().unwrap();
    let beobachten = BeobachtenStore::new();

    let corpus: Vec<Vec<u8>> = vec![
        vec![],
        vec![0x00],
        vec![0xFF; 1024],
        (0..255u8).collect(),
        b"\xF0\x28\x8C\x28".to_vec(),
    ];

    for sample in corpus {
        let (client_reader, _client_writer) = duplex(1024);
        let (_visible_reader, visible_writer) = duplex(1024);
        timeout(
            Duration::from_millis(300),
            handle_bad_client(
                client_reader,
                visible_writer,
                &sample,
                peer,
                local_addr,
                &config,
                &beobachten,
            ),
        )
        .await
        .expect("fuzz sample must complete in bounded time");
    }
}
