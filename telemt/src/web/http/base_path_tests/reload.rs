use super::*;

async fn issue_bootstrap(
    listener: &TcpListener,
    runtime: &Arc<WebProcessRuntime>,
    base: &str,
    capability: [u8; 32],
) -> String {
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(capability);
    let response = request(
        listener,
        runtime,
        bridge_request(&format!("{base}?bridge={encoded}")),
    )
    .await;
    let (headers, body) = split_response(&response);
    assert!(headers.starts_with(b"HTTP/1.1 200"));
    bridge_token(body)
}

async fn create_session(
    listener: &TcpListener,
    runtime: &Arc<WebProcessRuntime>,
    base: &str,
    bootstrap: &str,
) -> String {
    let hello = frame::encode(FrameType::Hello, 0, &[1]);
    let mut request_bytes = format!(
        "POST {base}api/v1/session HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {bootstrap}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        hello.len()
    )
    .into_bytes();
    request_bytes.extend_from_slice(&hello);
    let response = request(listener, runtime, request_bytes).await;
    let (headers, _) = split_response(&response);
    assert!(headers.starts_with(b"HTTP/1.1 200"));
    response_header(headers, "x-session-token").to_string()
}

fn session_request(base: &str, session: &str) -> Vec<u8> {
    format!(
        "POST {base}api/v1/down HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {session}\r\nX-Down-Cursor: 0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

fn assert_private_not_found(response: &[u8]) {
    let (headers, body) = split_response(response);
    assert!(headers.starts_with(b"HTTP/1.1 404"));
    assert_eq!(response_header(headers, "cache-control"), "no-store");
    assert_eq!(body, b"not found\n");
}

fn assert_decoy(response: &[u8]) {
    assert_eq!(
        split_response(response).1,
        b"<!doctype html><title>decoy</title>"
    );
}

#[tokio::test]
async fn generation_swap_preserves_process_tokens_and_replaces_route_identity() {
    let old_capability = [101u8; 32];
    let mut old_config = runtime_config_with_base(old_capability, WebCarrier::Https, "/old/");
    old_config.web.limits.max_bootstraps_per_ip = 8;
    old_config.web.timeouts.long_poll_secs = 1;
    let old_generation = test_runtime_generation(1, old_config);
    let active = Arc::new(ArcSwap::from(Arc::clone(&old_generation)));
    let runtime = WebProcessRuntime::start(Arc::clone(&active));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let unused_bootstrap = issue_bootstrap(&listener, &runtime, "/old/", old_capability).await;
    let used_bootstrap = issue_bootstrap(&listener, &runtime, "/old/", old_capability).await;
    let session = create_session(&listener, &runtime, "/old/", &used_bootstrap).await;

    let new_capability = [102u8; 32];
    let mut new_config = runtime_config_with_base(new_capability, WebCarrier::Https, "/new/");
    new_config.web.limits.max_bootstraps_per_ip = 8;
    new_config.web.timeouts.long_poll_secs = 1;
    let new_generation = test_runtime_generation(2, new_config);
    active.store(Arc::clone(&new_generation));
    let old_encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(old_capability);
    let new_encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(new_capability);

    assert_decoy(
        &request(
            &listener,
            &runtime,
            bridge_request(&format!("/old/?bridge={old_encoded}")),
        )
        .await,
    );
    assert_private_not_found(
        &request(
            &listener,
            &runtime,
            bridge_request(&format!("/old/?bridge={new_encoded}")),
        )
        .await,
    );
    assert_decoy(
        &request(
            &listener,
            &runtime,
            bridge_request(&format!("/new/?bridge={old_encoded}")),
        )
        .await,
    );

    let old_bootstrap_path = format!(
        "GET /old/wrong HTTP/1.1\r\nHost: proxy.example.com\r\nAuthorization: Bearer {unused_bootstrap}\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    assert_private_not_found(&request(&listener, &runtime, old_bootstrap_path).await);
    assert_private_not_found(
        &request(&listener, &runtime, session_request("/old/", &session)).await,
    );
    assert!(
        request(&listener, &runtime, session_request("/new/", &session),)
            .await
            .starts_with(b"HTTP/1.1 204")
    );

    let hello = frame::encode(FrameType::Hello, 0, &[1]);
    let mut stale_bootstrap_request = format!(
        "POST /new/api/v1/session HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {unused_bootstrap}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        hello.len()
    )
    .into_bytes();
    stale_bootstrap_request.extend_from_slice(&hello);
    assert_private_not_found(&request(&listener, &runtime, stale_bootstrap_request).await);

    let current = request(
        &listener,
        &runtime,
        bridge_request(&format!("/new/?bridge={new_encoded}")),
    )
    .await;
    let (headers, body) = split_response(&current);
    assert!(headers.starts_with(b"HTTP/1.1 200"));
    let new_bootstrap = bridge_token(body);
    create_session(&listener, &runtime, "/new/", &new_bootstrap).await;

    runtime.shutdown().await;
    old_generation.stop_sessions().await;
    old_generation.stop_background_tasks().await;
    new_generation.stop_sessions().await;
    new_generation.stop_background_tasks().await;
}

#[tokio::test]
async fn routed_uplink_finishes_under_its_acquisition_generation() {
    let capability = [103u8; 32];
    let mut old_config = runtime_config_with_base(capability, WebCarrier::Https, "/old/");
    old_config.web.timeouts.long_poll_secs = 1;
    let old_generation = test_runtime_generation(1, old_config);
    let active = Arc::new(ArcSwap::from(Arc::clone(&old_generation)));
    let runtime = WebProcessRuntime::start(Arc::clone(&active));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bootstrap = issue_bootstrap(&listener, &runtime, "/old/", capability).await;
    let session = create_session(&listener, &runtime, "/old/", &bootstrap).await;

    let address = listener.local_addr().unwrap();
    let (accepted, client) = tokio::join!(listener.accept(), TcpStream::connect(address));
    let (server, peer) = accepted.unwrap();
    let mut client = client.unwrap();
    let permit = runtime.try_http_connection().unwrap();
    let task = tokio::spawn(serve_connection(
        server,
        peer,
        WebClientIpSource::XForwardedFor,
        Arc::from(["127.0.0.1/32".parse().unwrap()]),
        Arc::clone(&runtime),
        CancellationToken::new(),
        permit,
    ));
    let pong = frame::encode(FrameType::Pong, 0, &[]);
    let head = format!(
        "POST /old/api/v1/up HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {session}\r\nContent-Type: application/octet-stream\r\nX-Up-Seq: 1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        pong.len()
    );
    client.write_all(head.as_bytes()).await.unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let body_readers = runtime
                .capacity_snapshot()
                .resources
                .into_iter()
                .find(|resource| resource.resource == "body_readers")
                .unwrap();
            if body_readers.used == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("uplink never entered body collection");

    let mut new_config = runtime_config_with_base([104u8; 32], WebCarrier::Https, "/new/");
    new_config.web.timeouts.long_poll_secs = 1;
    let new_generation = test_runtime_generation(2, new_config);
    active.store(Arc::clone(&new_generation));
    client.write_all(&pong).await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    task.await.unwrap();
    assert!(response.starts_with(b"HTTP/1.1 204"));

    assert_private_not_found(
        &request(&listener, &runtime, session_request("/old/", &session)).await,
    );
    assert!(
        request(&listener, &runtime, session_request("/new/", &session),)
            .await
            .starts_with(b"HTTP/1.1 204")
    );

    runtime.shutdown().await;
    old_generation.stop_sessions().await;
    old_generation.stop_background_tasks().await;
    new_generation.stop_sessions().await;
    new_generation.stop_background_tasks().await;
}

#[tokio::test]
async fn generation_transition_burst_never_authenticates_a_torn_route_identity() {
    let old_capability = [105u8; 32];
    let new_capability = [106u8; 32];
    let old_generation = test_runtime_generation(
        1,
        runtime_config_with_base(old_capability, WebCarrier::Https, "/old/"),
    );
    let new_generation = test_runtime_generation(
        2,
        runtime_config_with_base(new_capability, WebCarrier::Https, "/new/"),
    );
    let active = Arc::new(ArcSwap::from(Arc::clone(&old_generation)));
    let runtime = WebProcessRuntime::start(Arc::clone(&active));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let barrier = Arc::new(tokio::sync::Barrier::new(2));
    let swap_barrier = Arc::clone(&barrier);
    let swap_active = Arc::clone(&active);
    let swap_old = Arc::clone(&old_generation);
    let swap_new = Arc::clone(&new_generation);
    let swaps = tokio::spawn(async move {
        swap_barrier.wait().await;
        for index in 0..10_000 {
            if index % 2 == 0 {
                swap_active.store(Arc::clone(&swap_new));
            } else {
                swap_active.store(Arc::clone(&swap_old));
            }
            if index % 8 == 0 {
                tokio::task::yield_now().await;
            }
        }
    });
    barrier.wait().await;
    let old_encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(old_capability);
    let new_encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(new_capability);

    for index in 0..256 {
        let target = if index % 2 == 0 {
            format!("/old/?bridge={new_encoded}")
        } else {
            format!("/new/?bridge={old_encoded}")
        };
        let response = request(&listener, &runtime, bridge_request(&target)).await;
        assert!(!response.starts_with(b"HTTP/1.1 200"));
        assert!(
            !std::str::from_utf8(split_response(&response).1)
                .unwrap()
                .contains("bootstrap=\"")
        );
    }
    swaps.await.unwrap();

    runtime.shutdown().await;
    old_generation.stop_sessions().await;
    old_generation.stop_background_tasks().await;
    new_generation.stop_sessions().await;
    new_generation.stop_background_tasks().await;
}
