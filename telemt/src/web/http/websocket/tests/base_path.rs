use super::*;

async fn rejected_upgrade(
    listener: &TcpListener,
    runtime: &Arc<WebProcessRuntime>,
    path: &str,
    protocol: &str,
) -> Vec<u8> {
    let address = listener.local_addr().unwrap();
    let (accepted, client) = tokio::join!(listener.accept(), TcpStream::connect(address));
    let (server, peer) = accepted.unwrap();
    let mut client = client.unwrap();
    let permit = runtime.try_http_connection().unwrap();
    let task = tokio::spawn(super::super::super::serve_connection(
        server,
        peer,
        WebClientIpSource::XForwardedFor,
        Arc::from(["127.0.0.1/32".parse().unwrap()]),
        Arc::clone(runtime),
        CancellationToken::new(),
        permit,
    ));
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nConnection: close, Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: {protocol}\r\n\r\n"
    );
    client.write_all(request.as_bytes()).await.unwrap();
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    task.await.unwrap();
    response
}

fn assert_private_not_found(response: &[u8]) {
    let (headers, body) = crate::web::http::tests::split_response(response);
    assert!(headers.starts_with(b"HTTP/1.1 404"));
    assert_eq!(
        crate::web::http::tests::response_header(headers, "cache-control"),
        "no-store"
    );
    assert_eq!(body, b"not found\n");
}

#[tokio::test]
async fn authentic_websocket_protocol_rejects_every_base_path_alias_locally() {
    let config = runtime_config_with_base([32; 32], WebCarrier::Websocket, "/relay/");
    let generation = test_runtime_generation(1, config);
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (session, _) = create_session(&runtime);
    let protocol = format!("tproxy-v1.{session}");

    for path in [
        "/api/v1/ws",
        "/Relay/api/v1/ws",
        "/relayx/api/v1/ws",
        "/relay//api/v1/ws",
        "/relay%2Fapi/v1/ws",
        "/relay/api%2Fv1/ws",
        "/relay/api/v1/ws/",
    ] {
        assert_private_not_found(&rejected_upgrade(&listener, &runtime, path, &protocol).await);
    }

    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}

#[tokio::test]
async fn upgraded_socket_survives_base_path_generation_swap() {
    let old_generation = test_runtime_generation(
        1,
        runtime_config_with_base([33; 32], WebCarrier::Websocket, "/old/"),
    );
    let active = Arc::new(ArcSwap::from(Arc::clone(&old_generation)));
    let runtime = WebProcessRuntime::start(Arc::clone(&active));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (session, _) = create_session(&runtime);
    let protocol = format!("tproxy-v1.{session}");
    let mut socket = upgrade_at(&listener, &runtime, "/old/api/v1/ws", &protocol).await;

    let new_generation = test_runtime_generation(
        2,
        runtime_config_with_base([34; 32], WebCarrier::Websocket, "/new/"),
    );
    active.store(Arc::clone(&new_generation));
    socket
        .send(Message::Ping(Bytes::from_static(b"after-reload")))
        .await
        .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(2), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(response, Message::Pong(Bytes::from_static(b"after-reload")));
    assert_private_not_found(
        &rejected_upgrade(&listener, &runtime, "/old/api/v1/ws", &protocol).await,
    );

    let _ = socket.close(None).await;
    runtime.shutdown().await;
    old_generation.stop_sessions().await;
    old_generation.stop_background_tasks().await;
    new_generation.stop_sessions().await;
    new_generation.stop_background_tasks().await;
}
