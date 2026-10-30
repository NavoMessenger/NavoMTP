use super::*;

use sha2::{Digest, Sha256};

use crate::web::manager::CarrierFailure;
use crate::web::telemetry::WebCarrierFailurePhase;

fn issue_bootstrap(runtime: &Arc<WebProcessRuntime>, client_ip: &str) -> String {
    let profile = runtime
        .active_generation()
        .config()
        .web
        .runtime
        .as_ref()
        .unwrap()
        .profiles[0]
        .clone();
    runtime
        .issue_bootstrap(profile, client_ip.parse().unwrap())
        .unwrap()
        .token
}

fn token_hash(token: &str) -> crate::web::manager::TokenHash {
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token)
        .unwrap();
    Sha256::digest(raw).into()
}

async fn create_automatic_session(
    listener: &TcpListener,
    runtime: &Arc<WebProcessRuntime>,
) -> String {
    let bootstrap = issue_bootstrap(runtime, "192.0.2.10");
    let hello = frame::encode(FrameType::Hello, 0, &[1]);
    let mut create = format!(
        "POST /api/v1/session HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {bootstrap}\r\nContent-Type: application/octet-stream\r\nX-Carrier-Capabilities: https\r\nX-Carrier-Attempt: 1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        hello.len()
    )
    .into_bytes();
    create.extend_from_slice(&hello);
    let response = request(listener, runtime, create).await;
    let (headers, _) = split_response(&response);
    assert!(headers.starts_with(b"HTTP/1.1 200"));
    response_header(headers, "x-session-token").to_string()
}

fn delete_request(token: &str, failure_headers: &str) -> Vec<u8> {
    format!(
        "DELETE /api/v1/session HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {token}\r\n{failure_headers}Content-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .into_bytes()
}

fn diagnostic_runtime(capability: [u8; 32]) -> ProxyConfig {
    negotiation_runtime_config(
        capability,
        WebCarrier::Https,
        false,
        Arc::from([WebCarrier::Https]),
    )
}

#[tokio::test]
async fn delete_failure_is_strict_and_counted_only_for_the_winning_close() {
    let generation = test_runtime_generation(1, diagnostic_runtime([61; 32]));
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let token = create_automatic_session(&listener, &runtime).await;
    let hash = token_hash(&token);

    let malformed = request(
        &listener,
        &runtime,
        delete_request(&token, "X-Carrier-Failure: invalid\r\n"),
    )
    .await;
    assert!(!malformed.starts_with(b"HTTP/1.1 204"));
    assert!(runtime.get_session(hash, "proxy.example.com").is_ok());

    let close = delete_request(&token, "X-Carrier-Failure: network\r\n");
    let response = request(&listener, &runtime, close.clone()).await;
    assert!(response.starts_with(b"HTTP/1.1 204"));
    let retry = request(&listener, &runtime, close).await;
    assert!(retry.starts_with(b"HTTP/1.1 204"));
    assert_eq!(
        runtime.telemetry().carrier_failure_total(
            WebCarrier::Https,
            WebCarrierFailurePhase::Provisional,
            CarrierFailure::Network,
        ),
        1
    );

    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}

#[tokio::test]
async fn delete_failure_uses_the_committed_phase_after_real_uplink_progress() {
    let generation = test_runtime_generation(1, diagnostic_runtime([62; 32]));
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let token = create_automatic_session(&listener, &runtime).await;
    let hash = token_hash(&token);
    let open = frame::encode(FrameType::Open, 7, &[]);
    let data = frame::encode(FrameType::Data, 7, &[1]);
    let mut body = Vec::with_capacity(open.len() + data.len());
    body.extend_from_slice(&open);
    body.extend_from_slice(&data);
    let mut uplink = format!(
        "POST /api/v1/up HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {token}\r\nContent-Type: application/octet-stream\r\nX-Up-Seq: 1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    uplink.extend_from_slice(&body);

    let accepted = request(&listener, &runtime, uplink).await;
    assert!(accepted.starts_with(b"HTTP/1.1 204"));
    assert!(
        runtime
            .get_session(hash, "proxy.example.com")
            .unwrap()
            .is_carrier_committed()
    );
    let response = request(
        &listener,
        &runtime,
        delete_request(&token, "X-Carrier-Failure: protocol\r\n"),
    )
    .await;

    assert!(response.starts_with(b"HTTP/1.1 204"));
    assert_eq!(
        runtime.telemetry().carrier_failure_total(
            WebCarrier::Https,
            WebCarrierFailurePhase::Committed,
            CarrierFailure::Protocol,
        ),
        1
    );

    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}
