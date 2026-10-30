use super::*;
use sha2::{Digest, Sha256};

use crate::web::session::{SessionCloseOutcome, SessionCloseReason};
use crate::web::telemetry::{WebBridgeRecoveryEvent, WebSessionLifecycleObservation};

const RECOVERY_TYPE: &str = "application/vnd.telemt.web-recovery+json";

async fn bridge_bootstrap(
    listener: &TcpListener,
    runtime: &Arc<WebProcessRuntime>,
    encoded_capability: &str,
) -> String {
    let root = format!(
        "GET /?bridge={encoded_capability} HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.40\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    let response = request(listener, runtime, root).await;
    let (_, body) = split_response(&response);
    std::str::from_utf8(body)
        .unwrap()
        .split_once("bootstrap=\"")
        .and_then(|(_, suffix)| suffix.split_once('"'))
        .map(|(token, _)| token.to_string())
        .unwrap()
}

async fn create_session(
    listener: &TcpListener,
    runtime: &Arc<WebProcessRuntime>,
    bootstrap: &str,
) -> Vec<u8> {
    let hello = frame::encode(FrameType::Hello, 0, &[1]);
    let mut create = format!(
        "POST /api/v1/session HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.40\r\nAuthorization: Bearer {bootstrap}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        hello.len()
    )
    .into_bytes();
    create.extend_from_slice(&hello);
    request(listener, runtime, create).await
}

async fn send_open(
    listener: &TcpListener,
    runtime: &Arc<WebProcessRuntime>,
    bearer: &str,
) -> Vec<u8> {
    let open = frame::encode(FrameType::Open, 1, &[]);
    let mut request_bytes = format!(
        "POST /api/v1/up HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.40\r\nAuthorization: Bearer {bearer}\r\nContent-Type: application/octet-stream\r\nX-Up-Seq: 1\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        open.len()
    )
    .into_bytes();
    request_bytes.extend_from_slice(&open);
    request(listener, runtime, request_bytes).await
}

async fn recover(
    listener: &TcpListener,
    runtime: &Arc<WebProcessRuntime>,
    encoded_capability: &str,
    authorization: &str,
) -> Vec<u8> {
    request(
        listener,
        runtime,
        format!(
            "GET /?bridge={encoded_capability} HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.40\r\nAccept: {RECOVERY_TYPE}\r\nAuthorization: {authorization}\r\nConnection: close\r\n\r\n"
        )
        .into_bytes(),
    )
    .await
}

#[tokio::test]
async fn recovery_retires_current_bearer_before_single_slot_recreation() {
    let capability = [40u8; 32];
    let mut config = runtime_config(capability, WebCarrier::Https);
    config.web.limits.max_sessions_global = 1;
    config.web.limits.max_sessions_per_ip = 1;
    let generation = test_runtime_generation(1, config);
    let active_runtime = Arc::new(ArcSwap::from(Arc::clone(&generation)));
    let runtime = WebProcessRuntime::start(active_runtime);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(capability);
    let bootstrap = bridge_bootstrap(&listener, &runtime, &encoded).await;
    let create_response = create_session(&listener, &runtime, &bootstrap).await;
    let (create_headers, _) = split_response(&create_response);
    assert!(create_headers.starts_with(b"HTTP/1.1 200"));
    let old_session = response_header(create_headers, "x-session-token").to_string();

    let recovery_response = recover(
        &listener,
        &runtime,
        &encoded,
        &format!("Bearer {old_session}"),
    )
    .await;
    let (recovery_headers, recovery_body) = split_response(&recovery_response);
    assert!(recovery_headers.starts_with(b"HTTP/1.1 200"));
    assert_eq!(
        response_header(recovery_headers, "content-type"),
        RECOVERY_TYPE
    );
    assert_eq!(
        response_header(recovery_headers, "cache-control"),
        "no-store"
    );
    assert!(recovery_body.len() <= 1024);
    let document: serde_json::Value = serde_json::from_slice(recovery_body).unwrap();
    assert_eq!(document["v"], 1);
    assert_eq!(document["timeouts"]["bridge_recovery_secs"], 15);
    let recovery_bootstrap = document["bootstrap"].as_str().unwrap();

    let recreated = create_session(&listener, &runtime, recovery_bootstrap).await;
    assert!(recreated.starts_with(b"HTTP/1.1 200"));
    assert_eq!(
        runtime
            .telemetry()
            .session_close_total(WebCarrier::Https, SessionCloseReason::BridgeRecovery,),
        1
    );
    assert_eq!(
        runtime
            .telemetry()
            .bridge_recovery_total(WebBridgeRecoveryEvent::BootstrapIssued),
        1
    );
    assert_eq!(
        runtime
            .telemetry()
            .bridge_recovery_total(WebBridgeRecoveryEvent::SessionCreated),
        1
    );

    let late = format!(
        "POST /api/v1/down HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.40\r\nAuthorization: Bearer {old_session}\r\nX-Down-Cursor: 0\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    let late_response = request(&listener, &runtime, late).await;
    assert!(late_response.starts_with(b"HTTP/1.1 404"));
    assert_eq!(
        runtime.telemetry().session_observation_total(
            WebCarrier::Https,
            WebSessionLifecycleObservation::RequestAfterClose,
        ),
        1
    );

    let retired_recovery = recover(
        &listener,
        &runtime,
        &encoded,
        &format!("Bearer {old_session}"),
    )
    .await;
    let (retired_headers, retired_body) = split_response(&retired_recovery);
    assert!(retired_headers.starts_with(b"HTTP/1.1 200"));
    assert_eq!(
        response_header(retired_headers, "content-type"),
        RECOVERY_TYPE
    );
    assert!(serde_json::from_slice::<serde_json::Value>(retired_body).is_ok());
    assert_eq!(
        runtime
            .list_sessions(SessionListRequest {
                limit: 10,
                cursor: None,
                filter: SessionFilter::default(),
            })
            .sessions
            .len(),
        1
    );

    runtime.shutdown().await;
    assert_eq!(
        runtime
            .telemetry()
            .bridge_recovery_total(WebBridgeRecoveryEvent::ClosedBeforeCommit),
        1
    );
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}

#[tokio::test]
async fn malformed_or_over_capacity_recovery_is_indistinguishable_from_decoy() {
    let capability = [41u8; 32];
    let generation = test_runtime_generation(1, runtime_config(capability, WebCarrier::Https));
    let active_runtime = Arc::new(ArcSwap::from(Arc::clone(&generation)));
    let runtime = WebProcessRuntime::start(active_runtime);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(capability);

    let malformed = recover(&listener, &runtime, &encoded, "Bearer malformed").await;
    let (malformed_headers, malformed_body) = split_response(&malformed);
    assert!(malformed_headers.starts_with(b"HTTP/1.1 404"));
    assert_eq!(
        response_header(malformed_headers, "cache-control"),
        "no-store"
    );
    assert_eq!(malformed_body, b"not found\n");

    let invalid_capability = recover(
        &listener,
        &runtime,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([99u8; 32]),
        &format!("Bearer {}", "U".repeat(43)),
    )
    .await;
    let (invalid_headers, invalid_body) = split_response(&invalid_capability);
    assert!(invalid_headers.starts_with(b"HTTP/1.1 200"));
    assert_eq!(
        response_header(invalid_headers, "cache-control"),
        "no-store"
    );
    assert_eq!(invalid_body, b"<!doctype html><title>decoy</title>");

    let malformed_accept = request(
        &listener,
        &runtime,
        format!(
            "GET /?bridge={encoded} HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.40\r\nAccept: {RECOVERY_TYPE}, */*\r\nConnection: close\r\n\r\n"
        )
        .into_bytes(),
    )
    .await;
    assert_eq!(malformed_accept, malformed);

    let _held = bridge_bootstrap(&listener, &runtime, &encoded).await;
    let over_capacity = recover(
        &listener,
        &runtime,
        &encoded,
        &format!("Bearer {}", "U".repeat(43)),
    )
    .await;
    let (capacity_headers, capacity_body) = split_response(&over_capacity);
    assert!(capacity_headers.starts_with(b"HTTP/1.1 404"));
    assert_eq!(
        response_header(capacity_headers, "cache-control"),
        "no-store"
    );
    assert_eq!(capacity_body, b"not found\n");

    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}

#[tokio::test]
async fn fixed_carrier_recovery_commits_on_real_uplink_progress() {
    let capability = [43u8; 32];
    let generation = test_runtime_generation(1, runtime_config(capability, WebCarrier::Https));
    let active_runtime = Arc::new(ArcSwap::from(Arc::clone(&generation)));
    let runtime = WebProcessRuntime::start(active_runtime);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(capability);
    let bootstrap = bridge_bootstrap(&listener, &runtime, &encoded).await;
    let created = create_session(&listener, &runtime, &bootstrap).await;
    let (created_headers, _) = split_response(&created);
    let old_bearer = response_header(created_headers, "x-session-token");
    let recovered = recover(
        &listener,
        &runtime,
        &encoded,
        &format!("Bearer {old_bearer}"),
    )
    .await;
    let (_, recovery_body) = split_response(&recovered);
    let document: serde_json::Value = serde_json::from_slice(recovery_body).unwrap();
    let recovery_bootstrap = document["bootstrap"].as_str().unwrap();
    let recreated = create_session(&listener, &runtime, recovery_bootstrap).await;
    let (recreated_headers, _) = split_response(&recreated);
    let bearer = response_header(recreated_headers, "x-session-token");

    let uplink = send_open(&listener, &runtime, bearer).await;

    assert!(uplink.starts_with(b"HTTP/1.1 204"));
    assert_eq!(
        runtime
            .telemetry()
            .bridge_recovery_total(WebBridgeRecoveryEvent::Committed),
        1
    );
    runtime.shutdown().await;
    assert_eq!(
        runtime
            .telemetry()
            .bridge_recovery_total(WebBridgeRecoveryEvent::ClosedBeforeCommit),
        0
    );
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}

#[tokio::test]
async fn deferred_close_preserves_the_first_reason_across_replacement_cancel() {
    let capability = [42u8; 32];
    let generation = test_runtime_generation(1, runtime_config(capability, WebCarrier::Https));
    let active_runtime = Arc::new(ArcSwap::from(Arc::clone(&generation)));
    let runtime = WebProcessRuntime::start(active_runtime);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(capability);
    let bootstrap = bridge_bootstrap(&listener, &runtime, &encoded).await;
    let created = create_session(&listener, &runtime, &bootstrap).await;
    let (created_headers, _) = split_response(&created);
    let bearer = response_header(created_headers, "x-session-token");
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(bearer)
        .unwrap();
    let hash: crate::web::manager::TokenHash = Sha256::digest(raw).into();
    let session = runtime.get_session(hash, "proxy.example.com").unwrap();
    let trace_session_id = session.trace_session_id();

    assert!(session.begin_carrier_supersede());
    assert_eq!(
        session.close(SessionCloseReason::ApiClose),
        SessionCloseOutcome::Deferred
    );
    session.cancel_carrier_supersede();
    session.wait_close_complete().await;

    assert!(matches!(
        runtime.session_detail(trace_session_id),
        SessionDetail::Gone {
            reason: "api_close",
            ..
        }
    ));
    assert_eq!(
        runtime
            .telemetry()
            .session_close_total(WebCarrier::Https, SessionCloseReason::ApiClose),
        1
    );
    assert_eq!(
        runtime
            .telemetry()
            .session_close_total(WebCarrier::Https, SessionCloseReason::CarrierSuperseded,),
        0
    );

    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}
