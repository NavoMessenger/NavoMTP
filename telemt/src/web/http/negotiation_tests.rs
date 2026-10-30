use super::*;

use std::time::Duration;

use sha2::{Digest, Sha256};

const CAPABILITIES: &str = "https,https-lanes,websocket,websocket-lanes";
const NATIVE_USER_AGENT_HEADER: &str =
    "User-Agent: Telegram/3951 CFNetwork/3896.100.1.2.1 Darwin/27.0.0\r\n";

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

fn create_request(
    bootstrap: &str,
    hello: &[u8],
    attempt: Option<u8>,
    failure: Option<&str>,
) -> Vec<u8> {
    create_request_with_headers(bootstrap, hello, attempt, failure, "")
}

fn create_request_with_headers(
    bootstrap: &str,
    hello: &[u8],
    attempt: Option<u8>,
    failure: Option<&str>,
    extra_headers: &str,
) -> Vec<u8> {
    let negotiation = attempt.map_or_else(String::new, |attempt| {
        let failure = failure
            .map(|failure| format!("X-Carrier-Failure: {failure}\r\n"))
            .unwrap_or_default();
        format!(
            "X-Carrier-Capabilities: {CAPABILITIES}\r\nX-Carrier-Attempt: {attempt}\r\n{failure}"
        )
    });
    let mut request = format!(
        "POST /api/v1/session HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {bootstrap}\r\nContent-Type: application/octet-stream\r\n{negotiation}{extra_headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
        hello.len()
    )
    .into_bytes();
    request.extend_from_slice(hello);
    request
}

fn optional_response_header<'a>(headers: &'a [u8], name: &str) -> Option<&'a str> {
    std::str::from_utf8(headers)
        .unwrap()
        .lines()
        .filter_map(|line| line.split_once(':'))
        .find_map(|(header, value)| header.eq_ignore_ascii_case(name).then_some(value.trim()))
}

fn token_hash(token: &str) -> crate::web::manager::TokenHash {
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token)
        .unwrap();
    Sha256::digest(raw).into()
}

fn assert_no_negotiation_headers(headers: &[u8]) {
    for header in [
        "x-carrier-attempt",
        "x-carrier-candidate-count",
        "x-carrier-deadline",
        "x-carrier-state",
    ] {
        assert!(optional_response_header(headers, header).is_none());
    }
}

#[tokio::test]
async fn absent_carriers_reject_negotiation_and_preserve_legacy_creation() {
    let capability = [41; 32];
    let generation = test_runtime_generation(1, runtime_config(capability, WebCarrier::Https));
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bootstrap = issue_bootstrap(&runtime, "192.0.2.10");
    let hello = frame::encode(FrameType::Hello, 0, &[1]);

    let rejected = request(
        &listener,
        &runtime,
        create_request(&bootstrap, &hello, Some(1), None),
    )
    .await;
    let (rejected_headers, _) = split_response(&rejected);
    assert!(optional_response_header(rejected_headers, "x-session-token").is_none());

    let legacy = request(
        &listener,
        &runtime,
        create_request(&bootstrap, &hello, None, None),
    )
    .await;
    let (legacy_headers, _) = split_response(&legacy);
    assert!(legacy_headers.starts_with(b"HTTP/1.1 200"));
    assert_eq!(response_header(legacy_headers, "x-carrier-mode"), "https");
    assert!(optional_response_header(legacy_headers, "x-carrier-attempt").is_none());

    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}

#[tokio::test]
async fn metadata_free_native_client_can_use_each_fixed_carrier() {
    for (index, carrier) in WebCarrier::ALL.into_iter().enumerate() {
        let capability = [50 + index as u8; 32];
        let generation = test_runtime_generation(1, runtime_config(capability, carrier));
        let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let bootstrap = issue_bootstrap(&runtime, "192.0.2.10");
        let hello = frame::encode(FrameType::Hello, 0, &[1]);

        let response = request(
            &listener,
            &runtime,
            create_request_with_headers(&bootstrap, &hello, None, None, NATIVE_USER_AGENT_HEADER),
        )
        .await;
        let (headers, _) = split_response(&response);
        assert!(headers.starts_with(b"HTTP/1.1 200"));
        assert_eq!(response_header(headers, "x-carrier-mode"), carrier.as_str());
        assert_no_negotiation_headers(headers);

        runtime.shutdown().await;
        generation.stop_sessions().await;
        generation.stop_background_tasks().await;
    }
}

#[tokio::test]
async fn metadata_free_native_client_uses_fallback_when_candidates_are_enabled() {
    let capability = [55; 32];
    let generation = test_runtime_generation(
        1,
        negotiation_runtime_config(
            capability,
            WebCarrier::HttpsLanes,
            false,
            Arc::from([WebCarrier::Websocket, WebCarrier::HttpsLanes]),
        ),
    );
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bootstrap = issue_bootstrap(&runtime, "192.0.2.10");
    let hello = frame::encode(FrameType::Hello, 0, &[1]);

    let response = request(
        &listener,
        &runtime,
        create_request_with_headers(&bootstrap, &hello, None, None, NATIVE_USER_AGENT_HEADER),
    )
    .await;
    let (headers, _) = split_response(&response);
    assert!(headers.starts_with(b"HTTP/1.1 200"));
    assert_eq!(response_header(headers, "x-carrier-mode"), "https-lanes");
    assert_no_negotiation_headers(headers);

    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}

#[tokio::test]
async fn explicit_native_capabilities_are_limited_to_https() {
    let capability = [56; 32];
    let generation = test_runtime_generation(
        1,
        negotiation_runtime_config(
            capability,
            WebCarrier::Https,
            false,
            Arc::from([WebCarrier::WebsocketLanes, WebCarrier::Https]),
        ),
    );
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bootstrap = issue_bootstrap(&runtime, "192.0.2.10");
    let hello = frame::encode(FrameType::Hello, 0, &[1]);

    let response = request(
        &listener,
        &runtime,
        create_request_with_headers(&bootstrap, &hello, Some(1), None, NATIVE_USER_AGENT_HEADER),
    )
    .await;
    let (headers, _) = split_response(&response);
    assert!(headers.starts_with(b"HTTP/1.1 200"));
    assert_eq!(response_header(headers, "x-carrier-mode"), "https");
    assert_eq!(response_header(headers, "x-carrier-attempt"), "1");
    assert_eq!(response_header(headers, "x-carrier-candidate-count"), "1");

    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}

#[tokio::test]
async fn negotiation_replays_replaces_and_freezes_after_carrier_commit() {
    let capability = [42; 32];
    let mut config = negotiation_runtime_config(
        capability,
        WebCarrier::Websocket,
        false,
        Arc::from([
            WebCarrier::Https,
            WebCarrier::HttpsLanes,
            WebCarrier::Websocket,
        ]),
    );
    config.web.timeouts.long_poll_secs = 1;
    let generation = test_runtime_generation(1, config);
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bootstrap = issue_bootstrap(&runtime, "192.0.2.10");
    let hello = frame::encode(FrameType::Hello, 0, &[1]);

    let first_request = create_request(&bootstrap, &hello, Some(1), None);
    let first = request(&listener, &runtime, first_request.clone()).await;
    let (first_headers, _) = split_response(&first);
    assert_eq!(response_header(first_headers, "x-carrier-mode"), "https");
    assert_eq!(response_header(first_headers, "x-carrier-attempt"), "1");
    let first_token = response_header(first_headers, "x-session-token").to_string();

    let replay = request(&listener, &runtime, first_request).await;
    let (replay_headers, _) = split_response(&replay);
    assert_eq!(
        response_header(replay_headers, "x-session-token"),
        first_token
    );
    assert_eq!(
        response_header(replay_headers, "x-carrier-candidate-count"),
        "3"
    );
    assert_eq!(
        response_header(replay_headers, "x-carrier-state"),
        "provisional"
    );

    let second_request = create_request(&bootstrap, &hello, Some(2), Some("timeout"));
    let second = request(&listener, &runtime, second_request.clone()).await;
    let (second_headers, _) = split_response(&second);
    assert_eq!(
        response_header(second_headers, "x-carrier-mode"),
        "https-lanes"
    );
    assert_eq!(response_header(second_headers, "x-carrier-attempt"), "2");
    let second_token = response_header(second_headers, "x-session-token").to_string();
    assert_ne!(first_token, second_token);
    assert!(
        runtime
            .get_session(token_hash(&first_token), "proxy.example.com")
            .is_err()
    );

    let second_replay = request(&listener, &runtime, second_request).await;
    let (second_replay_headers, _) = split_response(&second_replay);
    for header in [
        "x-session-token",
        "x-carrier-mode",
        "x-carrier-attempt",
        "x-carrier-candidate-count",
        "x-carrier-deadline",
        "x-carrier-state",
    ] {
        assert_eq!(
            response_header(second_replay_headers, header),
            response_header(second_headers, header),
        );
    }

    let changed_failure = request(
        &listener,
        &runtime,
        create_request(&bootstrap, &hello, Some(2), Some("network")),
    )
    .await;
    let (changed_failure_headers, _) = split_response(&changed_failure);
    assert!(optional_response_header(changed_failure_headers, "x-session-token").is_none());

    let open = frame::encode(FrameType::Open, 7, &[]);
    let data = frame::encode(FrameType::Data, 7, &[0]);
    let mut body = Vec::with_capacity(open.len() + data.len());
    body.extend_from_slice(&open);
    body.extend_from_slice(&data);
    let mut uplink = format!(
        "POST /api/v1/up HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {second_token}\r\nContent-Type: application/octet-stream\r\nX-Up-Seq: 1\r\nX-Lane-ID: 7\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    uplink.extend_from_slice(&body);
    let accepted = request(&listener, &runtime, uplink).await;
    assert!(accepted.starts_with(b"HTTP/1.1 204"));

    let first_down = format!(
        "POST /api/v1/down HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {second_token}\r\nX-Down-Cursor: 0\r\nX-Lane-ID: 7\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    let first_down = request(&listener, &runtime, first_down).await;
    let (first_down_headers, first_down_body) = split_response(&first_down);
    assert!(first_down_headers.starts_with(b"HTTP/1.1 200"));
    assert!(!first_down_body.is_empty());
    assert_eq!(response_header(first_down_headers, "x-down-cursor"), "1");

    let acknowledgement = format!(
        "POST /api/v1/down HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {second_token}\r\nX-Down-Cursor: 1\r\nX-Lane-ID: 7\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    let acknowledgement = request(&listener, &runtime, acknowledgement).await;
    assert!(acknowledgement.starts_with(b"HTTP/1.1 204"));

    let third = request(
        &listener,
        &runtime,
        create_request(&bootstrap, &hello, Some(3), Some("http")),
    )
    .await;
    let (third_headers, _) = split_response(&third);
    assert!(third_headers.starts_with(b"HTTP/1.1 409"));
    assert!(optional_response_header(third_headers, "x-session-token").is_none());
    assert_eq!(
        response_header(third_headers, "x-carrier-mode"),
        "https-lanes"
    );
    assert_eq!(response_header(third_headers, "x-carrier-attempt"), "2");
    assert_eq!(
        response_header(third_headers, "x-carrier-candidate-count"),
        "3"
    );
    assert_eq!(response_header(third_headers, "x-carrier-deadline"), "12");
    assert_eq!(
        response_header(third_headers, "x-carrier-state"),
        "committed"
    );
    assert!(
        runtime
            .get_session(token_hash(&second_token), "proxy.example.com")
            .unwrap()
            .is_carrier_committed()
    );

    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}

#[tokio::test]
async fn timed_out_attempt_replays_before_successor_own_deadline() {
    let capability = [57; 32];
    let generation = test_runtime_generation(
        1,
        negotiation_runtime_config_with_deadlines(
            capability,
            WebCarrier::HttpsLanes,
            false,
            Arc::from([WebCarrier::Https, WebCarrier::HttpsLanes]),
            [1, 5, 8, 12],
        ),
    );
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bootstrap = issue_bootstrap(&runtime, "192.0.2.10");
    let hello = frame::encode(FrameType::Hello, 0, &[1]);
    let first_request = create_request(&bootstrap, &hello, Some(1), None);

    let first = request(&listener, &runtime, first_request.clone()).await;
    let (first_headers, _) = split_response(&first);
    assert!(first_headers.starts_with(b"HTTP/1.1 200"));
    assert_eq!(response_header(first_headers, "x-carrier-mode"), "https");
    let first_token = response_header(first_headers, "x-session-token").to_string();

    tokio::time::sleep(Duration::from_millis(1_100)).await;

    let replay = request(&listener, &runtime, first_request).await;
    let (replay_headers, _) = split_response(&replay);
    assert!(replay_headers.starts_with(b"HTTP/1.1 200"));
    assert_eq!(
        response_header(replay_headers, "x-session-token"),
        first_token
    );
    assert_eq!(
        response_header(replay_headers, "x-carrier-state"),
        "provisional"
    );

    let second = request(
        &listener,
        &runtime,
        create_request(&bootstrap, &hello, Some(2), Some("timeout")),
    )
    .await;
    let (second_headers, _) = split_response(&second);
    assert!(second_headers.starts_with(b"HTTP/1.1 200"));
    assert_eq!(
        response_header(second_headers, "x-carrier-mode"),
        "https-lanes"
    );
    assert_eq!(response_header(second_headers, "x-carrier-attempt"), "2");
    assert_ne!(
        response_header(second_headers, "x-session-token"),
        first_token
    );

    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}

#[tokio::test]
async fn https_lane_downlink_can_arrive_before_its_uplink_open() {
    let capability = [43; 32];
    let mut config = negotiation_runtime_config(
        capability,
        WebCarrier::HttpsLanes,
        false,
        Arc::from([WebCarrier::HttpsLanes]),
    );
    config.web.timeouts.lane_open_wait_secs = 1;
    config.web.timeouts.long_poll_secs = 2;
    let generation = test_runtime_generation(1, config);
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
    let listener = Arc::new(TcpListener::bind("127.0.0.1:0").await.unwrap());
    let bootstrap = issue_bootstrap(&runtime, "192.0.2.10");
    let hello = frame::encode(FrameType::Hello, 0, &[1]);
    let created = request(
        &listener,
        &runtime,
        create_request(&bootstrap, &hello, Some(1), None),
    )
    .await;
    let (created_headers, _) = split_response(&created);
    let token = response_header(created_headers, "x-session-token").to_string();

    let down_request = format!(
        "POST /api/v1/down HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {token}\r\nX-Down-Cursor: 0\r\nX-Lane-ID: 7\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    let down_listener = Arc::clone(&listener);
    let down_runtime = Arc::clone(&runtime);
    let down =
        tokio::spawn(async move { request(&down_listener, &down_runtime, down_request).await });
    tokio::task::yield_now().await;

    let open = frame::encode(FrameType::Open, 7, &[]);
    let data = frame::encode(FrameType::Data, 7, &[1]);
    let mut body = Vec::with_capacity(open.len() + data.len());
    body.extend_from_slice(&open);
    body.extend_from_slice(&data);
    let mut uplink = format!(
        "POST /api/v1/up HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {token}\r\nContent-Type: application/octet-stream\r\nX-Up-Seq: 1\r\nX-Lane-ID: 7\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    uplink.extend_from_slice(&body);
    let accepted = request(&listener, &runtime, uplink).await;
    assert!(accepted.starts_with(b"HTTP/1.1 204"));

    let down = tokio::time::timeout(Duration::from_secs(3), down)
        .await
        .unwrap()
        .unwrap();
    let (down_headers, _) = split_response(&down);
    assert!(down_headers.starts_with(b"HTTP/1.1 200") || down_headers.starts_with(b"HTTP/1.1 204"));
    assert!(optional_response_header(down_headers, "x-down-cursor").is_some());

    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}
