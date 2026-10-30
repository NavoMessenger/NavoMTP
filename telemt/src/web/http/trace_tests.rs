use std::sync::Arc;

use arc_swap::ArcSwap;
use base64::Engine as _;
use tokio::net::TcpListener;

use super::tests::{request, runtime_config, split_response};
use crate::config::{WebCarrier, WebDebugBodyCapture};
use crate::maestro::generation::test_runtime_generation;
use crate::web::manager::WebProcessRuntime;
use crate::web::trace::{TraceBodyState, TraceRecordKind, TraceRoute};

#[tokio::test]
async fn enabled_debug_records_bridge_request_response_without_credentials() {
    let capability = [18u8; 32];
    let mut config = runtime_config(capability, WebCarrier::Https);
    config.web.debug.enabled = true;
    config.web.debug.body_capture = WebDebugBodyCapture::Full;
    config.web.debug.body_prefix_bytes = 4096;
    let generation = test_runtime_generation(1, config);
    let active_runtime = Arc::new(ArcSwap::from(Arc::clone(&generation)));
    let runtime = WebProcessRuntime::start(active_runtime);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(capability);
    let root = format!(
        "GET /?bridge={encoded} HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.50\r\nUser-Agent: debug-client/1\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();

    let response = request(&listener, &runtime, root).await;
    let (_, body) = split_response(&response);
    let body = std::str::from_utf8(body).unwrap();
    let bootstrap = body
        .split_once("bootstrap=\"")
        .and_then(|(_, suffix)| suffix.split_once('"'))
        .map(|(token, _)| token)
        .unwrap();
    let records = runtime
        .trace()
        .snapshot_matching(|record| matches!(&record.kind, TraceRecordKind::Http(_)));
    assert_eq!(records.len(), 1);
    let record = &records[0].record;
    assert_eq!(record.effective_ip, Some("192.0.2.50".parse().unwrap()));
    assert_eq!(record.user_agent.as_deref(), Some("debug-client/1"));
    assert!(record.identity.session_id.is_some());
    assert_eq!(record.identity.user.as_deref(), Some("alice"));
    let TraceRecordKind::Http(http) = &record.kind else {
        panic!("expected HTTP debug record");
    };
    assert_eq!(http.method, "GET");
    assert_eq!(http.path, "/");
    assert_eq!(http.route, TraceRoute::Bridge);
    assert_eq!(http.status, Some(200));
    assert_eq!(
        http.response_body.as_ref().unwrap().state,
        TraceBodyState::Complete
    );
    let captured_response = &http.response_body.as_ref().unwrap().captured;
    assert!(
        !captured_response
            .windows(bootstrap.len())
            .any(|value| value == bootstrap.as_bytes())
    );
    assert!(
        captured_response
            .windows(bootstrap.len())
            .any(|value| value.iter().all(|byte| *byte == b'*'))
    );
    assert!(http.timings.as_ref().unwrap().response_ready_us.is_some());
    assert!(http.timings.as_ref().unwrap().response_body_us.is_some());

    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}
