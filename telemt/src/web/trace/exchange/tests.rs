use super::*;

fn trace_store() -> Arc<WebTraceStore> {
    let policy = WebDebugConfig {
        enabled: true,
        body_capture: WebDebugBodyCapture::Prefix,
        body_prefix_bytes: 256,
        ..Default::default()
    };
    let limits = WebLimitsConfig {
        debug_records_capacity: 4,
        debug_bytes_global: 16 * 1024,
        ..Default::default()
    };
    WebTraceStore::new(policy, &limits)
}

#[test]
fn request_response_capture_redacts_credentials_and_omits_query() {
    let request_token = "request-token-0123456789";
    let capability = "capability-0123456789";
    let response_token = "response-token-0123456789";
    let request = hyper::Request::builder()
        .uri(format!("/?bridge={capability}"))
        .header("authorization", format!("Bearer {request_token}"))
        .body(())
        .unwrap();
    let store = trace_store();
    let exchange = store
        .begin_http(&request, "192.0.2.30".parse().unwrap())
        .unwrap();
    exchange.set_route(TraceRoute::Bridge);
    exchange.body_data(
        TraceDirection::Request,
        format!("{request_token}:{capability}").as_bytes(),
    );
    exchange.body_finished(TraceDirection::Request, TraceBodyState::Complete);

    let response = hyper::Response::builder()
        .status(hyper::StatusCode::OK)
        .header("x-session-token", response_token)
        .body(())
        .unwrap();
    exchange.response_ready(&response);
    exchange.body_data(TraceDirection::Response, response_token.as_bytes());
    exchange.body_finished(TraceDirection::Response, TraceBodyState::Complete);

    let records = store.snapshot_matching(|_| true);
    assert_eq!(records.len(), 1);
    let TraceRecordKind::Http(http) = &records[0].record.kind else {
        panic!("expected HTTP debug record");
    };
    assert_eq!(http.path, "/");
    assert_eq!(http.route, TraceRoute::Bridge);
    assert!(
        http.request_headers
            .iter()
            .any(|header| header.name == "authorization" && header.value.is_none())
    );
    assert!(
        http.response_headers
            .iter()
            .any(|header| header.name == "x-session-token" && header.value.is_none())
    );
    let request_body = http.request_body.as_ref().unwrap();
    let response_body = http.response_body.as_ref().unwrap();
    for secret in [request_token.as_bytes(), capability.as_bytes()] {
        assert!(
            !request_body
                .captured
                .windows(secret.len())
                .any(|value| value == secret)
        );
    }
    assert!(
        !response_body
            .captured
            .windows(response_token.len())
            .any(|value| value == response_token.as_bytes())
    );
}

#[test]
fn late_capture_after_commit_cannot_leak_debug_byte_budget() {
    let request = hyper::Request::builder().uri("/").body(()).unwrap();
    let store = trace_store();
    let exchange = store
        .begin_http(&request, "192.0.2.31".parse().unwrap())
        .unwrap();
    exchange.commit();
    let committed_bytes = store.status().used_bytes;

    exchange.register_redaction(&[0x41; 2048]);
    exchange.body_data(TraceDirection::Request, &[0x42; 2048]);
    exchange.record_frames(
        TraceDirection::Request,
        &[0; frame::HEADER_BYTES],
        &WebLimitsConfig::default(),
    );

    assert_eq!(store.status().used_bytes, committed_bytes);
    drop(exchange);
    assert_eq!(store.clear().leased_bytes, 0);
}
