use super::*;

#[tokio::test]
async fn runtime_index_lists_and_asynchronously_closes_by_opaque_reference() {
    let capability = [19u8; 32];
    let generation = test_runtime_generation(1, runtime_config(capability, WebCarrier::Https));
    let active_runtime = Arc::new(ArcSwap::from(Arc::clone(&generation)));
    let runtime = WebProcessRuntime::start(active_runtime);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(capability);
    let root = format!(
        "GET /?bridge={encoded} HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.19\r\nUser-Agent: Telemt-Control-Test/1\r\nConnection: close\r\n\r\n"
    )
    .into_bytes();
    let root_response = request(&listener, &runtime, root).await;
    let (_, root_body) = split_response(&root_response);
    let bootstrap = std::str::from_utf8(root_body)
        .unwrap()
        .split_once("bootstrap=\"")
        .and_then(|(_, suffix)| suffix.split_once('"'))
        .map(|(token, _)| token)
        .unwrap();
    let hello = frame::encode(FrameType::Hello, 0, &[1]);
    let mut create = format!(
        "POST /api/v1/session HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.19\r\nAuthorization: Bearer {bootstrap}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        hello.len()
    )
    .into_bytes();
    create.extend_from_slice(&hello);
    let create_response = request(&listener, &runtime, create).await;
    assert!(create_response.starts_with(b"HTTP/1.1 200"));

    let page = runtime.list_sessions(SessionListRequest {
        limit: 50,
        cursor: None,
        filter: SessionFilter::default(),
    });
    assert_eq!(page.sessions.len(), 1);
    assert_eq!(
        page.sessions[0].user_agent.as_deref(),
        Some("Telemt-Control-Test/1")
    );
    let session_ref = page.sessions[0].session_ref.clone();
    let trace_session_id = runtime.parse_session_ref(&session_ref).unwrap();
    let noncanonical_session_ref = format!("ws1.{}.000000000000000A", runtime.runtime_instance());
    assert_eq!(
        runtime.parse_session_ref(&noncanonical_session_ref),
        Err(SessionRefError::Invalid)
    );
    let noncanonical_operation_id = format!("wo1.{}.000000000000000A", runtime.runtime_instance());
    assert!(matches!(
        runtime.control_operation(&noncanonical_operation_id),
        Err(ControlError::InvalidOperation)
    ));
    let nonmatching = runtime
        .start_close_operation(
            runtime.runtime_instance(),
            CloseOperationSelector::Filter(SessionFilter {
                state: Some("healthy".to_string()),
                ..SessionFilter::default()
            }),
        )
        .unwrap();
    let mut nonmatching_status = None;
    for _ in 0..32 {
        let status = runtime
            .control_operation(&nonmatching.operation_id)
            .unwrap();
        if serde_json::to_value(&status).unwrap()["state"] == "completed" {
            nonmatching_status = Some(status);
            break;
        }
        tokio::task::yield_now().await;
    }
    let nonmatching_status = nonmatching_status.expect("filtered close operation completed");
    assert_eq!(nonmatching_status.matched, 0);
    assert_eq!(nonmatching_status.close_signalled, 0);
    assert!(matches!(
        runtime.session_detail(trace_session_id),
        SessionDetail::Active(_)
    ));
    let operation = runtime
        .start_close_operation(
            runtime.runtime_instance(),
            CloseOperationSelector::Refs(vec![trace_session_id]),
        )
        .unwrap();
    for _ in 0..32 {
        let status = runtime.control_operation(&operation.operation_id).unwrap();
        if serde_json::to_value(&status).unwrap()["state"] == "completed" {
            break;
        }
        tokio::task::yield_now().await;
    }

    assert!(matches!(
        runtime.session_detail(trace_session_id),
        SessionDetail::Gone { .. }
    ));
    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}
