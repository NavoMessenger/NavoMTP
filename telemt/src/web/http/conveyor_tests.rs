use super::*;

async fn create_with_headers(
    listener: &TcpListener,
    runtime: &Arc<WebProcessRuntime>,
    bootstrap: &str,
    headers: &str,
) -> Vec<u8> {
    request(
        listener,
        runtime,
        carrier_request(
            "POST",
            "/api/v1/session",
            bootstrap,
            &format!("Content-Type: application/octet-stream\r\n{headers}"),
            &frame::encode(FrameType::Hello, 0, &[1]),
        ),
    )
    .await
}

fn up(token: &str, seq: u64, confirmed: &str, lane: &str) -> Vec<u8> {
    carrier_request(
        "POST",
        "/api/v1/up",
        token,
        &format!("Content-Type: application/octet-stream\r\nX-Up-Seq: {seq}\r\n{confirmed}{lane}"),
        &frame::encode(FrameType::Pong, 0, &[]),
    )
}

#[tokio::test]
async fn conveyor_negotiation_is_opt_in_bounded_and_invisible_to_native_welcome() {
    for enabled in [false, true] {
        for carrier in [
            WebCarrier::Https,
            WebCarrier::HttpsLanes,
            WebCarrier::Websocket,
        ] {
            let capability = [71; 32];
            let mut config = runtime_config(capability, carrier);
            config.web.conveyor = enabled;
            let generation = test_runtime_generation(1, config);
            let runtime =
                WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            for offered in [None, Some(1), Some(2), Some(4)] {
                let page = bridge_page(&listener, &runtime, capability, "/").await;
                let bootstrap = bootstrap_from(&page);
                let offer = offered.map_or(String::new(), |value| {
                    format!("X-Telemt-Up-Window: {value}\r\n")
                });
                let response = create_with_headers(&listener, &runtime, bootstrap, &offer).await;
                let (headers, body) = split_response(&response);
                assert!(headers.starts_with(b"HTTP/1.1 200"));
                assert_eq!(body, frame::encode(FrameType::Welcome, 0, &[]));
                if let Some(offered) = offered {
                    let window = if enabled && !carrier.uses_websocket() {
                        offered
                    } else {
                        1
                    };
                    assert_eq!(
                        response_header(headers, "x-telemt-up-window"),
                        window.to_string()
                    );
                } else {
                    assert!(
                        !String::from_utf8_lossy(headers)
                            .to_lowercase()
                            .contains("x-telemt-up-window")
                    );
                }
                let replay = create_with_headers(&listener, &runtime, bootstrap, &offer).await;
                let (replayed, _) = split_response(&replay);
                assert_eq!(
                    response_header(headers, "x-session-token"),
                    response_header(replayed, "x-session-token")
                );
            }
            runtime.shutdown().await;
            generation.stop_sessions().await;
            generation.stop_background_tasks().await;
        }
    }
}

#[tokio::test]
async fn malformed_window_does_not_consume_bootstrap_or_enable_a_conveyor() {
    let capability = [72; 32];
    let generation = test_runtime_generation(1, runtime_config(capability, WebCarrier::Https));
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let page = bridge_page(&listener, &runtime, capability, "/").await;
    let bootstrap = bootstrap_from(&page);
    for offer in ["0", "5", "04", "-1", "4, 4", "4\r\nX-Telemt-Up-Window: 4"] {
        let response = create_with_headers(
            &listener,
            &runtime,
            bootstrap,
            &format!("X-Telemt-Up-Window: {offer}\r\n"),
        )
        .await;
        assert!(
            response.starts_with(b"HTTP/1.1 404"),
            "{offer}: {:?}",
            response
        );
    }
    let response =
        create_with_headers(&listener, &runtime, bootstrap, "X-Telemt-Up-Window: 4\r\n").await;
    assert!(response.starts_with(b"HTTP/1.1 200"));
    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}

#[tokio::test]
async fn reload_changes_only_new_sessions_and_exact_creation_replay_keeps_its_window() {
    let capability = [73; 32];
    let config = runtime_config(capability, WebCarrier::Https);
    let generation = test_runtime_generation(1, config.clone());
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let page = bridge_page(&listener, &runtime, capability, "/").await;
    let bootstrap = bootstrap_from(&page);
    let offer = "X-Telemt-Up-Window: 4\r\n";
    let original = create_with_headers(&listener, &runtime, bootstrap, offer).await;
    let (original_headers, _) = split_response(&original);
    let token = response_header(original_headers, "x-session-token");
    let mut disabled = config;
    disabled.web.conveyor = false;
    let replacement = test_runtime_generation(2, disabled);
    runtime.activate_generation(Arc::clone(&replacement));
    let replay = create_with_headers(&listener, &runtime, bootstrap, offer).await;
    let (headers, _) = split_response(&replay);
    assert_eq!(response_header(headers, "x-telemt-up-window"), "4");
    assert_eq!(response_header(headers, "x-session-token"), token);
    let old_up = request(
        &listener,
        &runtime,
        up(token, 1, "X-Telemt-Up-Confirmed: 0\r\n", ""),
    )
    .await;
    assert!(old_up.starts_with(b"HTTP/1.1 204"));
    let page = bridge_page(&listener, &runtime, capability, "/").await;
    let created = create_with_headers(&listener, &runtime, bootstrap_from(&page), offer).await;
    let (headers, _) = split_response(&created);
    assert_eq!(response_header(headers, "x-telemt-up-window"), "1");
    let token = response_header(headers, "x-session-token");
    let mode_error = request(
        &listener,
        &runtime,
        up(token, 1, "X-Telemt-Up-Confirmed: 0\r\n", ""),
    )
    .await;
    assert!(mode_error.starts_with(b"HTTP/1.1 409"));
    let legacy = request(&listener, &runtime, up(token, 1, "", "")).await;
    assert!(legacy.starts_with(b"HTTP/1.1 204"));
    runtime.shutdown().await;
    for generation in [generation, replacement] {
        generation.stop_sessions().await;
        generation.stop_background_tasks().await;
    }
}

#[tokio::test]
async fn future_http_request_is_not_acked_until_head_applies_for_both_carriers() {
    for carrier in [WebCarrier::Https, WebCarrier::HttpsLanes] {
        let capability = [74; 32];
        let generation = test_runtime_generation(1, runtime_config(capability, carrier));
        let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let page = bridge_page(&listener, &runtime, capability, "/").await;
        let created = create_with_headers(
            &listener,
            &runtime,
            bootstrap_from(&page),
            "X-Telemt-Up-Window: 4\r\n",
        )
        .await;
        let (headers, _) = split_response(&created);
        let token = response_header(headers, "x-session-token");
        let lane = if carrier.uses_lanes() {
            "X-Lane-ID: 0\r\n"
        } else {
            ""
        };
        let (mut tail, cancellation, task) = open_keepalive(&listener, &runtime).await;
        tail.write_all(&up(token, 2, "X-Telemt-Up-Confirmed: 0\r\n", lane))
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(20), tail.read_u8())
                .await
                .is_err()
        );
        let head = request(
            &listener,
            &runtime,
            up(token, 1, "X-Telemt-Up-Confirmed: 0\r\n", lane),
        )
        .await;
        assert!(head.starts_with(b"HTTP/1.1 204"));
        let response = read_http_response(&mut tail).await;
        let (headers, _) = split_response(&response);
        assert!(headers.starts_with(b"HTTP/1.1 204"));
        assert_eq!(response_header(headers, "x-up-ack"), "2");
        cancellation.cancel();
        task.await.unwrap();
        runtime.shutdown().await;
        generation.stop_sessions().await;
        generation.stop_background_tasks().await;
    }
}

#[tokio::test]
async fn parked_uplink_keeps_its_session_deadline_after_reload() {
    let capability = [75; 32];
    let mut config = runtime_config(capability, WebCarrier::Https);
    config.web.timeouts.body_secs = 4;
    let generation = test_runtime_generation(1, config.clone());
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let page = bridge_page(&listener, &runtime, capability, "/").await;
    let response = create_with_headers(
        &listener,
        &runtime,
        bootstrap_from(&page),
        "X-Telemt-Up-Window: 4\r\n",
    )
    .await;
    let (headers, _) = split_response(&response);
    let token = response_header(headers, "x-session-token");
    config.web.timeouts.body_secs = 1;
    config.web.timeouts.http_idle_secs = 2;
    let replacement = test_runtime_generation(2, config);
    runtime.activate_generation(Arc::clone(&replacement));
    let (mut tail, cancellation, task) = open_keepalive(&listener, &runtime).await;
    tail.write_all(&up(token, 2, "X-Telemt-Up-Confirmed: 0\r\n", ""))
        .await
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(2200)).await;
    assert!(
        !task.is_finished(),
        "connection idle timeout must not replace the frozen parked-UP deadline"
    );
    let head = request(
        &listener,
        &runtime,
        up(token, 1, "X-Telemt-Up-Confirmed: 0\r\n", ""),
    )
    .await;
    assert!(head.starts_with(b"HTTP/1.1 204"));
    assert!(
        read_http_response(&mut tail)
            .await
            .starts_with(b"HTTP/1.1 204")
    );
    cancellation.cancel();
    task.await.unwrap();
    runtime.shutdown().await;
    for generation in [generation, replacement] {
        generation.stop_sessions().await;
        generation.stop_background_tasks().await;
    }
}

#[tokio::test]
async fn empty_long_poll_cannot_steal_the_reserved_head_body_capacity() {
    let capability = [76; 32];
    let mut config = runtime_config(capability, WebCarrier::Https);
    config.web.limits.max_body_readers = 3;
    config.web.limits.max_body_bytes = 32;
    config.web.limits.max_body_bytes_global = 96;
    let generation = test_runtime_generation(1, config);
    let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let page = bridge_page(&listener, &runtime, capability, "/").await;
    let response = create_with_headers(
        &listener,
        &runtime,
        bootstrap_from(&page),
        "X-Telemt-Up-Window: 4\r\n",
    )
    .await;
    let (headers, _) = split_response(&response);
    let token = response_header(headers, "x-session-token");
    let (mut down, down_cancel, down_task) = open_keepalive(&listener, &runtime).await;
    down.write_all(&carrier_request(
        "POST",
        "/api/v1/down",
        token,
        "X-Down-Cursor: 0\r\n",
        &[],
    ))
    .await
    .unwrap();
    let used = |resource| {
        runtime
            .capacity_snapshot()
            .resources
            .into_iter()
            .find(|value| value.resource == resource)
            .unwrap()
            .used
    };
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while used("lane_polls") != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        used("body_bytes"),
        0,
        "an empty long poll owns no buffered request body"
    );
    let mut tails = Vec::new();
    for sequence in [2, 3] {
        let (mut client, cancel, task) = open_keepalive(&listener, &runtime).await;
        client
            .write_all(&up(token, sequence, "X-Telemt-Up-Confirmed: 0\r\n", ""))
            .await
            .unwrap();
        tails.push((client, cancel, task));
    }
    tokio::time::timeout(std::time::Duration::from_secs(1), async {
        while used("body_bytes") != 64 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let head = request(
        &listener,
        &runtime,
        up(token, 1, "X-Telemt-Up-Confirmed: 0\r\n", ""),
    )
    .await;
    assert!(head.starts_with(b"HTTP/1.1 204"));
    for (mut client, cancel, task) in tails {
        assert!(
            read_http_response(&mut client)
                .await
                .starts_with(b"HTTP/1.1 204")
        );
        cancel.cancel();
        task.await.unwrap();
    }
    down_cancel.cancel();
    down_task.await.unwrap();
    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}
