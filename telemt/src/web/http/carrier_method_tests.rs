use super::super::session_policy_tests::{open_keepalive, read_http_response};
use super::super::*;
use crate::config::WebCarrierMethod;

#[path = "conveyor_tests.rs"]
mod conveyor_tests;

fn carrier_request(method: &str, path: &str, token: &str, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut bytes = format!(
        "{method} {path} HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.60\r\nAuthorization: Bearer {token}\r\n{headers}Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    bytes.extend_from_slice(body);
    bytes
}

async fn bridge_page(
    listener: &TcpListener,
    runtime: &Arc<WebProcessRuntime>,
    capability: [u8; 32],
    base: &str,
) -> Vec<u8> {
    let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(capability);
    request(
        listener,
        runtime,
        format!(
            "GET {base}?bridge={encoded} HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.60\r\nConnection: close\r\n\r\n"
        )
        .into_bytes(),
    )
    .await
}

fn bootstrap_from(page: &[u8]) -> &str {
    let (headers, body) = split_response(page);
    assert!(headers.starts_with(b"HTTP/1.1 200"));
    std::str::from_utf8(body)
        .unwrap()
        .split_once("bootstrap=\"")
        .unwrap()
        .1
        .split_once('"')
        .unwrap()
        .0
}

async fn create_session(
    listener: &TcpListener,
    runtime: &Arc<WebProcessRuntime>,
    bootstrap: &str,
    base: &str,
) -> String {
    let hello = frame::encode(FrameType::Hello, 0, &[1]);
    let bytes = carrier_request(
        "POST",
        &format!("{base}api/v1/session"),
        bootstrap,
        "Content-Type: application/octet-stream\r\n",
        &hello,
    );
    let response = request(listener, runtime, bytes).await;
    let (headers, _) = split_response(&response);
    assert!(headers.starts_with(b"HTTP/1.1 200"));
    response_header(headers, "x-session-token").to_string()
}

async fn session_token(
    listener: &TcpListener,
    runtime: &Arc<WebProcessRuntime>,
    capability: [u8; 32],
    base: &str,
) -> String {
    let page = bridge_page(listener, runtime, capability, base).await;
    create_session(listener, runtime, bootstrap_from(&page), base).await
}

async fn assert_put_accepted(path: &str) {
    for (carrier, base, method) in [WebCarrier::Https, WebCarrier::HttpsLanes]
        .into_iter()
        .flat_map(|carrier| {
            ["/", "/telegram/web/"].into_iter().flat_map(move |base| {
                [WebCarrierMethod::Post, WebCarrierMethod::Put]
                    .map(|method| (carrier, base, method))
            })
        })
    {
        let capability = [60; 32];
        let mut config = runtime_config_with_base(capability, carrier, base);
        config.web.carrier_method = method;
        config.web.timeouts.long_poll_secs = 0;
        let generation = test_runtime_generation(1, config);
        let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let token = session_token(&listener, &runtime, capability, base).await;
        let lane = if carrier.uses_lanes() {
            "X-Lane-ID: 0\r\n"
        } else {
            ""
        };
        let pong = frame::encode(FrameType::Pong, 0, &[]);
        let (headers, body) = if path.ends_with("/up") {
            (
                format!("Content-Type: application/octet-stream\r\nX-Up-Seq: 1\r\n{lane}"),
                pong.as_ref(),
            )
        } else {
            (format!("X-Down-Cursor: 0\r\n{lane}"), &[][..])
        };
        let path = format!("{base}{}", path.trim_start_matches('/'));
        let bytes = carrier_request("PUT", &path, &token, &headers, body);
        let response = request(&listener, &runtime, bytes).await;
        assert!(
            response.starts_with(b"HTTP/1.1 204"),
            "{carrier:?}: {}",
            String::from_utf8_lossy(&response)
        );
        runtime.shutdown().await;
        generation.stop_sessions().await;
        generation.stop_background_tasks().await;
    }
}

#[tokio::test]
async fn put_uplink_is_accepted_for_both_https_carriers() {
    assert_put_accepted("/api/v1/up").await;
}

#[tokio::test]
async fn put_downlink_is_accepted_for_both_https_carriers() {
    assert_put_accepted("/api/v1/down").await;
}

#[tokio::test]
async fn carrier_method_mixed_retries_share_sequence_and_cursor_state() {
    for carrier in [WebCarrier::Https, WebCarrier::HttpsLanes] {
        for method in [WebCarrierMethod::Post, WebCarrierMethod::Put] {
            let capability = [61; 32];
            let mut config = runtime_config(capability, carrier);
            config.web.carrier_method = method;
            config.web.timeouts.long_poll_secs = 0;
            // Exhausted admission queues a deterministic CLOSE without starting a relay task.
            config.web.limits.max_streams_global = 0;
            let generation = test_runtime_generation(1, config);
            let runtime =
                WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let token = session_token(&listener, &runtime, capability, "/").await;
            for (index, stream_id) in [7, 8].into_iter().enumerate() {
                let lane = if carrier.uses_lanes() {
                    format!("X-Lane-ID: {stream_id}\r\n")
                } else {
                    String::new()
                };
                let sequence = if carrier.uses_lanes() { 1 } else { index + 1 };
                let cursor = if carrier.uses_lanes() { 0 } else { index };
                let open = frame::encode(FrameType::Open, stream_id, &[]);
                let up_headers = format!(
                    "Content-Type: application/octet-stream\r\nX-Up-Seq: {sequence}\r\n{lane}"
                );
                let methods = if index == 0 {
                    ["POST", "PUT"]
                } else {
                    ["PUT", "POST"]
                };
                for verb in methods {
                    let bytes = carrier_request(verb, "/api/v1/up", &token, &up_headers, &open);
                    let response = request(&listener, &runtime, bytes).await;
                    let (headers, body) = split_response(&response);
                    assert!(headers.starts_with(b"HTTP/1.1 204"));
                    assert_eq!(response_header(headers, "x-up-ack"), sequence.to_string());
                    assert!(body.is_empty());
                }
                for verb in methods {
                    let headers = format!("X-Down-Cursor: {cursor}\r\n{lane}");
                    let bytes = carrier_request(verb, "/api/v1/down", &token, &headers, &[]);
                    let response = request(&listener, &runtime, bytes).await;
                    let (headers, body) = split_response(&response);
                    assert!(headers.starts_with(b"HTTP/1.1 200"));
                    assert_eq!(
                        response_header(headers, "x-down-cursor"),
                        (cursor + 1).to_string()
                    );
                    assert_eq!(body, frame::encode(FrameType::Close, stream_id, &[]));
                }
                let headers = format!("X-Down-Cursor: {}\r\n{lane}", cursor + 1);
                let bytes = carrier_request("PUT", "/api/v1/down", &token, &headers, &[]);
                let response = request(&listener, &runtime, bytes).await;
                assert!(response.starts_with(b"HTTP/1.1 204"));
            }
            runtime.shutdown().await;
            generation.stop_sessions().await;
            generation.stop_background_tasks().await;
        }
    }
}

#[tokio::test]
async fn carrier_method_changed_body_retry_keeps_protocol_failure() {
    for carrier in [WebCarrier::Https, WebCarrier::HttpsLanes] {
        let capability = [62; 32];
        let generation = test_runtime_generation(1, runtime_config(capability, carrier));
        let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let token = session_token(&listener, &runtime, capability, "/").await;
        let lane = if carrier.uses_lanes() {
            "X-Lane-ID: 0\r\n"
        } else {
            ""
        };
        let headers = format!("Content-Type: application/octet-stream\r\nX-Up-Seq: 1\r\n{lane}");
        let pong = frame::encode(FrameType::Pong, 0, &[]);
        let bytes = carrier_request("POST", "/api/v1/up", &token, &headers, &pong);
        let response = request(&listener, &runtime, bytes).await;
        assert!(response.starts_with(b"HTTP/1.1 204"));
        let mut changed = pong.to_vec();
        changed.extend_from_slice(&pong);
        let bytes = carrier_request("PUT", "/api/v1/up", &token, &headers, &changed);
        let response = request(&listener, &runtime, bytes).await;
        assert_private_decoy(&response);
        runtime.shutdown().await;
        generation.stop_sessions().await;
        generation.stop_background_tasks().await;
    }
}

fn assert_private_decoy(response: &[u8]) {
    let (headers, body) = split_response(response);
    assert!(headers.starts_with(b"HTTP/1.1 404"));
    assert_eq!(response_header(headers, "cache-control"), "no-store");
    assert_eq!(body, b"not found\n");
    let headers = std::str::from_utf8(headers).unwrap().to_ascii_lowercase();
    for name in ["x-up-ack:", "x-down-cursor:", "x-session-token:", "allow:"] {
        assert!(!headers.contains(name));
    }
}

#[tokio::test]
async fn carrier_method_put_preserves_authenticated_request_shape_checks() {
    for carrier in [WebCarrier::Https, WebCarrier::HttpsLanes] {
        let capability = [63; 32];
        let base = "/telegram/web/";
        let generation =
            test_runtime_generation(1, runtime_config_with_base(capability, carrier, base));
        let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let token = session_token(&listener, &runtime, capability, base).await;
        let pong = frame::encode(FrameType::Pong, 0, &[]);
        let lane = if carrier.uses_lanes() {
            "X-Lane-ID: 0\r\n"
        } else {
            ""
        };
        let up = format!("{base}api/v1/up");
        let down = format!("{base}api/v1/down");
        let up_headers = format!("Content-Type: application/octet-stream\r\nX-Up-Seq: 1\r\n{lane}");
        let down_headers = format!("X-Down-Cursor: 0\r\n{lane}");
        let mut invalid = Vec::new();
        for media in [
            "",
            "Content-Type: text/plain\r\n",
            "Content-Type: application/octet-stream\r\nContent-Type: application/octet-stream\r\n",
        ] {
            let headers = format!("{media}X-Up-Seq: 1\r\n{lane}");
            invalid.push(carrier_request("PUT", &up, &token, &headers, &pong));
        }
        for sequence in ["0", "01", ""] {
            let sequence = if sequence.is_empty() {
                String::new()
            } else {
                format!("X-Up-Seq: {sequence}\r\n")
            };
            let headers = format!("Content-Type: application/octet-stream\r\n{sequence}{lane}");
            invalid.push(carrier_request("PUT", &up, &token, &headers, &pong));
        }
        let invalid_lane = if carrier.uses_lanes() {
            ""
        } else {
            "X-Lane-ID: 0\r\n"
        };
        let headers =
            format!("Content-Type: application/octet-stream\r\nX-Up-Seq: 1\r\n{invalid_lane}");
        invalid.push(carrier_request("PUT", &up, &token, &headers, &pong));
        let headers = format!("{down_headers}Content-Type: application/octet-stream\r\n");
        invalid.push(carrier_request("PUT", &down, &token, &headers, &[]));
        invalid.push(carrier_request("PUT", &down, &token, &down_headers, &[0]));
        let headers = format!("X-Down-Cursor: 01\r\n{lane}");
        invalid.push(carrier_request("PUT", &down, &token, &headers, &[]));
        for verb in ["GET", "PATCH"] {
            invalid.push(carrier_request(verb, &up, &token, &up_headers, &pong));
            invalid.push(carrier_request(verb, &down, &token, &down_headers, &[]));
        }
        for path in [
            "/api/v1/up",
            "/telegram/web/api/v1/up/",
            "/telegram/web/api/v1/up?q=1",
            "/telegram/web/api/v1//up",
            "/telegram/web/api/v1/%75p",
        ] {
            invalid.push(carrier_request("PUT", path, &token, &up_headers, &pong));
        }
        let wrong_host = String::from_utf8(carrier_request("PUT", &up, &token, &up_headers, &pong))
            .unwrap()
            .replace("Host: proxy.example.com", "Host: other.example.com")
            .into_bytes();
        invalid.push(wrong_host);
        let path = format!("{base}api/v1/session");
        invalid.push(carrier_request("PUT", &path, &token, &up_headers, &pong));
        for bytes in invalid {
            let response = request(&listener, &runtime, bytes).await;
            assert_private_decoy(&response);
        }
        // Rejected shapes must not consume the first sequence or close the valid session.
        let bytes = carrier_request("PUT", &up, &token, &up_headers, &pong);
        let response = request(&listener, &runtime, bytes).await;
        assert!(response.starts_with(b"HTTP/1.1 204"));
        runtime.shutdown().await;
        generation.stop_sessions().await;
        generation.stop_background_tasks().await;
    }
}

#[tokio::test]
async fn carrier_method_post_and_put_reuse_one_private_http_connection() {
    for carrier in [WebCarrier::Https, WebCarrier::HttpsLanes] {
        let capability = [64; 32];
        let mut config = runtime_config(capability, carrier);
        config.web.timeouts.long_poll_secs = 0;
        config.web.limits.max_streams_global = 0;
        let generation = test_runtime_generation(1, config);
        let runtime = WebProcessRuntime::start(Arc::new(ArcSwap::from(Arc::clone(&generation))));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let token = session_token(&listener, &runtime, capability, "/").await;
        let (mut client, cancellation, task) = open_keepalive(&listener, &runtime).await;
        let lane = if carrier.uses_lanes() {
            "X-Lane-ID: 7\r\n"
        } else {
            ""
        };
        let open = frame::encode(FrameType::Open, 7, &[]);
        let close = frame::encode(FrameType::Close, 7, &[]);
        for verb in ["POST", "PUT", "PUT", "POST"] {
            for (path, headers, body, ack_header) in [
                (
                    "/api/v1/up",
                    format!("Content-Type: application/octet-stream\r\nX-Up-Seq: 1\r\n{lane}"),
                    open.as_ref(),
                    "x-up-ack",
                ),
                (
                    "/api/v1/down",
                    format!("X-Down-Cursor: 0\r\n{lane}"),
                    &[][..],
                    "x-down-cursor",
                ),
            ] {
                let bytes = carrier_request(verb, path, &token, &headers, body);
                let bytes = String::from_utf8(bytes)
                    .unwrap()
                    .replace("Connection: close\r\n", "Connection: keep-alive\r\n")
                    .into_bytes();
                client.write_all(&bytes).await.unwrap();
                let response = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    read_http_response(&mut client),
                )
                .await
                .unwrap();
                let (headers, body) = split_response(&response);
                assert_eq!(response_header(headers, ack_header), "1");
                assert!(
                    !std::str::from_utf8(headers)
                        .unwrap()
                        .to_ascii_lowercase()
                        .contains("connection: close")
                );
                if path.ends_with("/up") {
                    assert!(headers.starts_with(b"HTTP/1.1 204"));
                    assert!(body.is_empty());
                } else {
                    assert!(headers.starts_with(b"HTTP/1.1 200"));
                    assert_eq!(
                        response_header(headers, "content-length"),
                        close.len().to_string()
                    );
                    assert_eq!(body, close);
                }
            }
        }
        cancellation.cancel();
        task.await.unwrap();
        runtime.shutdown().await;
        generation.stop_sessions().await;
        generation.stop_background_tasks().await;
    }
}

#[tokio::test]
async fn carrier_method_reload_preserves_old_pages_bootstraps_sessions_and_recovery() {
    for carrier in [WebCarrier::Https, WebCarrier::HttpsLanes] {
        let capability = [65; 32];
        let mut config = runtime_config(capability, carrier);
        config.web.limits.max_bootstraps_per_ip = 6;
        let generation = test_runtime_generation(1, config.clone());
        let active_runtime = Arc::new(ArcSwap::from(Arc::clone(&generation)));
        let runtime = WebProcessRuntime::start(Arc::clone(&active_runtime));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let post_page = bridge_page(&listener, &runtime, capability, "/").await;
        let old_session =
            create_session(&listener, &runtime, bootstrap_from(&post_page), "/").await;
        let unused_post_page = bridge_page(&listener, &runtime, capability, "/").await;
        config.web.carrier_method = WebCarrierMethod::Put;
        let put_generation = test_runtime_generation(2, config.clone());
        active_runtime.store(Arc::clone(&put_generation));
        let post_session =
            create_session(&listener, &runtime, bootstrap_from(&unused_post_page), "/").await;
        let put_page = bridge_page(&listener, &runtime, capability, "/").await;
        assert!(String::from_utf8_lossy(&put_page).contains("const carrierMethod='PUT';"));
        config.web.carrier_method = WebCarrierMethod::Post;
        let rollback_generation = test_runtime_generation(3, config);
        active_runtime.store(Arc::clone(&rollback_generation));
        let put_session = create_session(&listener, &runtime, bootstrap_from(&put_page), "/").await;
        let rollback_page = bridge_page(&listener, &runtime, capability, "/").await;
        assert!(String::from_utf8_lossy(&rollback_page).contains("const carrierMethod='POST';"));
        assert!(String::from_utf8_lossy(&post_page).contains("const carrierMethod='POST';"));
        let lane = if carrier.uses_lanes() {
            "X-Lane-ID: 0\r\n"
        } else {
            ""
        };
        let headers = format!("Content-Type: application/octet-stream\r\nX-Up-Seq: 1\r\n{lane}");
        let pong = frame::encode(FrameType::Pong, 0, &[]);
        for token in [&old_session, &post_session, &put_session] {
            for verb in ["PUT", "POST"] {
                let bytes = carrier_request(verb, "/api/v1/up", token, &headers, &pong);
                let response = request(&listener, &runtime, bytes).await;
                assert!(response.starts_with(b"HTTP/1.1 204"));
            }
        }
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(capability);
        let bytes = carrier_request(
            "GET",
            &format!("/?bridge={encoded}"),
            &put_session,
            "Accept: application/vnd.telemt.web-recovery+json\r\n",
            &[],
        );
        let recovery = request(&listener, &runtime, bytes).await;
        let (recovery_headers, body) = split_response(&recovery);
        assert!(recovery_headers.starts_with(b"HTTP/1.1 200"));
        assert_eq!(
            response_header(recovery_headers, "content-type"),
            "application/vnd.telemt.web-recovery+json"
        );
        let document: serde_json::Value = serde_json::from_slice(body).unwrap();
        let keys: std::collections::BTreeSet<_> = document
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            keys,
            ["v", "bootstrap", "limits", "timeouts", "negotiation"]
                .into_iter()
                .collect()
        );
        let bootstrap = document["bootstrap"].as_str().unwrap();
        let recovered = create_session(&listener, &runtime, bootstrap, "/").await;
        let bytes = carrier_request("PUT", "/api/v1/up", &recovered, &headers, &pong);
        let response = request(&listener, &runtime, bytes).await;
        assert!(response.starts_with(b"HTTP/1.1 204"));
        let bytes = carrier_request("PUT", "/api/v1/up", &put_session, &headers, &pong);
        let retired = request(&listener, &runtime, bytes).await;
        assert_private_decoy(&retired);
        runtime.shutdown().await;
        for generation in [generation, put_generation, rollback_generation] {
            generation.stop_sessions().await;
            generation.stop_background_tasks().await;
        }
    }
}
