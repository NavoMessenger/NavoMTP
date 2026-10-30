use super::*;

// HTTP method compatibility keeps platform workarounds outside session state.
#[path = "carrier_method_tests.rs"]
mod carrier_method_tests;

#[tokio::test]
async fn windows_restricted_webview_empty_cookie_preserves_the_carrier_flow() {
    for (index, carrier) in [WebCarrier::Https, WebCarrier::HttpsLanes]
        .into_iter()
        .enumerate()
    {
        let capability = [12 + index as u8; 32];
        let mut config = runtime_config(capability, carrier);
        config.web.timeouts.long_poll_secs = 0;
        let generation = test_runtime_generation(1, config);
        let active_runtime = Arc::new(ArcSwap::from(Arc::clone(&generation)));
        let runtime = WebProcessRuntime::start(active_runtime);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(capability);
        let root = format!(
            "GET /?bridge={encoded} HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nCookie:\r\nConnection: close\r\n\r\n"
        )
        .into_bytes();
        let root_response = request(&listener, &runtime, root).await;
        let (root_headers, root_body) = split_response(&root_response);
        assert!(root_headers.starts_with(b"HTTP/1.1 200"));
        let root_body = std::str::from_utf8(root_body).unwrap();
        let bootstrap = root_body
            .split_once("bootstrap=\"")
            .and_then(|(_, suffix)| suffix.split_once('"'))
            .map(|(token, _)| token)
            .unwrap();

        let hello = frame::encode(FrameType::Hello, 0, &[1]);
        let create = |cookie: &str| {
            let mut request = format!(
                "POST /api/v1/session HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {bootstrap}\r\nContent-Type: application/octet-stream\r\n{cookie}Content-Length: {}\r\nConnection: close\r\n\r\n",
                hello.len()
            )
            .into_bytes();
            request.extend_from_slice(&hello);
            request
        };
        let nonempty_cookie =
            request(&listener, &runtime, create("Cookie: state=unexpected\r\n")).await;
        assert!(!nonempty_cookie.starts_with(b"HTTP/1.1 200"));
        let duplicate_cookie = request(
            &listener,
            &runtime,
            create("Cookie:\r\nCookie: state=unexpected\r\n"),
        )
        .await;
        assert!(!duplicate_cookie.starts_with(b"HTTP/1.1 200"));

        let create_response = request(&listener, &runtime, create("Cookie:\r\n")).await;
        let (create_headers, create_body) = split_response(&create_response);
        assert!(create_headers.starts_with(b"HTTP/1.1 200"));
        assert_eq!(
            response_header(create_headers, "x-carrier-mode"),
            carrier.as_str()
        );
        assert_eq!(create_body, frame::encode(FrameType::Welcome, 0, &[]));
        let session = response_header(create_headers, "x-session-token").to_string();
        let lane = if carrier == WebCarrier::HttpsLanes {
            "X-Lane-ID: 0\r\n"
        } else {
            ""
        };

        let pong = frame::encode(FrameType::Pong, 0, &[]);
        let mut uplink = format!(
            "POST /api/v1/up HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {session}\r\nContent-Type: application/octet-stream\r\nCookie:\r\nX-Up-Seq: 1\r\n{lane}Content-Length: {}\r\nConnection: close\r\n\r\n",
            pong.len()
        )
        .into_bytes();
        uplink.extend_from_slice(&pong);
        let uplink_response = request(&listener, &runtime, uplink).await;
        let (uplink_headers, _) = split_response(&uplink_response);
        assert!(uplink_headers.starts_with(b"HTTP/1.1 204"));
        assert_eq!(response_header(uplink_headers, "x-up-ack"), "1");

        let downlink = format!(
            "POST /api/v1/down HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {session}\r\nCookie:\r\nX-Down-Cursor: 0\r\n{lane}Content-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .into_bytes();
        let downlink_response = request(&listener, &runtime, downlink).await;
        let (downlink_headers, _) = split_response(&downlink_response);
        assert!(downlink_headers.starts_with(b"HTTP/1.1 204"));
        assert_eq!(response_header(downlink_headers, "x-down-cursor"), "0");

        let close = format!(
            "DELETE /api/v1/session HTTP/1.1\r\nHost: proxy.example.com\r\nX-Forwarded-For: 192.0.2.10\r\nAuthorization: Bearer {session}\r\nCookie:\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .into_bytes();
        let close_response = request(&listener, &runtime, close).await;
        assert!(close_response.starts_with(b"HTTP/1.1 204"));

        runtime.shutdown().await;
        generation.stop_sessions().await;
        generation.stop_background_tasks().await;
    }
}
