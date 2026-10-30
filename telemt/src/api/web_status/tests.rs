use http_body_util::BodyExt as _;

use super::*;
use crate::web::trace::{TraceIdentity, TraceLifecycleEvent};

#[test]
fn query_rejects_noncanonical_ip_and_excessive_window() {
    let policy = WebDebugConfig::default();
    assert!(parse_query(Some("ip=2001%3A0db8%3A%3A1"), &policy).is_err());
    assert!(parse_query(Some("window_secs=3601"), &policy).is_err());
    assert!(parse_query(Some("session=1&session=2"), &policy).is_err());
}

#[test]
fn html_escaping_covers_active_markup_characters() {
    let mut output = String::new();
    escape(&mut output, "<script a='\"'>&");
    assert_eq!(output, "&lt;script a=&#39;&quot;&#39;&gt;&amp;");
}

#[tokio::test]
async fn renderer_filters_groups_and_sets_control_plane_security_headers() {
    let policy = WebDebugConfig {
        enabled: true,
        sideband: true,
        ..Default::default()
    };
    let limits = crate::config::WebLimitsConfig {
        debug_records_capacity: 8,
        debug_bytes_global: 16 * 1024,
        ..Default::default()
    };
    let store = WebTraceStore::new(policy.clone(), &limits);
    store.record_lifecycle(
        None,
        Some("192.0.2.40".parse().unwrap()),
        TraceIdentity {
            session_id: Some(42),
            user: Some("alice".to_string()),
            key_fingerprint: Some("0123456789abcdef".to_string()),
        },
        TraceLifecycleEvent::SessionCreated,
        None,
        None,
    );

    let response = render(
        Some("ip=192.0.2.40&session=42&key=0123456789abcdef&group_by=ip&group_by=key"),
        &store,
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert!(
        response
            .headers()
            .contains_key(header::CONTENT_SECURITY_POLICY)
    );
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body = std::str::from_utf8(&body).unwrap();
    assert!(body.contains("session_created"));
    assert!(body.contains("<th>sideband</th><td>yes</td>"));
    assert!(body.contains("0123456789abcdef"));
    assert!(body.contains("192.0.2.40"));
}

#[tokio::test]
async fn render_permits_remain_owned_by_inflight_response_bodies() {
    let policy = WebDebugConfig::default();
    let limits = crate::config::WebLimitsConfig::default();
    let store = WebTraceStore::new(policy.clone(), &limits);

    let first = render(None, &store).await;
    let second = render(None, &store).await;
    let busy = render(None, &store).await;
    assert_eq!(busy.status(), StatusCode::SERVICE_UNAVAILABLE);

    drop(first);
    let admitted = render(None, &store).await;
    assert_eq!(admitted.status(), StatusCode::OK);
    drop(second);
    drop(admitted);
}

#[tokio::test]
async fn stale_renderer_cannot_restore_an_old_debug_policy() {
    let stale_policy = WebDebugConfig::default();
    let active_policy = WebDebugConfig {
        enabled: true,
        capture_headers: false,
        ..Default::default()
    };
    let limits = crate::config::WebLimitsConfig::default();
    let store = WebTraceStore::new(stale_policy.clone(), &limits);
    store.apply_policy(2, &active_policy);

    let response = render(None, &store).await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(store.status().policy.as_ref(), &active_policy);
}

#[test]
fn page_truncation_preserves_utf8_boundary_and_cap() {
    let mut html = "\u{044f}".repeat(MAX_PAGE_BYTES);
    truncate_page(&mut html);
    assert!(html.len() <= MAX_PAGE_BYTES);
    assert!(html.ends_with("[page output truncated]"));
}
