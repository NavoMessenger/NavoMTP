use std::collections::BTreeMap;
use std::sync::Arc;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::header::{self, HeaderValue};
use hyper::{Response, StatusCode};
use tokio::sync::OwnedSemaphorePermit;

use crate::config::WebDebugConfig;
use crate::web::trace::{StoredTraceRecord, TraceRecord, TraceRecordKind, WebTraceStore};

const MAX_PAGE_BYTES: usize = 8 * 1024 * 1024;
const MAX_GROUPS: usize = 1024;

// Record-detail rendering remains isolated from filtering and page layout.
mod details;
// Query parsing and matching remain independent from bounded HTML rendering.
mod query;

use details::{push_body, push_frames, push_headers, push_lifecycle};
use query::{GroupBy, StatusQuery, client_ip, parse_query, record_matches};

struct GroupSummary {
    count: usize,
    latest_seq: u64,
}

struct RenderedPage {
    html: String,
    _permit: OwnedSemaphorePermit,
}

impl AsRef<[u8]> for RenderedPage {
    fn as_ref(&self) -> &[u8] {
        self.html.as_bytes()
    }
}

/// Renders the authenticated server-side WEB debugging table.
pub(super) async fn render(
    raw_query: Option<&str>,
    store: &Arc<WebTraceStore>,
) -> Response<Full<Bytes>> {
    let status = store.status();
    let query = match parse_query(raw_query, &status.policy) {
        Ok(query) => query,
        Err(error) => return html_error(StatusCode::BAD_REQUEST, "Invalid query", &error),
    };
    let Some(render_permit) = store.try_render_permit() else {
        return html_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Renderer busy",
            "Two WEB status pages are already rendering",
        );
    };
    let now_millis = crate::web::trace::store_epoch_millis();
    let since_millis = if query.record.is_none() {
        now_millis.saturating_sub(query.window_secs.saturating_mul(1000))
    } else {
        0
    };
    let records = store.snapshot_matching(|record| record_matches(record, &query, since_millis));
    let mut html = String::with_capacity(MAX_PAGE_BYTES);
    push_page_start(&mut html);
    html.push_str("<h1>WEB status</h1>");
    push_filter_form(&mut html, &query);
    html.push_str("<section><h2>Store</h2><table><tbody>");
    summary_row(&mut html, "debug enabled", yes_no(status.policy.enabled));
    summary_row(
        &mut html,
        "sideband",
        yes_no(status.policy.bridge_diagnostics_enabled()),
    );
    summary_row(&mut html, "body capture", body_mode(&status.policy));
    summary_row(&mut html, "window seconds", &query.window_secs.to_string());
    summary_row(
        &mut html,
        "records",
        &format!("{} / {}", status.records, status.records_capacity),
    );
    summary_row(
        &mut html,
        "bytes",
        &format!("{} / {}", status.used_bytes, status.bytes_capacity),
    );
    summary_row(&mut html, "matched", &records.len().to_string());
    summary_row(
        &mut html,
        "contention drops",
        &status.contention_drops.to_string(),
    );
    summary_row(&mut html, "evictions", &status.evictions.to_string());
    summary_row(
        &mut html,
        "byte truncations",
        &status.byte_truncations.to_string(),
    );
    summary_row(
        &mut html,
        "sequence range",
        &format!(
            "{} .. {}",
            option_u64(status.earliest_seq),
            option_u64(status.latest_seq)
        ),
    );
    html.push_str("</tbody></table></section>");
    if !query.group_by.is_empty() {
        push_groups(&mut html, &records, &query.group_by);
    }
    push_records(&mut html, &records, &query);
    html.push_str("</main></body></html>");
    truncate_page(&mut html);
    retained_html_response(StatusCode::OK, html, render_permit)
}

fn push_page_start(html: &mut String) {
    html.push_str("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>WEB status</title><style>body{font:14px system-ui,sans-serif;margin:0;background:#f5f7fa;color:#17202a}main{max-width:1600px;margin:auto;padding:20px}h1,h2{margin:.4em 0}section{background:#fff;border:1px solid #d9e0e7;border-radius:8px;padding:12px;margin:12px 0;overflow:auto}form{display:flex;flex-wrap:wrap;gap:8px;align-items:end}label{display:grid;gap:3px}input,select,button{font:inherit;padding:5px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #d9e0e7;padding:5px;text-align:left;vertical-align:top}th{background:#edf2f7;position:sticky;top:0}code,pre{font:12px ui-monospace,monospace;white-space:pre-wrap;overflow-wrap:anywhere}details{max-width:900px}.muted{color:#657786}.bad{color:#a00}</style></head><body><main>");
}

fn push_filter_form(html: &mut String, query: &StatusQuery) {
    html.push_str("<section><h2>Filters</h2><form method=\"get\" action=\"/web-status\">");
    input(html, "window_secs", &query.window_secs.to_string());
    input(
        html,
        "ip",
        &query.ip.map(|value| value.to_string()).unwrap_or_default(),
    );
    input(
        html,
        "session",
        &query
            .session
            .map(|value| value.to_string())
            .unwrap_or_default(),
    );
    input(
        html,
        "user_agent",
        query.user_agent.as_deref().unwrap_or_default(),
    );
    input(html, "key", query.key.as_deref().unwrap_or_default());
    input(html, "limit", &query.limit.to_string());
    html.push_str("<label>group_by<select name=\"group_by\" multiple size=\"4\">");
    for group in [
        GroupBy::Ip,
        GroupBy::Session,
        GroupBy::UserAgent,
        GroupBy::Key,
    ] {
        html.push_str("<option value=\"");
        html.push_str(group.as_str());
        if query.group_by.contains(&group) {
            html.push_str("\" selected>");
        } else {
            html.push_str("\">");
        }
        html.push_str(group.as_str());
        html.push_str("</option>");
    }
    html.push_str("</select></label><button type=\"submit\">Observe</button></form></section>");
}

fn input(html: &mut String, name: &str, value: &str) {
    html.push_str("<label>");
    escape(html, name);
    html.push_str("<input name=\"");
    escape(html, name);
    html.push_str("\" value=\"");
    escape(html, value);
    html.push_str("\"></label>");
}

fn summary_row(html: &mut String, name: &str, value: &str) {
    html.push_str("<tr><th>");
    escape(html, name);
    html.push_str("</th><td>");
    escape(html, value);
    html.push_str("</td></tr>");
}

fn push_groups(html: &mut String, records: &[Arc<StoredTraceRecord>], groups: &[GroupBy]) {
    let mut summaries = BTreeMap::<Vec<String>, GroupSummary>::new();
    let mut overflow = 0usize;
    for stored in records {
        let values = groups
            .iter()
            .map(|group| group_value(&stored.record, *group))
            .collect::<Vec<_>>();
        if let Some(summary) = summaries.get_mut(&values) {
            summary.count += 1;
            summary.latest_seq = summary.latest_seq.max(stored.record.seq);
        } else if summaries.len() < MAX_GROUPS {
            summaries.insert(
                values,
                GroupSummary {
                    count: 1,
                    latest_seq: stored.record.seq,
                },
            );
        } else {
            overflow += 1;
        }
    }
    let mut summaries = summaries.into_iter().collect::<Vec<_>>();
    summaries.sort_by(|(left_values, left), (right_values, right)| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left_values.cmp(right_values))
    });
    html.push_str("<section><h2>Groups</h2><table><thead><tr>");
    for group in groups {
        html.push_str("<th>");
        html.push_str(group.as_str());
        html.push_str("</th>");
    }
    html.push_str("<th>records</th><th>latest seq</th></tr></thead><tbody>");
    for (values, summary) in summaries {
        html.push_str("<tr>");
        for value in values {
            html.push_str("<td>");
            escape(html, &value);
            html.push_str("</td>");
        }
        html.push_str("<td>");
        html.push_str(&summary.count.to_string());
        html.push_str("</td><td>");
        html.push_str(&summary.latest_seq.to_string());
        html.push_str("</td></tr>");
        if html.len() >= MAX_PAGE_BYTES / 2 {
            break;
        }
    }
    if overflow != 0 {
        html.push_str("<tr><td colspan=\"6\" class=\"muted\">Additional groups omitted: ");
        html.push_str(&overflow.to_string());
        html.push_str("</td></tr>");
    }
    html.push_str("</tbody></table></section>");
}

fn group_value(record: &TraceRecord, group: GroupBy) -> String {
    match group {
        GroupBy::Ip => client_ip(record).map(|value| value.to_string()),
        GroupBy::Session => record.identity.session_id.map(|value| value.to_string()),
        GroupBy::UserAgent => record.user_agent.clone(),
        GroupBy::Key => record.identity.key_fingerprint.clone(),
    }
    .unwrap_or_else(|| "-".to_string())
}

fn push_records(html: &mut String, records: &[Arc<StoredTraceRecord>], query: &StatusQuery) {
    html.push_str("<section><h2>Records</h2><table><thead><tr><th>seq</th><th>time</th><th>kind</th><th>route/event</th><th>method</th><th>status</th><th>IP</th><th>session</th><th>user / key</th><th>User-Agent</th><th>details</th></tr></thead><tbody>");
    let mut shown = 0usize;
    for stored in records.iter().take(query.limit) {
        if html.len() >= MAX_PAGE_BYTES.saturating_sub(64 * 1024) {
            break;
        }
        push_record(html, &stored.record);
        shown += 1;
    }
    if shown == 0 {
        html.push_str("<tr><td colspan=\"11\" class=\"muted\">No matching records</td></tr>");
    }
    html.push_str("</tbody></table>");
    if records.len() > shown && shown != 0 {
        let before = records[shown - 1].record.seq;
        html.push_str("<p><a href=\"");
        escape(html, &pagination_url(query, before));
        html.push_str("\">Next page</a></p>");
    }
    html.push_str("</section>");
}

fn push_record(html: &mut String, record: &TraceRecord) {
    html.push_str("<tr><td><a href=\"/web-status?record=");
    html.push_str(&record.seq.to_string());
    html.push_str("\">");
    html.push_str(&record.seq.to_string());
    html.push_str("</a></td><td>");
    escape(html, &format_time(record.epoch_millis));
    let (kind, route, method, status) = match &record.kind {
        TraceRecordKind::Http(http) => (
            "http",
            http.route.as_str(),
            http.method.as_str(),
            http.status
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string()),
        ),
        TraceRecordKind::Websocket(message) => (
            "websocket",
            message.direction.as_str(),
            message.message_type,
            message.payload_bytes.to_string(),
        ),
        TraceRecordKind::Lifecycle(event) => (
            "lifecycle",
            event.event.as_str(),
            "-",
            event.reason.unwrap_or("-").to_string(),
        ),
    };
    for value in [kind, route, method, status.as_str()] {
        html.push_str("</td><td>");
        escape(html, value);
    }
    html.push_str("</td><td>");
    escape(
        html,
        &client_ip(record)
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string()),
    );
    html.push_str("</td><td>");
    escape(html, &option_u64(record.identity.session_id));
    html.push_str("</td><td>");
    escape(html, record.identity.user.as_deref().unwrap_or("-"));
    html.push_str(" / ");
    escape(
        html,
        record.identity.key_fingerprint.as_deref().unwrap_or("-"),
    );
    html.push_str("</td><td>");
    escape(html, record.user_agent.as_deref().unwrap_or("-"));
    html.push_str("</td><td><details><summary>request → response</summary>");
    match &record.kind {
        TraceRecordKind::Http(http) => {
            html.push_str("<p><code>");
            escape(html, &http.method);
            html.push(' ');
            escape(html, &http.path);
            html.push_str("</code></p>");
            push_headers(html, "request headers", &http.request_headers);
            push_body(html, "request body", http.request_body.as_ref());
            push_headers(html, "response headers", &http.response_headers);
            push_body(html, "response body", http.response_body.as_ref());
            if let Some(timings) = &http.timings {
                html.push_str("<h3>timings</h3><pre>service/head accepted: 0 us\nrequest body: ");
                html.push_str(&option_u64(timings.request_body_us));
                html.push_str(" us\nresponse ready: ");
                html.push_str(&option_u64(timings.response_ready_us));
                html.push_str(" us\nresponse body consumed/polled: ");
                html.push_str(&option_u64(timings.response_body_us));
                html.push_str(" us\n(kernel flush and TCP ACK are not observed)</pre>");
            }
            push_frames(html, &http.frames);
        }
        TraceRecordKind::Websocket(message) => {
            html.push_str("<pre>connection: ");
            html.push_str(&message.connection_id.to_string());
            html.push_str("\nlane: ");
            html.push_str(
                &message
                    .lane_id
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "-".to_string()),
            );
            html.push_str("\ndirection: ");
            html.push_str(message.direction.as_str());
            html.push_str("\nmessage: ");
            html.push_str(message.message_type);
            html.push_str("\npayload bytes: ");
            html.push_str(&message.payload_bytes.to_string());
            html.push_str("\nduration: ");
            html.push_str(&option_u64(message.duration_us));
            html.push_str(" us</pre>");
            push_body(html, "message body", message.body.as_ref());
            push_frames(html, &message.frames);
        }
        TraceRecordKind::Lifecycle(event) => push_lifecycle(html, event),
    }
    html.push_str("</details></td></tr>");
}

fn pagination_url(query: &StatusQuery, before_seq: u64) -> String {
    let mut serializer = url::form_urlencoded::Serializer::new(String::from("/web-status?"));
    serializer.append_pair("window_secs", &query.window_secs.to_string());
    if let Some(ip) = query.ip {
        serializer.append_pair("ip", &ip.to_string());
    }
    if let Some(session) = query.session {
        serializer.append_pair("session", &session.to_string());
    }
    if let Some(user_agent) = &query.user_agent {
        serializer.append_pair("user_agent", user_agent);
    }
    if let Some(key) = &query.key {
        serializer.append_pair("key", key);
    }
    for group in &query.group_by {
        serializer.append_pair("group_by", group.as_str());
    }
    serializer.append_pair("limit", &query.limit.to_string());
    serializer.append_pair("before_seq", &before_seq.to_string());
    serializer.finish()
}

fn format_time(epoch_millis: u64) -> String {
    chrono::DateTime::from_timestamp_millis(epoch_millis as i64)
        .map(|value| value.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
        .unwrap_or_else(|| epoch_millis.to_string())
}

fn option_u64(value: Option<u64>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "-".to_string())
}

fn body_mode(policy: &WebDebugConfig) -> &'static str {
    match policy.body_capture {
        crate::config::WebDebugBodyCapture::Off => "off",
        crate::config::WebDebugBodyCapture::Metadata => "metadata",
        crate::config::WebDebugBodyCapture::Prefix => "prefix",
        crate::config::WebDebugBodyCapture::Full => "full",
    }
}

fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

fn escape(output: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '&' => output.push_str("&amp;"),
            '<' => output.push_str("&lt;"),
            '>' => output.push_str("&gt;"),
            '"' => output.push_str("&quot;"),
            '\'' => output.push_str("&#39;"),
            _ => output.push(character),
        }
    }
}

fn truncate_page(html: &mut String) {
    const SUFFIX: &str = "[page output truncated]";
    if html.len() <= MAX_PAGE_BYTES {
        return;
    }
    let mut end = MAX_PAGE_BYTES.saturating_sub(SUFFIX.len());
    while !html.is_char_boundary(end) {
        end -= 1;
    }
    html.truncate(end);
    html.push_str(SUFFIX);
}

fn html_error(status: StatusCode, title: &str, message: &str) -> Response<Full<Bytes>> {
    let mut html = String::new();
    push_page_start(&mut html);
    html.push_str("<h1 class=\"bad\">");
    escape(&mut html, title);
    html.push_str("</h1><p>");
    escape(&mut html, message);
    html.push_str("</p></main></body></html>");
    html_response(status, html)
}

fn html_response(status: StatusCode, html: String) -> Response<Full<Bytes>> {
    html_bytes_response(status, Bytes::from(html))
}

fn retained_html_response(
    status: StatusCode,
    html: String,
    permit: OwnedSemaphorePermit,
) -> Response<Full<Bytes>> {
    html_bytes_response(
        status,
        Bytes::from_owner(RenderedPage {
            html,
            _permit: permit,
        }),
    )
}

fn html_bytes_response(status: StatusCode, html: Bytes) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(html));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"),
    );
    response.headers_mut().insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response.headers_mut().insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
        .headers_mut()
        .insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    response
}

#[cfg(test)]
#[path = "web_status/tests.rs"]
mod tests;
