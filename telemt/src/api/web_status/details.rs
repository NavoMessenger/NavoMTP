use base64::Engine as _;

use super::{MAX_PAGE_BYTES, escape, yes_no};

pub(super) fn push_frames(html: &mut String, frames: &[crate::web::trace::TraceFrame]) {
    if frames.is_empty() {
        return;
    }
    html.push_str("<h3>frames</h3><table><tr><th>dir</th><th>type</th><th>stream/lane</th><th>payload</th><th>WINDOW</th><th>error</th></tr>");
    for frame in frames {
        html.push_str("<tr>");
        for value in [
            frame.direction.as_str().to_string(),
            frame.frame_type.unwrap_or("-").to_string(),
            frame
                .stream_id
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string()),
            frame
                .payload_len
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string()),
            frame
                .window_delta
                .map(|value| value.to_string())
                .unwrap_or_else(|| "-".to_string()),
            frame.parse_error.unwrap_or("-").to_string(),
        ] {
            html.push_str("<td>");
            escape(html, &value);
            html.push_str("</td>");
        }
        html.push_str("</tr>");
    }
    html.push_str("</table>");
}

pub(super) fn push_headers(
    html: &mut String,
    title: &str,
    headers: &[crate::web::trace::TraceHeader],
) {
    html.push_str("<h3>");
    escape(html, title);
    html.push_str("</h3><pre>");
    for header in headers {
        escape(html, &header.name);
        html.push_str(": ");
        escape(html, header.value.as_deref().unwrap_or("[value omitted]"));
        html.push('\n');
    }
    html.push_str("</pre>");
}

pub(super) fn push_body(
    html: &mut String,
    title: &str,
    body: Option<&crate::web::trace::TraceBodySnapshot>,
) {
    html.push_str("<h3>");
    escape(html, title);
    html.push_str("</h3>");
    let Some(body) = body else {
        html.push_str("<p class=\"muted\">capture off</p>");
        return;
    };
    html.push_str("<p>observed=");
    html.push_str(&body.observed_bytes.to_string());
    html.push_str(" captured=");
    html.push_str(&body.captured.len().to_string());
    html.push_str(" state=");
    html.push_str(body.state.as_str());
    html.push_str(" truncated=");
    html.push_str(yes_no(body.truncated));
    html.push_str("</p><pre>");
    let available = MAX_PAGE_BYTES
        .saturating_sub(html.len())
        .saturating_sub(4096);
    let raw_limit = available.saturating_mul(3) / 4;
    let shown = body.captured.len().min(raw_limit);
    base64::engine::general_purpose::STANDARD.encode_string(&body.captured[..shown], html);
    if shown < body.captured.len() {
        html.push_str("\n[page output truncated]");
    }
    html.push_str("</pre>");
}

pub(super) fn push_lifecycle(html: &mut String, event: &crate::web::trace::TraceLifecycleRecord) {
    html.push_str("<pre>event: ");
    html.push_str(event.event.as_str());
    html.push_str("\nstream: ");
    html.push_str(
        &event
            .stream_id
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string()),
    );
    html.push_str("\nreason: ");
    html.push_str(event.reason.unwrap_or("-"));
    html.push_str("\npeer gap ms: ");
    html.push_str(
        &event
            .peer_gap_ms
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string()),
    );
    html.push_str("\npredecessor session: ");
    html.push_str(
        &event
            .predecessor_session_id
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string()),
    );
    if let Some(carrier) = &event.carrier {
        html.push_str("\nclient class: ");
        html.push_str(carrier.client_class);
        html.push_str("\ncarrier: ");
        html.push_str(carrier.carrier.as_str());
        html.push_str("\nattempt: ");
        html.push_str(&carrier.attempt.to_string());
        html.push_str("\nscores: https=");
        html.push_str(&carrier.scores[0].to_string());
        html.push_str(" https-lanes=");
        html.push_str(&carrier.scores[1].to_string());
        html.push_str(" websocket=");
        html.push_str(&carrier.scores[2].to_string());
        html.push_str(" websocket-lanes=");
        html.push_str(&carrier.scores[3].to_string());
    }
    html.push_str("</pre>");
}
