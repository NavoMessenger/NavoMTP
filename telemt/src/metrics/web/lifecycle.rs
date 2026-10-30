use std::fmt::Write;

use crate::config::{ProxyConfig, WebCarrier};
use crate::web::control::WebRuntimePublication;
use crate::web::session::SessionCloseReason;
use crate::web::telemetry::{WebBridgeRecoveryEvent, WebSessionLifecycleObservation};

pub(super) fn render(out: &mut String, publication: &WebRuntimePublication, config: &ProxyConfig) {
    let _ = writeln!(
        out,
        "# HELP telemt_web_session_closures_total Closed WEB session incarnations by carrier and terminal reason"
    );
    let _ = writeln!(out, "# TYPE telemt_web_session_closures_total counter");
    for carrier in WebCarrier::ALL {
        for reason in SessionCloseReason::ALL {
            let _ = writeln!(
                out,
                "telemt_web_session_closures_total{{carrier=\"{}\",reason=\"{}\"}} {}",
                carrier.as_str(),
                reason.as_str(),
                publication.telemetry.session_close_total(carrier, reason)
            );
        }
    }

    let _ = writeln!(
        out,
        "# HELP telemt_web_session_lifecycle_observations_total Authenticated WEB session lifecycle observations"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_web_session_lifecycle_observations_total counter"
    );
    for carrier in WebCarrier::ALL {
        for observation in WebSessionLifecycleObservation::ALL {
            let _ = writeln!(
                out,
                "telemt_web_session_lifecycle_observations_total{{carrier=\"{}\",observation=\"{}\"}} {}",
                carrier.as_str(),
                observation.as_str(),
                publication
                    .telemetry
                    .session_observation_total(carrier, observation)
            );
        }
    }

    let _ = writeln!(
        out,
        "# HELP telemt_web_bridge_recovery_events_total Server-observed bridge recovery milestones"
    );
    let _ = writeln!(
        out,
        "# TYPE telemt_web_bridge_recovery_events_total counter"
    );
    for event in WebBridgeRecoveryEvent::ALL {
        let _ = writeln!(
            out,
            "telemt_web_bridge_recovery_events_total{{event=\"{}\"}} {}",
            event.as_str(),
            publication.telemetry.bridge_recovery_total(event)
        );
    }

    let _ = writeln!(
        out,
        "# HELP telemt_web_bridge_recovery_seconds Effective bridge recovery deadline"
    );
    let _ = writeln!(out, "# TYPE telemt_web_bridge_recovery_seconds gauge");
    let _ = writeln!(
        out,
        "telemt_web_bridge_recovery_seconds {}",
        config.web.timeouts.bridge_recovery_secs
    );

    render_aggregates(out, publication);
}

fn render_aggregates(out: &mut String, publication: &WebRuntimePublication) {
    let totals = publication.telemetry.aggregates();
    let _ = writeln!(
        out,
        "# HELP telemt_web_session_incarnations_total Process-owned WEB session lifecycle totals"
    );
    let _ = writeln!(out, "# TYPE telemt_web_session_incarnations_total counter");
    let _ = writeln!(
        out,
        "telemt_web_session_incarnations_total{{event=\"created\"}} {}",
        totals.sessions_created
    );
    let _ = writeln!(
        out,
        "telemt_web_session_incarnations_total{{event=\"closed\"}} {}",
        totals.sessions_closed
    );
    let _ = writeln!(
        out,
        "# HELP telemt_web_streams_total Process-owned WEB logical stream totals"
    );
    let _ = writeln!(out, "# TYPE telemt_web_streams_total counter");
    let _ = writeln!(
        out,
        "telemt_web_streams_total{{event=\"opened\"}} {}",
        totals.streams_opened
    );
    let _ = writeln!(
        out,
        "telemt_web_streams_total{{event=\"rejected\"}} {}",
        totals.streams_rejected
    );
    let _ = writeln!(
        out,
        "# HELP telemt_web_carrier_bytes_total Process-owned WEB carrier payload bytes"
    );
    let _ = writeln!(out, "# TYPE telemt_web_carrier_bytes_total counter");
    let _ = writeln!(
        out,
        "telemt_web_carrier_bytes_total{{direction=\"up\"}} {}",
        totals.bytes_up
    );
    let _ = writeln!(
        out,
        "telemt_web_carrier_bytes_total{{direction=\"down\"}} {}",
        totals.bytes_down
    );
}
