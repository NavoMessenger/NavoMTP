use std::collections::BTreeSet;
use std::net::IpAddr;

use crate::config::WebDebugConfig;
use crate::web::trace::TraceRecord;

const DEFAULT_LIMIT: usize = 200;
const MAX_LIMIT: usize = 1000;

/// Supported status-page grouping dimensions.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum GroupBy {
    Ip,
    Session,
    UserAgent,
    Key,
}

impl GroupBy {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "ip" => Some(Self::Ip),
            "session" => Some(Self::Session),
            "user_agent" => Some(Self::UserAgent),
            "key" => Some(Self::Key),
            _ => None,
        }
    }

    /// Returns the canonical query and table label.
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Session => "session",
            Self::UserAgent => "user_agent",
            Self::Key => "key",
        }
    }
}

/// Validated bounded status-page filter and pagination state.
pub(super) struct StatusQuery {
    pub(super) window_secs: u64,
    pub(super) ip: Option<IpAddr>,
    pub(super) session: Option<u64>,
    pub(super) user_agent: Option<String>,
    pub(super) key: Option<String>,
    pub(super) group_by: Vec<GroupBy>,
    pub(super) limit: usize,
    pub(super) before_seq: Option<u64>,
    pub(super) record: Option<u64>,
}

/// Parses a strict query without accepting unknown or ambiguous fields.
pub(super) fn parse_query(
    raw: Option<&str>,
    policy: &WebDebugConfig,
) -> Result<StatusQuery, String> {
    let mut query = StatusQuery {
        window_secs: policy.default_window_secs,
        ip: None,
        session: None,
        user_agent: None,
        key: None,
        group_by: Vec::new(),
        limit: DEFAULT_LIMIT,
        before_seq: None,
        record: None,
    };
    let mut seen = BTreeSet::new();
    for (name, value) in url::form_urlencoded::parse(raw.unwrap_or_default().as_bytes()) {
        let name = name.as_ref();
        let value = value.as_ref();
        if name != "group_by" && !seen.insert(name.to_string()) {
            return Err(format!("{name} must not repeat"));
        }
        match name {
            "window_secs" => {
                query.window_secs = parse_positive_u64(value, "window_secs")?;
            }
            "ip" => {
                let parsed = value
                    .parse::<IpAddr>()
                    .map_err(|_| "ip must be a canonical IP address".to_string())?;
                if parsed.to_string() != value {
                    return Err("ip must use canonical formatting".to_string());
                }
                query.ip = Some(parsed);
            }
            "session" => query.session = Some(parse_positive_u64(value, "session")?),
            "user_agent" => {
                if value.is_empty() || value.len() > 512 {
                    return Err("user_agent must contain 1..512 bytes".to_string());
                }
                query.user_agent = Some(value.to_string());
            }
            "key" => {
                if value.is_empty() || value.len() > 64 {
                    return Err("key must contain 1..64 bytes".to_string());
                }
                query.key = Some(value.to_string());
            }
            "group_by" => {
                let group = GroupBy::parse(value).ok_or_else(|| {
                    "group_by must be ip, session, user_agent, or key".to_string()
                })?;
                if query.group_by.contains(&group) {
                    return Err("group_by values must not repeat".to_string());
                }
                query.group_by.push(group);
            }
            "limit" => {
                query.limit = value
                    .parse::<usize>()
                    .ok()
                    .filter(|value| (1..=MAX_LIMIT).contains(value))
                    .ok_or_else(|| "limit must be within 1..1000".to_string())?;
            }
            "before_seq" => {
                query.before_seq = Some(parse_positive_u64(value, "before_seq")?);
            }
            "record" => query.record = Some(parse_positive_u64(value, "record")?),
            _ => return Err(format!("unknown query field `{name}`")),
        }
    }
    if query.window_secs > policy.max_window_secs {
        return Err(format!(
            "window_secs must not exceed {}",
            policy.max_window_secs
        ));
    }
    Ok(query)
}

fn parse_positive_u64(value: &str, field: &str) -> Result<u64, String> {
    value
        .parse::<u64>()
        .ok()
        .filter(|value| *value != 0)
        .ok_or_else(|| format!("{field} must be a positive integer"))
}

/// Applies the complete filter predicate to one immutable record.
pub(super) fn record_matches(record: &TraceRecord, query: &StatusQuery, since_millis: u64) -> bool {
    !(record.epoch_millis < since_millis
        || query.before_seq.is_some_and(|before| record.seq >= before)
        || query.record.is_some_and(|seq| record.seq != seq)
        || query.ip.is_some_and(|ip| client_ip(record) != Some(ip))
        || query
            .session
            .is_some_and(|session| record.identity.session_id != Some(session))
        || query.user_agent.as_ref().is_some_and(|needle| {
            record
                .user_agent
                .as_deref()
                .is_none_or(|value| !contains_ascii_case_insensitive(value, needle))
        })
        || query.key.as_ref().is_some_and(|key| {
            record.identity.user.as_deref() != Some(key)
                && record.identity.key_fingerprint.as_deref() != Some(key)
        }))
}

fn contains_ascii_case_insensitive(value: &str, needle: &str) -> bool {
    let needle = needle.as_bytes();
    needle.is_empty()
        || value
            .as_bytes()
            .windows(needle.len())
            .any(|window| window.eq_ignore_ascii_case(needle))
}

/// Returns the trusted effective address or direct peer fallback.
pub(super) fn client_ip(record: &TraceRecord) -> Option<IpAddr> {
    record.effective_ip.or(record.peer_ip)
}
