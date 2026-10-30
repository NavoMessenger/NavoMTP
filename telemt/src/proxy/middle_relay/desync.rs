use super::*;

#[derive(Default)]
pub(crate) struct DesyncDedupRotationState {
    current_started_at: Option<Instant>,
}

pub(in crate::proxy::middle_relay) struct RelayForensicsState {
    pub(in crate::proxy::middle_relay) trace_id: u64,
    pub(in crate::proxy::middle_relay) conn_id: u64,
    pub(in crate::proxy::middle_relay) user: String,
    pub(in crate::proxy::middle_relay) peer: SocketAddr,
    pub(in crate::proxy::middle_relay) peer_hash: u64,
    pub(in crate::proxy::middle_relay) started_at: Instant,
    pub(in crate::proxy::middle_relay) bytes_c2me: u64,
    pub(in crate::proxy::middle_relay) bytes_me2c: Arc<AtomicU64>,
    pub(in crate::proxy::middle_relay) desync_all_full: bool,
}

#[cfg(test)]
pub(crate) fn hash_value<T: Hash>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

fn hash_value_in<T: Hash>(shared: &ProxySharedState, value: &T) -> u64 {
    shared.middle_relay.desync_hasher.hash_one(value)
}

#[cfg(test)]
pub(crate) fn hash_ip(ip: IpAddr) -> u64 {
    hash_value(&ip)
}

pub(super) fn hash_ip_in(shared: &ProxySharedState, ip: IpAddr) -> u64 {
    hash_value_in(shared, &ip)
}

fn should_emit_full_desync_in(
    shared: &ProxySharedState,
    key: u64,
    all_full: bool,
    now: Instant,
) -> bool {
    if all_full {
        return true;
    }

    let dedup_current = &shared.middle_relay.desync_dedup;
    let dedup_previous = &shared.middle_relay.desync_dedup_previous;
    let rotation_state = &shared.middle_relay.desync_dedup_rotation_state;

    let mut state = match rotation_state.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            let mut guard = poisoned.into_inner();
            *guard = DesyncDedupRotationState::default();
            rotation_state.clear_poison();
            guard
        }
    };

    let rotate_now = match state.current_started_at {
        Some(current_started_at) => match now.checked_duration_since(current_started_at) {
            Some(elapsed) => elapsed >= DESYNC_DEDUP_WINDOW,
            None => true,
        },
        None => true,
    };
    if rotate_now {
        dedup_previous.clear();
        for entry in dedup_current.iter() {
            dedup_previous.insert(*entry.key(), *entry.value());
        }
        dedup_current.clear();
        state.current_started_at = Some(now);
    }

    if let Some(seen_at) = dedup_current.get(&key).map(|entry| *entry.value()) {
        let within_window = match now.checked_duration_since(seen_at) {
            Some(elapsed) => elapsed < DESYNC_DEDUP_WINDOW,
            None => true,
        };
        if within_window {
            return false;
        }
        dedup_current.insert(key, now);
        return true;
    }

    if let Some(seen_at) = dedup_previous.get(&key).map(|entry| *entry.value()) {
        let within_window = match now.checked_duration_since(seen_at) {
            Some(elapsed) => elapsed < DESYNC_DEDUP_WINDOW,
            None => true,
        };
        if within_window {
            dedup_current.insert(key, seen_at);
            return false;
        }
        dedup_previous.remove(&key);
    }

    if dedup_current.len() >= DESYNC_DEDUP_MAX_ENTRIES {
        dedup_previous.clear();
        for entry in dedup_current.iter() {
            dedup_previous.insert(*entry.key(), *entry.value());
        }
        dedup_current.clear();
        state.current_started_at = Some(now);
        dedup_current.insert(key, now);
        should_emit_full_desync_full_cache_in(shared, now)
    } else {
        dedup_current.insert(key, now);
        true
    }
}

fn should_emit_full_desync_full_cache_in(shared: &ProxySharedState, now: Instant) -> bool {
    let gate = &shared.middle_relay.desync_full_cache_last_emit_at;
    let Ok(mut last_emit_at) = gate.lock() else {
        return false;
    };

    match *last_emit_at {
        None => {
            *last_emit_at = Some(now);
            true
        }
        Some(last) => {
            let Some(elapsed) = now.checked_duration_since(last) else {
                *last_emit_at = Some(now);
                return true;
            };
            if elapsed >= DESYNC_FULL_CACHE_EMIT_MIN_INTERVAL {
                *last_emit_at = Some(now);
                true
            } else {
                false
            }
        }
    }
}

pub(crate) fn desync_forensics_len_bytes(len: usize) -> ([u8; 4], bool) {
    match u32::try_from(len) {
        Ok(value) => (value.to_le_bytes(), false),
        Err(_) => (u32::MAX.to_le_bytes(), true),
    }
}

pub(super) fn report_desync_frame_too_large_in(
    shared: &ProxySharedState,
    state: &RelayForensicsState,
    proto_tag: ProtoTag,
    frame_counter: u64,
    max_frame: usize,
    len: usize,
    raw_len_bytes: Option<[u8; 4]>,
    stats: &Stats,
) -> ProxyError {
    let (fallback_len_buf, len_buf_truncated) = desync_forensics_len_bytes(len);
    let len_buf = raw_len_bytes.unwrap_or(fallback_len_buf);
    let looks_like_tls = raw_len_bytes
        .map(|b| b[0] == 0x16 && b[1] == 0x03)
        .unwrap_or(false);
    let looks_like_http = raw_len_bytes
        .map(|b| matches!(b[0], b'G' | b'P' | b'H' | b'C' | b'D'))
        .unwrap_or(false);
    let now = Instant::now();
    let dedup_key = hash_value_in(
        shared,
        &(
            state.user.as_str(),
            state.peer_hash,
            proto_tag,
            DESYNC_ERROR_CLASS,
        ),
    );
    let emit_full = should_emit_full_desync_in(shared, dedup_key, state.desync_all_full, now);
    let duration_ms = state.started_at.elapsed().as_millis() as u64;
    let bytes_me2c = state.bytes_me2c.load(Ordering::Relaxed);

    stats.increment_desync_total();
    stats.increment_relay_protocol_desync_close_total();
    stats.observe_desync_frames_ok(frame_counter);
    if emit_full {
        stats.increment_desync_full_logged();
        warn!(
            trace_id = format_args!("0x{:016x}", state.trace_id),
            conn_id = state.conn_id,
            user = %state.user,
            peer_hash = format_args!("0x{:016x}", state.peer_hash),
            proto = ?proto_tag,
            mode = "middle_proxy",
            is_tls = true,
            duration_ms,
            bytes_c2me = state.bytes_c2me,
            bytes_me2c,
            raw_len = len,
            raw_len_hex = format_args!("0x{:08x}", len),
            raw_len_bytes_truncated = len_buf_truncated,
            raw_bytes = format_args!(
                "{:02x} {:02x} {:02x} {:02x}",
                len_buf[0], len_buf[1], len_buf[2], len_buf[3]
            ),
            max_frame,
            tls_like = looks_like_tls,
            http_like = looks_like_http,
            frames_ok = frame_counter,
            dedup_window_secs = DESYNC_DEDUP_WINDOW.as_secs(),
            desync_all_full = state.desync_all_full,
            full_reason = if state.desync_all_full { "desync_all_full" } else { "first_in_dedup_window" },
            error_class = DESYNC_ERROR_CLASS,
            "Frame too large — crypto desync forensics"
        );
        debug!(
            trace_id = format_args!("0x{:016x}", state.trace_id),
            conn_id = state.conn_id,
            user = %state.user,
            peer = %state.peer,
            "Frame too large forensic peer detail"
        );
    } else {
        stats.increment_desync_suppressed();
        debug!(
            trace_id = format_args!("0x{:016x}", state.trace_id),
            conn_id = state.conn_id,
            user = %state.user,
            peer_hash = format_args!("0x{:016x}", state.peer_hash),
            proto = ?proto_tag,
            duration_ms,
            bytes_c2me = state.bytes_c2me,
            bytes_me2c,
            raw_len = len,
            frames_ok = frame_counter,
            dedup_window_secs = DESYNC_DEDUP_WINDOW.as_secs(),
            error_class = DESYNC_ERROR_CLASS,
            "Frame too large — crypto desync forensic suppressed"
        );
    }

    ProxyError::Proxy(format!(
        "Frame too large: {len} (max {max_frame}), frames_ok={frame_counter}, conn_id={}, trace_id=0x{:016x}",
        state.conn_id, state.trace_id
    ))
}

#[cfg(test)]
pub(crate) fn report_desync_frame_too_large(
    state: &RelayForensicsState,
    proto_tag: ProtoTag,
    frame_counter: u64,
    max_frame: usize,
    len: usize,
    raw_len_bytes: Option<[u8; 4]>,
    stats: &Stats,
) -> ProxyError {
    let shared = ProxySharedState::new();
    report_desync_frame_too_large_in(
        shared.as_ref(),
        state,
        proto_tag,
        frame_counter,
        max_frame,
        len,
        raw_len_bytes,
        stats,
    )
}

#[cfg(test)]
pub(crate) fn should_emit_full_desync_for_testing(
    shared: &ProxySharedState,
    key: u64,
    all_full: bool,
    now: Instant,
) -> bool {
    if all_full {
        return true;
    }

    let dedup_current = &shared.middle_relay.desync_dedup;
    let dedup_previous = &shared.middle_relay.desync_dedup_previous;

    let Ok(mut state) = shared.middle_relay.desync_dedup_rotation_state.lock() else {
        return false;
    };

    let rotate_now = match state.current_started_at {
        Some(current_started_at) => match now.checked_duration_since(current_started_at) {
            Some(elapsed) => elapsed >= DESYNC_DEDUP_WINDOW,
            None => true,
        },
        None => true,
    };
    if rotate_now {
        dedup_previous.clear();
        for entry in dedup_current.iter() {
            dedup_previous.insert(*entry.key(), *entry.value());
        }
        dedup_current.clear();
        state.current_started_at = Some(now);
    }

    if let Some(seen_at) = dedup_current.get(&key).map(|entry| *entry.value()) {
        let within_window = match now.checked_duration_since(seen_at) {
            Some(elapsed) => elapsed < DESYNC_DEDUP_WINDOW,
            None => true,
        };
        if within_window {
            return false;
        }
        dedup_current.insert(key, now);
        return true;
    }

    if let Some(seen_at) = dedup_previous.get(&key).map(|entry| *entry.value()) {
        let within_window = match now.checked_duration_since(seen_at) {
            Some(elapsed) => elapsed < DESYNC_DEDUP_WINDOW,
            None => true,
        };
        if within_window {
            dedup_current.insert(key, seen_at);
            return false;
        }
        dedup_previous.remove(&key);
    }

    if dedup_current.len() >= DESYNC_DEDUP_MAX_ENTRIES {
        dedup_previous.clear();
        for entry in dedup_current.iter() {
            dedup_previous.insert(*entry.key(), *entry.value());
        }
        dedup_current.clear();
        state.current_started_at = Some(now);
        dedup_current.insert(key, now);
        let Ok(mut last_emit_at) = shared.middle_relay.desync_full_cache_last_emit_at.lock() else {
            return false;
        };
        return match *last_emit_at {
            None => {
                *last_emit_at = Some(now);
                true
            }
            Some(last) => {
                let Some(elapsed) = now.checked_duration_since(last) else {
                    *last_emit_at = Some(now);
                    return true;
                };
                if elapsed >= DESYNC_FULL_CACHE_EMIT_MIN_INTERVAL {
                    *last_emit_at = Some(now);
                    true
                } else {
                    false
                }
            }
        };
    }

    dedup_current.insert(key, now);
    true
}

#[cfg(test)]
pub(crate) fn clear_desync_dedup_for_testing_in_shared(shared: &ProxySharedState) {
    shared.middle_relay.desync_dedup.clear();
    shared.middle_relay.desync_dedup_previous.clear();
    if let Ok(mut rotation_state) = shared.middle_relay.desync_dedup_rotation_state.lock() {
        *rotation_state = DesyncDedupRotationState::default();
    }
    if let Ok(mut last_emit_at) = shared.middle_relay.desync_full_cache_last_emit_at.lock() {
        *last_emit_at = None;
    }
}

#[cfg(test)]
pub(crate) fn desync_dedup_len_for_testing(shared: &ProxySharedState) -> usize {
    shared.middle_relay.desync_dedup.len()
}

#[cfg(test)]
pub(crate) fn desync_dedup_insert_for_testing(shared: &ProxySharedState, key: u64, at: Instant) {
    shared.middle_relay.desync_dedup.insert(key, at);
}

#[cfg(test)]
pub(crate) fn desync_dedup_get_for_testing(shared: &ProxySharedState, key: u64) -> Option<Instant> {
    shared
        .middle_relay
        .desync_dedup
        .get(&key)
        .map(|entry| *entry.value())
}

#[cfg(test)]
pub(crate) fn desync_dedup_keys_for_testing(
    shared: &ProxySharedState,
) -> std::collections::HashSet<u64> {
    shared
        .middle_relay
        .desync_dedup
        .iter()
        .map(|entry| *entry.key())
        .collect()
}
