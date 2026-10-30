use super::*;

pub(crate) async fn read_client_payload_with_idle_policy_in<R>(
    client_reader: &mut CryptoReader<R>,
    proto_tag: ProtoTag,
    max_frame: usize,
    buffer_pool: &Arc<BufferPool>,
    forensics: &RelayForensicsState,
    frame_counter: &mut u64,
    stats: &Stats,
    shared: &ProxySharedState,
    idle_policy: &RelayClientIdlePolicy,
    idle_state: &mut RelayClientIdleState,
    last_downstream_activity_ms: &AtomicU64,
    session_started_at: Instant,
) -> Result<Option<(PooledBuffer, bool)>>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    const LEGACY_MAX_CONSECUTIVE_ZERO_LEN_FRAMES: u32 = 4;

    async fn read_exact_with_policy<R>(
        client_reader: &mut CryptoReader<R>,
        buf: &mut [u8],
        idle_policy: &RelayClientIdlePolicy,
        idle_state: &mut RelayClientIdleState,
        last_downstream_activity_ms: &AtomicU64,
        session_started_at: Instant,
        forensics: &RelayForensicsState,
        stats: &Stats,
        shared: &ProxySharedState,
        read_label: &'static str,
    ) -> Result<()>
    where
        R: AsyncRead + Unpin + Send + 'static,
    {
        fn hard_deadline(
            idle_policy: &RelayClientIdlePolicy,
            idle_state: &RelayClientIdleState,
            session_started_at: Instant,
            last_downstream_activity_ms: u64,
        ) -> Instant {
            let mut deadline = idle_state.last_client_frame_at + idle_policy.hard_idle;
            if idle_policy.grace_after_downstream_activity.is_zero() {
                return deadline;
            }

            let downstream_at =
                session_started_at + Duration::from_millis(last_downstream_activity_ms);
            if downstream_at > idle_state.last_client_frame_at {
                let grace_deadline = downstream_at + idle_policy.grace_after_downstream_activity;
                if grace_deadline > deadline {
                    deadline = grace_deadline;
                }
            }
            deadline
        }

        let mut filled = 0usize;
        while filled < buf.len() {
            let timeout_window = if idle_policy.enabled {
                let now = Instant::now();
                let downstream_ms = last_downstream_activity_ms.load(Ordering::Relaxed);
                let hard_deadline =
                    hard_deadline(idle_policy, idle_state, session_started_at, downstream_ms);
                if !idle_state.soft_idle_marked
                    && now.saturating_duration_since(idle_state.last_client_frame_at)
                        >= idle_policy.soft_idle
                {
                    idle_state.soft_idle_marked = true;
                    if mark_relay_idle_candidate_in(shared, forensics.conn_id) {
                        stats.increment_relay_idle_soft_mark_total();
                    }
                    info!(
                        trace_id = format_args!("0x{:016x}", forensics.trace_id),
                        conn_id = forensics.conn_id,
                        user = %forensics.user,
                        read_label,
                        soft_idle_secs = idle_policy.soft_idle.as_secs(),
                        hard_idle_secs = idle_policy.hard_idle.as_secs(),
                        grace_secs = idle_policy.grace_after_downstream_activity.as_secs(),
                        "Middle-relay soft idle mark"
                    );
                }

                let soft_deadline = idle_state.last_client_frame_at + idle_policy.soft_idle;
                let next_deadline = if idle_state.soft_idle_marked {
                    hard_deadline
                } else {
                    soft_deadline.min(hard_deadline)
                };
                let mut remaining = next_deadline.saturating_duration_since(now);
                if remaining.is_zero() {
                    remaining = Duration::from_millis(1);
                }
                remaining.min(RELAY_IDLE_IO_POLL_MAX)
            } else {
                idle_policy.legacy_frame_read_timeout
            };

            let read_result = timeout(timeout_window, client_reader.read(&mut buf[filled..])).await;
            match read_result {
                Ok(Ok(0)) => {
                    return Err(ProxyError::Io(std::io::Error::from(
                        std::io::ErrorKind::UnexpectedEof,
                    )));
                }
                Ok(Ok(n)) => {
                    filled = filled.saturating_add(n);
                }
                Ok(Err(e)) => return Err(ProxyError::Io(e)),
                Err(_) if !idle_policy.enabled => {
                    return Err(ProxyError::Io(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!(
                            "middle-relay client frame read timeout while reading {read_label}"
                        ),
                    )));
                }
                Err(_) => {
                    let now = Instant::now();
                    let downstream_ms = last_downstream_activity_ms.load(Ordering::Relaxed);
                    let hard_deadline =
                        hard_deadline(idle_policy, idle_state, session_started_at, downstream_ms);
                    if now >= hard_deadline {
                        clear_relay_idle_candidate_in(shared, forensics.conn_id);
                        stats.increment_relay_idle_hard_close_total();
                        let client_idle_secs = now
                            .saturating_duration_since(idle_state.last_client_frame_at)
                            .as_secs();
                        let downstream_idle_secs = now
                            .saturating_duration_since(
                                session_started_at + Duration::from_millis(downstream_ms),
                            )
                            .as_secs();
                        warn!(
                            trace_id = format_args!("0x{:016x}", forensics.trace_id),
                            conn_id = forensics.conn_id,
                            user = %forensics.user,
                            read_label,
                            client_idle_secs,
                            downstream_idle_secs,
                            soft_idle_secs = idle_policy.soft_idle.as_secs(),
                            hard_idle_secs = idle_policy.hard_idle.as_secs(),
                            grace_secs = idle_policy.grace_after_downstream_activity.as_secs(),
                            "Middle-relay hard idle close"
                        );
                        return Err(ProxyError::Io(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            format!(
                                "middle-relay hard idle timeout while reading {read_label}: client_idle_secs={client_idle_secs}, downstream_idle_secs={downstream_idle_secs}, soft_idle_secs={}, hard_idle_secs={}, grace_secs={}",
                                idle_policy.soft_idle.as_secs(),
                                idle_policy.hard_idle.as_secs(),
                                idle_policy.grace_after_downstream_activity.as_secs(),
                            ),
                        )));
                    }
                }
            }
        }

        Ok(())
    }

    let mut consecutive_zero_len_frames = 0u32;
    loop {
        let (len, quickack, raw_len_bytes) = match proto_tag {
            ProtoTag::Abridged => {
                let mut first = [0u8; 1];
                match read_exact_with_policy(
                    client_reader,
                    &mut first,
                    idle_policy,
                    idle_state,
                    last_downstream_activity_ms,
                    session_started_at,
                    forensics,
                    stats,
                    shared,
                    "abridged.first_len_byte",
                )
                .await
                {
                    Ok(()) => {}
                    Err(ProxyError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        return Ok(None);
                    }
                    Err(e) => return Err(e),
                }

                let quickack = (first[0] & 0x80) != 0;
                let len_words = if (first[0] & 0x7f) == 0x7f {
                    let mut ext = [0u8; 3];
                    read_exact_with_policy(
                        client_reader,
                        &mut ext,
                        idle_policy,
                        idle_state,
                        last_downstream_activity_ms,
                        session_started_at,
                        forensics,
                        stats,
                        shared,
                        "abridged.extended_len",
                    )
                    .await?;
                    u32::from_le_bytes([ext[0], ext[1], ext[2], 0]) as usize
                } else {
                    (first[0] & 0x7f) as usize
                };

                let len = len_words
                    .checked_mul(4)
                    .ok_or_else(|| ProxyError::Proxy("Abridged frame length overflow".into()))?;
                (len, quickack, None)
            }
            ProtoTag::Intermediate | ProtoTag::Secure => {
                let mut len_buf = [0u8; 4];
                match read_exact_with_policy(
                    client_reader,
                    &mut len_buf,
                    idle_policy,
                    idle_state,
                    last_downstream_activity_ms,
                    session_started_at,
                    forensics,
                    stats,
                    shared,
                    "len_prefix",
                )
                .await
                {
                    Ok(()) => {}
                    Err(ProxyError::Io(e)) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                        return Ok(None);
                    }
                    Err(e) => return Err(e),
                }
                let header = crate::protocol::framing::parse_intermediate_header(len_buf);
                (header.wire_len, header.quickack, Some(len_buf))
            }
        };

        if len == 0 {
            idle_state.on_client_tiny_frame(Instant::now());
            idle_state.tiny_frame_debt = idle_state
                .tiny_frame_debt
                .saturating_add(TINY_FRAME_DEBT_PER_TINY);
            if idle_state.tiny_frame_debt >= TINY_FRAME_DEBT_LIMIT {
                stats.increment_relay_protocol_desync_close_total();
                return Err(ProxyError::Proxy(format!(
                    "Tiny frame overhead limit exceeded: debt={}, conn_id={}",
                    idle_state.tiny_frame_debt, forensics.conn_id
                )));
            }

            if !idle_policy.enabled {
                consecutive_zero_len_frames = consecutive_zero_len_frames.saturating_add(1);
                if consecutive_zero_len_frames > LEGACY_MAX_CONSECUTIVE_ZERO_LEN_FRAMES {
                    stats.increment_relay_protocol_desync_close_total();
                    return Err(ProxyError::Proxy(
                        "Excessive zero-length abridged frames".to_string(),
                    ));
                }
            }
            continue;
        }
        if len < 4 && proto_tag != ProtoTag::Abridged {
            warn!(
                trace_id = format_args!("0x{:016x}", forensics.trace_id),
                conn_id = forensics.conn_id,
                user = %forensics.user,
                len,
                proto = ?proto_tag,
                "Frame too small — corrupt or probe"
            );
            stats.increment_relay_protocol_desync_close_total();
            return Err(ProxyError::Proxy(format!("Frame too small: {len}")));
        }

        if len > max_frame {
            return Err(report_desync_frame_too_large_in(
                shared,
                forensics,
                proto_tag,
                *frame_counter,
                max_frame,
                len,
                raw_len_bytes,
                stats,
            ));
        }

        let secure_payload_len = if proto_tag == ProtoTag::Secure {
            match secure_payload_len_from_wire_len(len) {
                Some(payload_len) => payload_len,
                None => {
                    stats.increment_secure_padding_invalid();
                    stats.increment_relay_protocol_desync_close_total();
                    return Err(ProxyError::Proxy(format!(
                        "Invalid secure frame length: {len}"
                    )));
                }
            }
        } else {
            len
        };

        let mut payload = buffer_pool.get();
        payload.clear();
        let current_cap = payload.capacity();
        if current_cap < len {
            payload.reserve(len - current_cap);
        }
        payload.resize(len, 0);
        read_exact_with_policy(
            client_reader,
            &mut payload[..len],
            idle_policy,
            idle_state,
            last_downstream_activity_ms,
            session_started_at,
            forensics,
            stats,
            shared,
            "payload",
        )
        .await?;

        // Secure Intermediate strips only non-aligned tail padding; full-word
        // padding is indistinguishable from payload in VersionD framing.
        if proto_tag == ProtoTag::Secure {
            payload.truncate(secure_payload_len);
        }
        *frame_counter += 1;
        idle_state.on_client_frame(Instant::now());
        idle_state.tiny_frame_debt = idle_state.tiny_frame_debt.saturating_sub(1);
        clear_relay_idle_candidate_in(shared, forensics.conn_id);
        return Ok(Some((payload, quickack)));
    }
}

#[cfg(test)]
pub(crate) async fn read_client_payload_with_idle_policy<R>(
    client_reader: &mut CryptoReader<R>,
    proto_tag: ProtoTag,
    max_frame: usize,
    buffer_pool: &Arc<BufferPool>,
    forensics: &RelayForensicsState,
    frame_counter: &mut u64,
    stats: &Stats,
    idle_policy: &RelayClientIdlePolicy,
    idle_state: &mut RelayClientIdleState,
    last_downstream_activity_ms: &AtomicU64,
    session_started_at: Instant,
) -> Result<Option<(PooledBuffer, bool)>>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let shared = ProxySharedState::new();
    read_client_payload_with_idle_policy_in(
        client_reader,
        proto_tag,
        max_frame,
        buffer_pool,
        forensics,
        frame_counter,
        stats,
        shared.as_ref(),
        idle_policy,
        idle_state,
        last_downstream_activity_ms,
        session_started_at,
    )
    .await
}

#[cfg(test)]
pub(crate) async fn read_client_payload_legacy<R>(
    client_reader: &mut CryptoReader<R>,
    proto_tag: ProtoTag,
    max_frame: usize,
    frame_read_timeout: Duration,
    buffer_pool: &Arc<BufferPool>,
    forensics: &RelayForensicsState,
    frame_counter: &mut u64,
    stats: &Stats,
) -> Result<Option<(PooledBuffer, bool)>>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    let now = Instant::now();
    let shared = ProxySharedState::new();
    let mut idle_state = RelayClientIdleState::new(now);
    let last_downstream_activity_ms = AtomicU64::new(0);
    let idle_policy = RelayClientIdlePolicy::disabled(frame_read_timeout);
    read_client_payload_with_idle_policy_in(
        client_reader,
        proto_tag,
        max_frame,
        buffer_pool,
        forensics,
        frame_counter,
        stats,
        shared.as_ref(),
        &idle_policy,
        &mut idle_state,
        &last_downstream_activity_ms,
        now,
    )
    .await
}

#[cfg(test)]
pub(crate) async fn read_client_payload<R>(
    client_reader: &mut CryptoReader<R>,
    proto_tag: ProtoTag,
    max_frame: usize,
    frame_read_timeout: Duration,
    buffer_pool: &Arc<BufferPool>,
    forensics: &RelayForensicsState,
    frame_counter: &mut u64,
    stats: &Stats,
) -> Result<Option<(PooledBuffer, bool)>>
where
    R: AsyncRead + Unpin + Send + 'static,
{
    read_client_payload_legacy(
        client_reader,
        proto_tag,
        max_frame,
        frame_read_timeout,
        buffer_pool,
        forensics,
        frame_counter,
        stats,
    )
    .await
}
