use super::*;

pub(super) struct TlsClientValidation {
    pub(super) digest: [u8; tls::TLS_DIGEST_LEN],
    pub(super) session_id: [u8; 32],
    pub(super) session_id_len: usize,
    pub(super) user: String,
    pub(super) secret: [u8; ACCESS_SECRET_BYTES],
    pub(super) user_id: Option<u32>,
}

pub(super) async fn validate_tls_client(
    handshake: &[u8],
    peer: SocketAddr,
    config: &ProxyConfig,
    shared: &ProxySharedState,
    preferred_user_hint: Option<&str>,
    client_sni: &Option<String>,
) -> Option<TlsClientValidation> {
    let mut validation_digest = [0u8; tls::TLS_DIGEST_LEN];
    let mut validation_session_id = [0u8; 32];
    let mut validation_session_id_len = 0usize;
    let mut validated_user = String::new();
    let mut validated_secret = [0u8; ACCESS_SECRET_BYTES];
    let mut validated_user_id: Option<u32> = None;

    if let Some(snapshot) = config.runtime_user_auth() {
        let parsed = match parse_tls_auth_material(
            handshake,
            config.access.ignore_time_skew,
            config.access.replay_window_secs,
        ) {
            Some(parsed) => parsed,
            None => {
                auth_probe_record_failure_in(shared, peer.ip(), Instant::now());
                maybe_apply_server_hello_delay(config).await;
                debug!(peer = %peer, "TLS handshake auth material parsing failed");
                return None;
            }
        };

        let sticky_ip_hint = sticky_hint_get_by_ip(shared, peer.ip());
        let sticky_ip_candidates =
            sticky_ip_hint.and_then(|hint_key| snapshot.candidate_ids_by_hint_key(hint_key));
        let preferred_user_id = preferred_user_hint.and_then(|user| snapshot.user_id_by_name(user));
        let sticky_sni_hint = client_sni
            .as_deref()
            .and_then(|sni| sticky_hint_get_by_sni(shared, sni));
        let sticky_sni_candidates =
            sticky_sni_hint.and_then(|hint_key| snapshot.candidate_ids_by_hint_key(hint_key));
        let sticky_prefix_hint = sticky_hint_get_by_ip_prefix(shared, peer.ip());
        let sticky_prefix_candidates =
            sticky_prefix_hint.and_then(|hint_key| snapshot.candidate_ids_by_hint_key(hint_key));
        let sni_candidates = client_sni
            .as_deref()
            .and_then(|sni| snapshot.sni_candidates(sni));
        let sni_initial_candidates = client_sni
            .as_deref()
            .and_then(|sni| snapshot.sni_initial_candidates(sni));

        let has_hint = sticky_ip_candidates.is_some_and(|ids| !ids.is_empty())
            || preferred_user_id.is_some()
            || sticky_sni_candidates.is_some_and(|ids| !ids.is_empty())
            || sticky_prefix_candidates.is_some_and(|ids| !ids.is_empty())
            || sni_candidates.is_some_and(|ids| !ids.is_empty())
            || sni_initial_candidates.is_some_and(|ids| !ids.is_empty());
        let overload = auth_probe_saturation_is_throttled_in(shared, Instant::now());
        let candidate_budget = budget_for_validation(snapshot.entries().len(), overload, has_hint);

        let mut tried_user_ids = [u32::MAX; CANDIDATE_HINT_TRACK_CAP];
        let mut tried_len = 0usize;
        let mut validation_checks = 0usize;
        let mut budget_exhausted = false;

        macro_rules! try_user_id {
            ($user_id:expr) => {{
                if validation_checks >= candidate_budget {
                    budget_exhausted = true;
                    false
                } else if !mark_candidate_if_new(&mut tried_user_ids, &mut tried_len, $user_id) {
                    false
                } else if let Some(entry) = snapshot.entry_by_id($user_id) {
                    validation_checks = validation_checks.saturating_add(1);
                    if let Some(candidate) =
                        validate_tls_secret_candidate(&parsed, handshake, &entry.secret)
                    {
                        validation_digest = candidate.digest;
                        validation_session_id = candidate.session_id;
                        validation_session_id_len = candidate.session_id_len;
                        validated_secret.copy_from_slice(&entry.secret);
                        validated_user = entry.user.clone();
                        validated_user_id = Some($user_id);
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }};
        }

        let mut matched = false;
        if let Some(candidate_ids) = sticky_ip_candidates {
            for &user_id in candidate_ids {
                if try_user_id!(user_id) {
                    matched = true;
                    break;
                }
                if budget_exhausted {
                    break;
                }
            }
        }

        if !matched && let Some(user_id) = preferred_user_id {
            matched = try_user_id!(user_id);
        }

        if !matched && let Some(candidate_ids) = sticky_sni_candidates {
            for &user_id in candidate_ids {
                if try_user_id!(user_id) {
                    matched = true;
                    break;
                }
                if budget_exhausted {
                    break;
                }
            }
        }

        if !matched && let Some(candidate_ids) = sticky_prefix_candidates {
            for &user_id in candidate_ids {
                if try_user_id!(user_id) {
                    matched = true;
                    break;
                }
                if budget_exhausted {
                    break;
                }
            }
        }

        if !matched
            && !budget_exhausted
            && let Some(candidate_ids) = sni_candidates
        {
            for &user_id in candidate_ids {
                if try_user_id!(user_id) {
                    matched = true;
                    break;
                }
                if budget_exhausted {
                    break;
                }
            }
        }

        if !matched
            && !budget_exhausted
            && let Some(candidate_ids) = sni_initial_candidates
        {
            for &user_id in candidate_ids {
                if try_user_id!(user_id) {
                    matched = true;
                    break;
                }
                if budget_exhausted {
                    break;
                }
            }
        }

        if !matched && !budget_exhausted {
            let ring = &shared.handshake.recent_user_ring;
            if !ring.is_empty() {
                let next_seq = shared
                    .handshake
                    .recent_user_ring_seq
                    .load(Ordering::Relaxed);
                let scan_limit = ring.len().min(RECENT_USER_RING_SCAN_LIMIT);
                'recent_hints: for offset in 0..scan_limit {
                    let idx = (next_seq as usize + ring.len() - 1 - offset) % ring.len();
                    let hint_key = ring[idx].load(Ordering::Relaxed);
                    if hint_key == 0 {
                        continue;
                    }
                    if let Some(candidate_ids) = snapshot.candidate_ids_by_hint_key(hint_key) {
                        for &user_id in candidate_ids {
                            if try_user_id!(user_id) {
                                matched = true;
                                break 'recent_hints;
                            }
                            if budget_exhausted {
                                break 'recent_hints;
                            }
                        }
                    }
                }
            }
        }

        if !matched && !budget_exhausted {
            for idx in 0..snapshot.entries().len() {
                let Some(user_id) = u32::try_from(idx).ok() else {
                    break;
                };
                if try_user_id!(user_id) {
                    matched = true;
                    break;
                }
                if budget_exhausted {
                    break;
                }
            }
        }

        shared
            .handshake
            .auth_expensive_checks_total
            .fetch_add(validation_checks as u64, Ordering::Relaxed);
        if budget_exhausted {
            shared
                .handshake
                .auth_budget_exhausted_total
                .fetch_add(1, Ordering::Relaxed);
        }

        if !matched {
            let failure_now = Instant::now();
            auth_probe_note_expensive_invalid_scan_in(
                shared,
                failure_now,
                validation_checks,
                overload,
            );
            auth_probe_record_failure_in(shared, peer.ip(), failure_now);
            maybe_apply_server_hello_delay(config).await;
            debug!(
                peer = %peer,
                ignore_time_skew = config.access.ignore_time_skew,
                budget_exhausted = budget_exhausted,
                candidate_budget = candidate_budget,
                validation_checks = validation_checks,
                "TLS handshake validation failed - no matching user, time skew, or budget exhausted"
            );
            return None;
        }
    } else {
        let secrets = decode_user_secrets_in(shared, config, preferred_user_hint);
        let validation = match tls::validate_tls_handshake_with_replay_window(
            handshake,
            &secrets,
            config.access.ignore_time_skew,
            config.access.replay_window_secs,
        ) {
            Some(v) => v,
            None => {
                auth_probe_record_failure_in(shared, peer.ip(), Instant::now());
                maybe_apply_server_hello_delay(config).await;
                debug!(
                    peer = %peer,
                    ignore_time_skew = config.access.ignore_time_skew,
                    "TLS handshake validation failed - no matching user or time skew"
                );
                return None;
            }
        };
        let secret = match secrets.iter().find(|(name, _)| *name == validation.user) {
            Some((_, s)) if s.len() == ACCESS_SECRET_BYTES => s,
            _ => {
                maybe_apply_server_hello_delay(config).await;
                return None;
            }
        };

        validation_digest = validation.digest;
        validation_session_id_len = validation.session_id.len();
        if validation_session_id_len > validation_session_id.len() {
            maybe_apply_server_hello_delay(config).await;
            return None;
        }
        validation_session_id[..validation_session_id_len].copy_from_slice(&validation.session_id);
        validated_user = validation.user;
        validated_secret.copy_from_slice(secret);
    }

    if config
        .access
        .is_user_source_ip_denied(validated_user.as_str(), peer.ip())
    {
        auth_probe_record_failure_in(shared, peer.ip(), Instant::now());
        maybe_apply_server_hello_delay(config).await;
        warn!(
            peer = %peer,
            user = %validated_user,
            "TLS handshake rejected: client source IP on per-user deny list (access.user_source_deny)"
        );
        return None;
    }

    Some(TlsClientValidation {
        digest: validation_digest,
        session_id: validation_session_id,
        session_id_len: validation_session_id_len,
        user: validated_user,
        secret: validated_secret,
        user_id: validated_user_id,
    })
}
