use super::*;

/// Handles an MTProto obfuscation handshake with isolated test state.
#[cfg(test)]
pub async fn handle_mtproto_handshake<R, W>(
    handshake: &[u8; HANDSHAKE_LEN],
    reader: R,
    writer: W,
    peer: SocketAddr,
    config: &ProxyConfig,
    replay_checker: &ReplayChecker,
    is_tls: bool,
    preferred_user: Option<&str>,
) -> HandshakeResult<(CryptoReader<R>, CryptoWriter<W>, HandshakeSuccess), R, W>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    let shared = ProxySharedState::new();
    handle_mtproto_handshake_impl(
        handshake,
        reader,
        writer,
        peer,
        config,
        replay_checker,
        is_tls,
        preferred_user,
        None,
        MtprotoModePolicy::Configured,
        shared.as_ref(),
    )
    .await
}

/// Handles an MTProto obfuscation handshake with process-shared defenses.
pub async fn handle_mtproto_handshake_with_shared<R, W>(
    handshake: &[u8; HANDSHAKE_LEN],
    reader: R,
    writer: W,
    peer: SocketAddr,
    config: &ProxyConfig,
    replay_checker: &ReplayChecker,
    is_tls: bool,
    preferred_user: Option<&str>,
    shared: &ProxySharedState,
) -> HandshakeResult<(CryptoReader<R>, CryptoWriter<W>, HandshakeSuccess), R, W>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    handle_mtproto_handshake_impl(
        handshake,
        reader,
        writer,
        peer,
        config,
        replay_checker,
        is_tls,
        preferred_user,
        None,
        MtprotoModePolicy::Configured,
        shared,
    )
    .await
}

/// Authenticates one WEB logical stream against exactly one user and secret mode.
pub(crate) async fn handle_mtproto_handshake_for_web_user<R, W>(
    handshake: &[u8; HANDSHAKE_LEN],
    reader: R,
    writer: W,
    peer: SocketAddr,
    config: &ProxyConfig,
    replay_checker: &ReplayChecker,
    exact_user: &str,
    secret_mode: WebSecretMode,
    shared: &ProxySharedState,
) -> HandshakeResult<(CryptoReader<R>, CryptoWriter<W>, HandshakeSuccess), R, W>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    handle_mtproto_handshake_impl(
        handshake,
        reader,
        writer,
        peer,
        config,
        replay_checker,
        false,
        None,
        Some(exact_user),
        MtprotoModePolicy::Web(secret_mode),
        shared,
    )
    .await
}

async fn handle_mtproto_handshake_impl<R, W>(
    handshake: &[u8; HANDSHAKE_LEN],
    reader: R,
    writer: W,
    peer: SocketAddr,
    config: &ProxyConfig,
    replay_checker: &ReplayChecker,
    is_tls: bool,
    preferred_user: Option<&str>,
    exact_user: Option<&str>,
    mode_policy: MtprotoModePolicy,
    shared: &ProxySharedState,
) -> HandshakeResult<(CryptoReader<R>, CryptoWriter<W>, HandshakeSuccess), R, W>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    let handshake_fingerprint = {
        let digest = sha256(&handshake[..8]);
        hex::encode(&digest[..4])
    };
    trace!(
        peer = %peer,
        handshake_fingerprint = %handshake_fingerprint,
        "MTProto handshake prefix"
    );

    let throttle_now = Instant::now();
    if auth_probe_should_apply_preauth_throttle_in(shared, peer.ip(), throttle_now) {
        maybe_apply_server_hello_delay(config).await;
        debug!(peer = %peer, "MTProto handshake rejected by pre-auth probe throttle");
        return HandshakeResult::BadClient { reader, writer };
    }

    let dec_prekey_iv = &handshake[SKIP_LEN..SKIP_LEN + PREKEY_LEN + IV_LEN];
    let mut dec_prekey = [0u8; PREKEY_LEN];
    dec_prekey.copy_from_slice(&dec_prekey_iv[..PREKEY_LEN]);
    let mut dec_iv_arr = [0u8; IV_LEN];
    dec_iv_arr.copy_from_slice(&dec_prekey_iv[PREKEY_LEN..]);
    let dec_iv = u128::from_be_bytes(dec_iv_arr);

    let mut enc_prekey_iv = [0u8; PREKEY_LEN + IV_LEN];
    for idx in 0..enc_prekey_iv.len() {
        enc_prekey_iv[idx] = dec_prekey_iv[dec_prekey_iv.len() - 1 - idx];
    }
    let mut enc_prekey = [0u8; PREKEY_LEN];
    enc_prekey.copy_from_slice(&enc_prekey_iv[..PREKEY_LEN]);
    let mut enc_iv_arr = [0u8; IV_LEN];
    enc_iv_arr.copy_from_slice(&enc_prekey_iv[PREKEY_LEN..]);
    let enc_iv = u128::from_be_bytes(enc_iv_arr);

    if let Some(snapshot) = config.runtime_user_auth() {
        let sticky_ip_hint = sticky_hint_get_by_ip(shared, peer.ip());
        let sticky_prefix_hint = sticky_hint_get_by_ip_prefix(shared, peer.ip());
        let sticky_ip_candidates =
            sticky_ip_hint.and_then(|hint_key| snapshot.candidate_ids_by_hint_key(hint_key));
        let sticky_prefix_candidates =
            sticky_prefix_hint.and_then(|hint_key| snapshot.candidate_ids_by_hint_key(hint_key));
        let preferred_user_id = preferred_user.and_then(|user| snapshot.user_id_by_name(user));
        let exact_user_id = exact_user.and_then(|user| snapshot.user_id_by_name(user));
        let has_hint = sticky_ip_candidates.is_some_and(|ids| !ids.is_empty())
            || sticky_prefix_candidates.is_some_and(|ids| !ids.is_empty())
            || preferred_user_id.is_some()
            || exact_user_id.is_some();
        let overload = auth_probe_saturation_is_throttled_in(shared, Instant::now());
        let candidate_budget = budget_for_validation(snapshot.entries().len(), overload, has_hint);

        let mut tried_user_ids = [u32::MAX; CANDIDATE_HINT_TRACK_CAP];
        let mut tried_len = 0usize;
        let mut validation_checks = 0usize;
        let mut budget_exhausted = false;

        let mut matched_user = String::new();
        let mut matched_user_id = None;
        let mut matched_validation = None;

        macro_rules! try_user_id {
            ($user_id:expr) => {{
                if validation_checks >= candidate_budget {
                    budget_exhausted = true;
                    false
                } else if !mark_candidate_if_new(&mut tried_user_ids, &mut tried_len, $user_id) {
                    false
                } else if let Some(entry) = snapshot.entry_by_id($user_id) {
                    validation_checks = validation_checks.saturating_add(1);
                    if let Some(validation) = validate_mtproto_secret_candidate(
                        handshake,
                        &dec_prekey,
                        dec_iv,
                        &enc_prekey,
                        enc_iv,
                        &entry.secret,
                        config,
                        is_tls,
                        mode_policy,
                    ) {
                        matched_user = entry.user.clone();
                        matched_user_id = Some($user_id);
                        matched_validation = Some(validation);
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            }};
        }

        let mut matched = exact_user_id.is_some_and(|user_id| try_user_id!(user_id));
        if exact_user.is_none()
            && let Some(candidate_ids) = sticky_ip_candidates
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

        if exact_user.is_none()
            && !matched
            && let Some(user_id) = preferred_user_id
        {
            matched = try_user_id!(user_id);
        }

        if exact_user.is_none()
            && !matched
            && let Some(candidate_ids) = sticky_prefix_candidates
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

        if exact_user.is_none() && !matched && !budget_exhausted {
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

        if exact_user.is_none() && !matched && !budget_exhausted {
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
                budget_exhausted = budget_exhausted,
                candidate_budget = candidate_budget,
                validation_checks = validation_checks,
                "MTProto handshake: no matching user found"
            );
            return HandshakeResult::BadClient { reader, writer };
        }

        let Some(validation) = matched_validation else {
            auth_probe_record_failure_in(shared, peer.ip(), Instant::now());
            maybe_apply_server_hello_delay(config).await;
            warn!(
                peer = %peer,
                user = %matched_user,
                "MTProto handshake matched user without validation material"
            );
            return HandshakeResult::BadClient { reader, writer };
        };

        if config
            .access
            .is_user_source_ip_denied(matched_user.as_str(), peer.ip())
        {
            auth_probe_record_failure_in(shared, peer.ip(), Instant::now());
            maybe_apply_server_hello_delay(config).await;
            warn!(
                peer = %peer,
                user = %matched_user,
                "MTProto handshake rejected: client source IP on per-user deny list (access.user_source_deny)"
            );
            return HandshakeResult::BadClient { reader, writer };
        }

        // Apply replay tracking only after successful authentication.
        //
        // This ordering prevents an attacker from producing invalid handshakes that
        // still collide with a valid handshake's replay slot and thus evict a valid
        // entry from the cache. We accept the cost of performing the full
        // authentication check first to avoid poisoning the replay cache.
        if replay_checker.check_and_add_handshake(dec_prekey_iv) {
            auth_probe_record_failure_in(shared, peer.ip(), Instant::now());
            maybe_apply_server_hello_delay(config).await;
            warn!(peer = %peer, user = %matched_user, "MTProto replay attack detected");
            return HandshakeResult::BadClient { reader, writer };
        }

        let dec_key = Zeroizing::new(validation.dec_key);
        let enc_key = Zeroizing::new(validation.enc_key);
        let success = HandshakeSuccess {
            user: matched_user.clone(),
            dc_idx: validation.dc_idx,
            proto_tag: validation.proto_tag,
            dec_key: *dec_key,
            dec_iv: validation.dec_iv,
            enc_key: *enc_key,
            enc_iv: validation.enc_iv,
            peer,
            is_tls,
        };

        debug!(
            peer = %peer,
            user = %matched_user,
            dc = validation.dc_idx,
            proto = ?validation.proto_tag,
            tls = is_tls,
            "MTProto handshake successful"
        );

        auth_probe_record_success_in(shared, peer.ip());
        if let Some(user_id) = matched_user_id {
            if let Some(entry) = snapshot.entry_by_id(user_id) {
                sticky_hint_record_success_in(shared, peer.ip(), entry.hint_key, None);
                record_recent_user_success_in(shared, entry.hint_key);
            }
        }

        let max_pending = config.general.crypto_pending_buffer;
        return HandshakeResult::Success((
            CryptoReader::new(reader, validation.decryptor),
            CryptoWriter::new(writer, validation.encryptor, max_pending),
            success,
        ));
    } else {
        let decoded_users = match exact_user {
            Some(user) => config
                .access
                .users
                .get(user)
                .and_then(|secret| decode_user_secret(shared, user, secret))
                .map(|secret| vec![(user.to_string(), secret)])
                .unwrap_or_default(),
            None => decode_user_secrets_in(shared, config, preferred_user),
        };
        let mut validation_checks = 0usize;

        for (user, secret) in decoded_users {
            if secret.len() != ACCESS_SECRET_BYTES {
                continue;
            }
            validation_checks = validation_checks.saturating_add(1);

            let mut secret_arr = [0u8; ACCESS_SECRET_BYTES];
            secret_arr.copy_from_slice(&secret);
            let Some(validation) = validate_mtproto_secret_candidate(
                handshake,
                &dec_prekey,
                dec_iv,
                &enc_prekey,
                enc_iv,
                &secret_arr,
                config,
                is_tls,
                mode_policy,
            ) else {
                continue;
            };

            shared
                .handshake
                .auth_expensive_checks_total
                .fetch_add(validation_checks as u64, Ordering::Relaxed);

            if config
                .access
                .is_user_source_ip_denied(user.as_str(), peer.ip())
            {
                auth_probe_record_failure_in(shared, peer.ip(), Instant::now());
                maybe_apply_server_hello_delay(config).await;
                warn!(
                    peer = %peer,
                    user = %user,
                    "MTProto handshake rejected: client source IP on per-user deny list (access.user_source_deny)"
                );
                return HandshakeResult::BadClient { reader, writer };
            }

            // Apply replay tracking only after successful authentication.
            //
            // This ordering prevents an attacker from producing invalid handshakes that
            // still collide with a valid handshake's replay slot and thus evict a valid
            // entry from the cache. We accept the cost of performing the full
            // authentication check first to avoid poisoning the replay cache.
            if replay_checker.check_and_add_handshake(dec_prekey_iv) {
                auth_probe_record_failure_in(shared, peer.ip(), Instant::now());
                maybe_apply_server_hello_delay(config).await;
                warn!(peer = %peer, user = %user, "MTProto replay attack detected");
                return HandshakeResult::BadClient { reader, writer };
            }

            let dec_key = Zeroizing::new(validation.dec_key);
            let enc_key = Zeroizing::new(validation.enc_key);
            let success = HandshakeSuccess {
                user: user.clone(),
                dc_idx: validation.dc_idx,
                proto_tag: validation.proto_tag,
                dec_key: *dec_key,
                dec_iv: validation.dec_iv,
                enc_key: *enc_key,
                enc_iv: validation.enc_iv,
                peer,
                is_tls,
            };

            debug!(
                peer = %peer,
                user = %user,
                dc = validation.dc_idx,
                proto = ?validation.proto_tag,
                tls = is_tls,
                "MTProto handshake successful"
            );

            auth_probe_record_success_in(shared, peer.ip());

            let max_pending = config.general.crypto_pending_buffer;
            return HandshakeResult::Success((
                CryptoReader::new(reader, validation.decryptor),
                CryptoWriter::new(writer, validation.encryptor, max_pending),
                success,
            ));
        }

        shared
            .handshake
            .auth_expensive_checks_total
            .fetch_add(validation_checks as u64, Ordering::Relaxed);
    }

    auth_probe_record_failure_in(shared, peer.ip(), Instant::now());
    maybe_apply_server_hello_delay(config).await;
    debug!(peer = %peer, "MTProto handshake: no matching user found");
    HandshakeResult::BadClient { reader, writer }
}
