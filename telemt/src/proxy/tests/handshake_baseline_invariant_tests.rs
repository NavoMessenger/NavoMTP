use super::*;
use crate::crypto::sha256_hmac;
use crate::protocol::constants::{TLS_RECORD_HANDSHAKE, TLS_VERSION};
use crate::stats::ReplayChecker;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::time::timeout;

fn test_config_with_secret_hex(secret_hex: &str) -> ProxyConfig {
    let mut cfg = ProxyConfig::default();
    cfg.access.users.clear();
    cfg.access
        .users
        .insert("user".to_string(), secret_hex.to_string());
    cfg.access.ignore_time_skew = true;
    cfg.censorship.mask = true;
    cfg
}

fn make_valid_tls_handshake(secret: &[u8], timestamp: u32) -> Vec<u8> {
    const TLS_AES_128_GCM_SHA256: [u8; 2] = [0x13, 0x01];
    const TLS_EXTENSION_KEY_SHARE: u16 = 0x0033;
    const X25519_KEY_SHARE_LEN: usize = 32;
    let session_id_len: usize = 32;
    let fill = 0x42u8;

    let mut extensions = Vec::new();
    let mut key_share = Vec::new();
    key_share.extend_from_slice(&tls::TLS_NAMED_GROUP_X25519.to_be_bytes());
    key_share.extend_from_slice(&(X25519_KEY_SHARE_LEN as u16).to_be_bytes());
    key_share.push(9);
    key_share.resize(key_share.len() + X25519_KEY_SHARE_LEN - 1, 0);

    let mut key_share_extension = Vec::new();
    key_share_extension.extend_from_slice(&(key_share.len() as u16).to_be_bytes());
    key_share_extension.extend_from_slice(&key_share);
    extensions.extend_from_slice(&TLS_EXTENSION_KEY_SHARE.to_be_bytes());
    extensions.extend_from_slice(&(key_share_extension.len() as u16).to_be_bytes());
    extensions.extend_from_slice(&key_share_extension);

    let body_len = 2
        + 32
        + 1
        + session_id_len
        + 2
        + TLS_AES_128_GCM_SHA256.len()
        + 1
        + 1
        + 2
        + extensions.len();
    let mut body = Vec::with_capacity(body_len);
    body.extend_from_slice(&TLS_VERSION);
    body.extend_from_slice(&[fill; 32]);
    body.push(session_id_len as u8);
    body.extend_from_slice(&[fill; 32]);
    body.extend_from_slice(&(TLS_AES_128_GCM_SHA256.len() as u16).to_be_bytes());
    body.extend_from_slice(&TLS_AES_128_GCM_SHA256);
    body.push(1);
    body.push(0);
    body.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    body.extend_from_slice(&extensions);
    assert_eq!(body.len(), body_len);

    let mut handshake = Vec::with_capacity(5 + 4 + body_len);
    handshake.push(TLS_RECORD_HANDSHAKE);
    handshake.extend_from_slice(&[0x03, 0x01]);
    handshake.extend_from_slice(&((4 + body_len) as u16).to_be_bytes());
    handshake.push(0x01);
    let body_len_bytes = (body_len as u32).to_be_bytes();
    handshake.extend_from_slice(&body_len_bytes[1..4]);
    handshake.extend_from_slice(&body);

    // The proxy authenticates TLS-fronted clients through the random field.
    handshake[tls::TLS_DIGEST_POS..tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN].fill(0);

    let computed = sha256_hmac(secret, &handshake);
    let mut digest = computed;
    let ts = timestamp.to_le_bytes();
    for i in 0..4 {
        digest[28 + i] ^= ts[i];
    }

    handshake[tls::TLS_DIGEST_POS..tls::TLS_DIGEST_POS + tls::TLS_DIGEST_LEN]
        .copy_from_slice(&digest);
    handshake
}

#[tokio::test]
async fn handshake_baseline_probe_always_falls_back_to_masking() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let cfg = test_config_with_secret_hex("11111111111111111111111111111111");
    let replay_checker = ReplayChecker::new(64, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "198.51.100.210:44321".parse().unwrap();

    let probe = b"not-a-tls-clienthello";
    let res = handle_tls_handshake(
        probe,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &cfg,
        &replay_checker,
        &rng,
        None,
    )
    .await;

    assert!(matches!(res, HandshakeResult::BadClient { .. }));
}

#[tokio::test]
async fn handshake_baseline_invalid_secret_triggers_fallback_not_error_response() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let good_secret = [0x22u8; 16];
    let bad_cfg = test_config_with_secret_hex("33333333333333333333333333333333");
    let replay_checker = ReplayChecker::new(64, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "198.51.100.211:44322".parse().unwrap();

    let handshake = make_valid_tls_handshake(&good_secret, 0);
    let res = handle_tls_handshake(
        &handshake,
        tokio::io::empty(),
        tokio::io::sink(),
        peer,
        &bad_cfg,
        &replay_checker,
        &rng,
        None,
    )
    .await;

    assert!(matches!(res, HandshakeResult::BadClient { .. }));
}

#[tokio::test]
async fn handshake_baseline_auth_probe_streak_increments_per_ip() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let cfg = test_config_with_secret_hex("44444444444444444444444444444444");
    let replay_checker = ReplayChecker::new(64, Duration::from_secs(60));
    let rng = SecureRandom::new();

    let peer: SocketAddr = "203.0.113.10:5555".parse().unwrap();
    let untouched_ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11));
    let bad_probe = b"\x16\x03\x01\x00";

    for expected in 1..=3 {
        let res = handle_tls_handshake_with_shared(
            bad_probe,
            tokio::io::empty(),
            tokio::io::sink(),
            peer,
            &cfg,
            &replay_checker,
            &rng,
            None,
            shared.as_ref(),
        )
        .await;
        assert!(matches!(res, HandshakeResult::BadClient { .. }));
        assert_eq!(
            auth_probe_fail_streak_for_testing_in_shared(shared.as_ref(), peer.ip()),
            Some(expected)
        );
        assert_eq!(
            auth_probe_fail_streak_for_testing_in_shared(shared.as_ref(), untouched_ip),
            None
        );
    }
}

#[test]
fn handshake_baseline_saturation_fires_at_compile_time_threshold() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 33));
    let now = Instant::now();

    for _ in 0..AUTH_PROBE_BACKOFF_START_FAILS.saturating_sub(1) {
        auth_probe_record_failure_in(shared.as_ref(), ip, now);
    }
    assert!(!auth_probe_is_throttled_in(shared.as_ref(), ip, now));

    auth_probe_record_failure_in(shared.as_ref(), ip, now);
    assert!(auth_probe_is_throttled_in(shared.as_ref(), ip, now));
}

#[test]
fn handshake_baseline_repeated_probes_streak_monotonic() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42));
    let now = Instant::now();
    let mut prev = 0u32;

    for _ in 0..100 {
        auth_probe_record_failure_in(shared.as_ref(), ip, now);
        let current =
            auth_probe_fail_streak_for_testing_in_shared(shared.as_ref(), ip).unwrap_or(0);
        assert!(current >= prev, "streak must be monotonic");
        prev = current;
    }
}

#[test]
fn handshake_baseline_throttled_ip_incurs_backoff_delay() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let ip = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 44));
    let now = Instant::now();

    for _ in 0..AUTH_PROBE_BACKOFF_START_FAILS {
        auth_probe_record_failure_in(shared.as_ref(), ip, now);
    }

    let delay = auth_probe_backoff(AUTH_PROBE_BACKOFF_START_FAILS);
    assert!(delay >= Duration::from_millis(AUTH_PROBE_BACKOFF_BASE_MS));

    let before_expiry = now + delay.saturating_sub(Duration::from_millis(1));
    let after_expiry = now + delay + Duration::from_millis(1);

    assert!(auth_probe_is_throttled_in(
        shared.as_ref(),
        ip,
        before_expiry
    ));
    assert!(!auth_probe_is_throttled_in(
        shared.as_ref(),
        ip,
        after_expiry
    ));
}

#[tokio::test]
async fn handshake_baseline_malformed_probe_frames_fail_closed_to_masking() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());

    let cfg = test_config_with_secret_hex("55555555555555555555555555555555");
    let replay_checker = ReplayChecker::new(64, Duration::from_secs(60));
    let rng = SecureRandom::new();
    let peer: SocketAddr = "198.51.100.212:44323".parse().unwrap();

    let corpus: Vec<Vec<u8>> = vec![
        vec![0x16, 0x03, 0x01],
        vec![0x16, 0x03, 0x01, 0xFF, 0xFF],
        vec![0x00; 128],
        (0..64u8).collect(),
    ];

    for probe in corpus {
        let res = timeout(
            Duration::from_millis(250),
            handle_tls_handshake(
                &probe,
                tokio::io::empty(),
                tokio::io::sink(),
                peer,
                &cfg,
                &replay_checker,
                &rng,
                None,
            ),
        )
        .await
        .expect("malformed probe handling must complete in bounded time");

        assert!(
            matches!(
                res,
                HandshakeResult::BadClient { .. } | HandshakeResult::Error(_)
            ),
            "malformed probe must fail closed"
        );
    }
}
