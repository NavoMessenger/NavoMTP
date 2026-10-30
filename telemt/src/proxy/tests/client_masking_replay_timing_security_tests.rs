use super::*;
use crate::config::{UpstreamConfig, UpstreamType};
use crate::crypto::sha256_hmac;
use crate::protocol::constants::{HANDSHAKE_LEN, TLS_VERSION};
use crate::protocol::tls;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::time::{Duration, Instant};

fn new_upstream_manager(stats: Arc<Stats>) -> Arc<UpstreamManager> {
    Arc::new(UpstreamManager::new(
        vec![UpstreamConfig {
            upstream_type: UpstreamType::Direct {
                interface: None,
                bind_addresses: None,
                bindtodevice: None,
            },
            weight: 1,
            enabled: true,
            scopes: String::new(),
            selected_scope: String::new(),
            ipv4: None,
            ipv6: None,
            prefer: None,
        }],
        1,
        1,
        1,
        10,
        1,
        false,
        stats,
    ))
}

fn make_valid_tls_client_hello(secret: &[u8], timestamp: u32, tls_len: usize, fill: u8) -> Vec<u8> {
    assert!(
        tls_len <= u16::MAX as usize,
        "TLS length must fit into record header"
    );

    const TLS_AES_128_GCM_SHA256: [u8; 2] = [0x13, 0x01];
    const TLS_EXTENSION_KEY_SHARE: u16 = 0x0033;
    const TLS_EXTENSION_PADDING: u16 = 0x0015;
    const X25519_KEY_SHARE_LEN: usize = 32;
    let session_id_len: usize = 32;

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

    let base_tls_len = 4
        + 2
        + 32
        + 1
        + session_id_len
        + 2
        + TLS_AES_128_GCM_SHA256.len()
        + 1
        + 1
        + 2
        + extensions.len();
    assert!(
        tls_len == base_tls_len || tls_len >= base_tls_len + 4,
        "TLS length must leave room for a complete padding extension"
    );
    if tls_len > base_tls_len {
        let padding_len = tls_len - base_tls_len - 4;
        extensions.extend_from_slice(&TLS_EXTENSION_PADDING.to_be_bytes());
        extensions.extend_from_slice(&(padding_len as u16).to_be_bytes());
        extensions.resize(extensions.len() + padding_len, fill);
    }

    let body_len = tls_len - 4;
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

    let mut handshake = Vec::with_capacity(5 + tls_len);
    handshake.push(0x16);
    handshake.extend_from_slice(&[0x03, 0x01]);
    handshake.extend_from_slice(&(tls_len as u16).to_be_bytes());
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

async fn run_replay_candidate_session(
    replay_checker: Arc<ReplayChecker>,
    hello: &[u8],
    peer: SocketAddr,
    drive_mtproto_fail: bool,
) -> Duration {
    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.censorship.mask = true;
    cfg.censorship.mask_unix_sock = None;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_port = 1;
    cfg.censorship.mask_timing_normalization_enabled = false;
    cfg.access.ignore_time_skew = true;
    cfg.access.users.insert(
        "user".to_string(),
        "abababababababababababababababab".to_string(),
    );

    let config = Arc::new(cfg);
    let stats = Arc::new(Stats::new());
    let beobachten = Arc::new(BeobachtenStore::new());

    let (server_side, mut client_side) = duplex(65536);
    let started = Instant::now();

    let task = tokio::spawn(handle_client_stream(
        server_side,
        peer,
        config,
        stats.clone(),
        new_upstream_manager(stats),
        replay_checker,
        Arc::new(BufferPool::new()),
        Arc::new(SecureRandom::new()),
        None,
        Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct)),
        None,
        Arc::new(UserIpTracker::new()),
        beobachten,
        false,
    ));

    client_side.write_all(hello).await.unwrap();

    if drive_mtproto_fail {
        let mut server_hello_head = [0u8; 5];
        client_side
            .read_exact(&mut server_hello_head)
            .await
            .unwrap();
        assert_eq!(server_hello_head[0], 0x16);
        let body_len = u16::from_be_bytes([server_hello_head[3], server_hello_head[4]]) as usize;
        let mut body = vec![0u8; body_len];
        client_side.read_exact(&mut body).await.unwrap();

        let mut invalid_mtproto_record = Vec::with_capacity(5 + HANDSHAKE_LEN);
        invalid_mtproto_record.push(0x17);
        invalid_mtproto_record.extend_from_slice(&TLS_VERSION);
        invalid_mtproto_record.extend_from_slice(&(HANDSHAKE_LEN as u16).to_be_bytes());
        invalid_mtproto_record.extend_from_slice(&vec![0u8; HANDSHAKE_LEN]);
        let mut client_payload = invalid_mtproto_record;
        client_payload.extend_from_slice(b"GET /replay-fallback HTTP/1.1\r\nHost: x\r\n\r\n");
        client_side.write_all(&client_payload).await.unwrap();
    }

    client_side.shutdown().await.unwrap();

    let _ = tokio::time::timeout(Duration::from_secs(4), task)
        .await
        .unwrap()
        .unwrap();

    started.elapsed()
}

#[tokio::test]
async fn replay_reject_still_honors_masking_timing_budget() {
    let replay_checker = Arc::new(ReplayChecker::new(256, Duration::from_secs(60)));
    let hello = make_valid_tls_client_hello(&[0xAB; 16], 7, 600, 0x51);

    let seed_elapsed = run_replay_candidate_session(
        Arc::clone(&replay_checker),
        &hello,
        "198.51.100.201:58001".parse().unwrap(),
        true,
    )
    .await;

    assert!(
        seed_elapsed >= Duration::from_millis(40) && seed_elapsed < Duration::from_millis(250),
        "seed replay-candidate run must honor masking timing budget without unbounded delay"
    );

    let replay_elapsed = run_replay_candidate_session(
        Arc::clone(&replay_checker),
        &hello,
        "198.51.100.202:58002".parse().unwrap(),
        false,
    )
    .await;

    assert!(
        replay_elapsed >= Duration::from_millis(40) && replay_elapsed < Duration::from_millis(250),
        "replay rejection path must still satisfy masking timing budget without unbounded DB/CPU delay"
    );
}
