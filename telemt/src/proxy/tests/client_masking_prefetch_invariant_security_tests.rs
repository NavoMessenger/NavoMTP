use super::*;
use crate::config::{UpstreamConfig, UpstreamType};
use crate::crypto::sha256_hmac;
use crate::protocol::constants::{HANDSHAKE_LEN, TLS_VERSION};
use crate::protocol::tls;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::net::TcpListener;

struct PipelineHarness {
    config: Arc<ProxyConfig>,
    stats: Arc<Stats>,
    upstream_manager: Arc<UpstreamManager>,
    replay_checker: Arc<ReplayChecker>,
    buffer_pool: Arc<BufferPool>,
    rng: Arc<SecureRandom>,
    route_runtime: Arc<RouteRuntimeController>,
    ip_tracker: Arc<UserIpTracker>,
    beobachten: Arc<BeobachtenStore>,
}

fn build_harness(secret_hex: &str, mask_port: u16) -> PipelineHarness {
    let mut cfg = ProxyConfig::default();
    cfg.general.beobachten = false;
    cfg.censorship.mask = true;
    cfg.censorship.mask_unix_sock = None;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_port = mask_port;
    cfg.censorship.mask_proxy_protocol = 0;
    cfg.access.ignore_time_skew = true;
    cfg.access
        .users
        .insert("user".to_string(), secret_hex.to_string());

    let config = Arc::new(cfg);
    let stats = Arc::new(Stats::new());
    let upstream_manager = Arc::new(UpstreamManager::new(
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
        stats.clone(),
    ));

    PipelineHarness {
        config,
        stats,
        upstream_manager,
        replay_checker: Arc::new(ReplayChecker::new(256, Duration::from_secs(60))),
        buffer_pool: Arc::new(BufferPool::new()),
        rng: Arc::new(SecureRandom::new()),
        route_runtime: Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct)),
        ip_tracker: Arc::new(UserIpTracker::new()),
        beobachten: Arc::new(BeobachtenStore::new()),
    }
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

fn wrap_tls_application_data(payload: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(5 + payload.len());
    record.push(0x17);
    record.extend_from_slice(&TLS_VERSION);
    record.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    record.extend_from_slice(payload);
    record
}

async fn read_and_discard_tls_record_body<T>(stream: &mut T, header: [u8; 5])
where
    T: tokio::io::AsyncRead + Unpin,
{
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).await.unwrap();
}

#[test]
fn empty_initial_data_prefetch_gate_is_fail_closed() {
    assert!(
        !should_prefetch_mask_classifier_window(&[]),
        "empty initial_data must not trigger classifier prefetch"
    );
}

#[tokio::test]
async fn blackhat_empty_initial_data_prefetch_must_not_consume_fallback_payload() {
    let payload = b"\x17\x03\x03\x00\x10coalesced-tail-bytes".to_vec();
    let (mut reader, mut writer) = duplex(1024);

    writer.write_all(&payload).await.unwrap();
    writer.shutdown().await.unwrap();

    let mut initial_data = Vec::new();
    extend_masking_initial_window(&mut reader, &mut initial_data).await;

    assert!(
        initial_data.is_empty(),
        "empty initial_data must remain empty after prefetch stage"
    );

    let mut remaining = Vec::new();
    reader.read_to_end(&mut remaining).await.unwrap();
    assert_eq!(
        remaining, payload,
        "prefetch stage must not consume fallback payload when initial_data is empty"
    );
}

#[tokio::test]
async fn positive_fragmented_http_prefix_still_prefetches_within_window() {
    let (mut reader, mut writer) = duplex(1024);
    writer
        .write_all(b"NECT example.org:443 HTTP/1.1\r\n")
        .await
        .unwrap();
    writer.shutdown().await.unwrap();

    let mut initial_data = b"CON".to_vec();
    extend_masking_initial_window(&mut reader, &mut initial_data).await;

    assert!(
        initial_data.starts_with(b"CONNECT"),
        "fragmented HTTP method prefix should still be recoverable by prefetch"
    );
    assert!(
        initial_data.len() <= 16,
        "prefetch window must remain bounded"
    );
}

#[tokio::test]
async fn light_fuzz_empty_initial_data_never_prefetches_any_bytes() {
    let mut seed = 0xD15C_A11E_2026_0322u64;

    for _ in 0..128 {
        seed ^= seed << 7;
        seed ^= seed >> 9;
        seed ^= seed << 8;

        let len = ((seed & 0x3f) as usize).saturating_add(1);
        let mut payload = vec![0u8; len];
        for (idx, byte) in payload.iter_mut().enumerate() {
            *byte = (seed as u8).wrapping_add(idx as u8).wrapping_mul(17);
        }

        let (mut reader, mut writer) = duplex(1024);
        writer.write_all(&payload).await.unwrap();
        writer.shutdown().await.unwrap();

        let mut initial_data = Vec::new();
        extend_masking_initial_window(&mut reader, &mut initial_data).await;
        assert!(initial_data.is_empty());

        let mut remaining = Vec::new();
        reader.read_to_end(&mut remaining).await.unwrap();
        assert_eq!(remaining, payload);
    }
}

#[tokio::test]
async fn blackhat_integration_empty_initial_data_path_is_byte_exact_and_eof_clean() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_addr = listener.local_addr().unwrap();

    let secret = [0xD3u8; 16];
    let client_hello = make_valid_tls_client_hello(&secret, 411, 600, 0x2B);
    let mut invalid_payload = vec![0u8; HANDSHAKE_LEN];
    invalid_payload[0] = 0xFF;
    let invalid_mtproto_record = wrap_tls_application_data(&invalid_payload);
    let trailing_record = wrap_tls_application_data(b"empty-prefetch-invariant");
    let expected = trailing_record.clone();

    let accept_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();

        let mut got = vec![0u8; expected.len()];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(got, expected);

        let mut one = [0u8; 1];
        let n = stream.read(&mut one).await.unwrap();
        assert_eq!(
            n, 0,
            "fallback stream must not append synthetic bytes on empty initial_data path"
        );
    });

    let harness = build_harness("d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3d3", backend_addr.port());
    let (server_side, mut client_side) = duplex(131072);

    let handler = tokio::spawn(handle_client_stream(
        server_side,
        "198.51.100.245:56145".parse().unwrap(),
        harness.config,
        harness.stats,
        harness.upstream_manager,
        harness.replay_checker,
        harness.buffer_pool,
        harness.rng,
        None,
        harness.route_runtime,
        None,
        harness.ip_tracker,
        harness.beobachten,
        false,
    ));

    client_side.write_all(&client_hello).await.unwrap();
    let mut head = [0u8; 5];
    client_side.read_exact(&mut head).await.unwrap();
    assert_eq!(head[0], 0x16);
    read_and_discard_tls_record_body(&mut client_side, head).await;

    let mut client_payload = invalid_mtproto_record;
    client_payload.extend_from_slice(&trailing_record);
    client_side.write_all(&client_payload).await.unwrap();
    client_side.shutdown().await.unwrap();

    tokio::time::timeout(Duration::from_secs(3), accept_task)
        .await
        .unwrap()
        .unwrap();

    let _ = tokio::time::timeout(Duration::from_secs(3), handler)
        .await
        .unwrap()
        .unwrap();
}
