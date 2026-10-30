use super::*;
use crate::error::ProxyError;
use crate::stats::Stats;
use crate::stream::BufferPool;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, duplex};
use tokio::time::{Duration, timeout};

struct BrokenPipeWriter;

impl AsyncWrite for BrokenPipeWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "forced broken pipe",
        )))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test(start_paused = true)]
async fn relay_baseline_activity_timeout_fires_after_inactivity() {
    let stats = Arc::new(Stats::new());
    let user = "relay-baseline-idle-timeout";

    let (_client_peer, relay_client) = duplex(1024);
    let (_server_peer, relay_server) = duplex(1024);

    let (client_reader, client_writer) = tokio::io::split(relay_client);
    let (server_reader, server_writer) = tokio::io::split(relay_server);

    let relay_task = tokio::spawn(relay_bidirectional(
        client_reader,
        client_writer,
        server_reader,
        server_writer,
        1024,
        1024,
        user,
        Arc::clone(&stats),
        None,
        Arc::new(BufferPool::new()),
    ));

    tokio::task::yield_now().await;
    tokio::time::advance(ACTIVITY_TIMEOUT.saturating_sub(Duration::from_secs(1))).await;
    tokio::task::yield_now().await;
    assert!(
        !relay_task.is_finished(),
        "relay must stay alive before inactivity timeout"
    );

    tokio::time::advance(WATCHDOG_INTERVAL + Duration::from_secs(2)).await;

    let done = timeout(Duration::from_secs(1), relay_task)
        .await
        .expect("relay must complete after inactivity timeout")
        .expect("relay task must not panic");

    assert!(
        done.is_ok(),
        "relay must return Ok(()) after inactivity timeout"
    );
}

#[tokio::test]
async fn relay_baseline_zero_bytes_returns_ok_and_counters_zero() {
    let stats = Arc::new(Stats::new());
    let user = "relay-baseline-zero-bytes";

    let (client_peer, relay_client) = duplex(1024);
    let (server_peer, relay_server) = duplex(1024);

    let (client_reader, client_writer) = tokio::io::split(relay_client);
    let (server_reader, server_writer) = tokio::io::split(relay_server);

    let relay_task = tokio::spawn(relay_bidirectional(
        client_reader,
        client_writer,
        server_reader,
        server_writer,
        1024,
        1024,
        user,
        Arc::clone(&stats),
        None,
        Arc::new(BufferPool::new()),
    ));

    drop(client_peer);
    drop(server_peer);

    let done = timeout(Duration::from_secs(2), relay_task)
        .await
        .expect("relay must stop after both peers close")
        .expect("relay task must not panic");

    assert!(done.is_ok(), "relay must return Ok(()) on immediate EOF");
    assert_eq!(stats.get_user_total_octets(user), 0);
}

#[tokio::test]
async fn relay_baseline_bidirectional_bytes_counted_symmetrically() {
    let stats = Arc::new(Stats::new());
    let user = "relay-baseline-bidir-counters";

    let (mut client_peer, relay_client) = duplex(16 * 1024);
    let (relay_server, mut server_peer) = duplex(16 * 1024);

    let (client_reader, client_writer) = tokio::io::split(relay_client);
    let (server_reader, server_writer) = tokio::io::split(relay_server);

    let relay_task = tokio::spawn(relay_bidirectional(
        client_reader,
        client_writer,
        server_reader,
        server_writer,
        4096,
        4096,
        user,
        Arc::clone(&stats),
        None,
        Arc::new(BufferPool::new()),
    ));

    let c2s = vec![0xAA; 4096];
    let s2c = vec![0xBB; 2048];

    client_peer.write_all(&c2s).await.unwrap();
    server_peer.write_all(&s2c).await.unwrap();

    let mut seen_c2s = vec![0u8; c2s.len()];
    let mut seen_s2c = vec![0u8; s2c.len()];
    server_peer.read_exact(&mut seen_c2s).await.unwrap();
    client_peer.read_exact(&mut seen_s2c).await.unwrap();

    assert_eq!(seen_c2s, c2s);
    assert_eq!(seen_s2c, s2c);

    drop(client_peer);
    drop(server_peer);

    let done = timeout(Duration::from_secs(2), relay_task)
        .await
        .expect("relay must complete after both peers close")
        .expect("relay task must not panic");
    assert!(done.is_ok());

    assert_eq!(
        stats.get_user_total_octets(user),
        (c2s.len() + s2c.len()) as u64
    );
}

#[tokio::test]
async fn relay_baseline_both_sides_close_simultaneously_no_panic() {
    let stats = Arc::new(Stats::new());

    let (client_peer, relay_client) = duplex(1024);
    let (relay_server, server_peer) = duplex(1024);

    let (client_reader, client_writer) = tokio::io::split(relay_client);
    let (server_reader, server_writer) = tokio::io::split(relay_server);

    let relay_task = tokio::spawn(relay_bidirectional(
        client_reader,
        client_writer,
        server_reader,
        server_writer,
        1024,
        1024,
        "relay-baseline-sim-close",
        Arc::clone(&stats),
        None,
        Arc::new(BufferPool::new()),
    ));

    drop(client_peer);
    drop(server_peer);

    let done = timeout(Duration::from_secs(2), relay_task)
        .await
        .expect("relay must complete")
        .expect("relay task must not panic");
    assert!(done.is_ok());
}

#[tokio::test]
async fn relay_baseline_broken_pipe_midtransfer_returns_error() {
    let stats = Arc::new(Stats::new());
    let user = "relay-baseline-broken-pipe";

    let (mut client_peer, relay_client) = duplex(1024);
    let (client_reader, client_writer) = tokio::io::split(relay_client);

    let relay_task = tokio::spawn(relay_bidirectional(
        client_reader,
        client_writer,
        tokio::io::empty(),
        BrokenPipeWriter,
        1024,
        1024,
        user,
        Arc::clone(&stats),
        None,
        Arc::new(BufferPool::new()),
    ));

    client_peer.write_all(b"trigger").await.unwrap();

    let done = timeout(Duration::from_secs(2), relay_task)
        .await
        .expect("relay must return after broken pipe")
        .expect("relay task must not panic");

    match done {
        Err(ProxyError::Io(err)) => {
            assert!(
                matches!(
                    err.kind(),
                    io::ErrorKind::BrokenPipe | io::ErrorKind::ConnectionReset
                ),
                "expected BrokenPipe/ConnectionReset, got {:?}",
                err.kind()
            );
        }
        other => panic!("expected ProxyError::Io, got {other:?}"),
    }
}

#[tokio::test]
async fn relay_baseline_many_small_writes_exact_counter() {
    let stats = Arc::new(Stats::new());
    let user = "relay-baseline-many-small";

    let (mut client_peer, relay_client) = duplex(4096);
    let (relay_server, mut server_peer) = duplex(4096);

    let (client_reader, client_writer) = tokio::io::split(relay_client);
    let (server_reader, server_writer) = tokio::io::split(relay_server);

    let relay_task = tokio::spawn(relay_bidirectional(
        client_reader,
        client_writer,
        server_reader,
        server_writer,
        1024,
        1024,
        user,
        Arc::clone(&stats),
        None,
        Arc::new(BufferPool::new()),
    ));

    for i in 0..10_000u32 {
        let b = [(i & 0xFF) as u8];
        client_peer.write_all(&b).await.unwrap();
        let mut seen = [0u8; 1];
        server_peer.read_exact(&mut seen).await.unwrap();
        assert_eq!(seen, b);
    }

    drop(client_peer);
    drop(server_peer);

    let done = timeout(Duration::from_secs(3), relay_task)
        .await
        .expect("relay must complete for many small writes")
        .expect("relay task must not panic");
    assert!(done.is_ok());
    assert_eq!(stats.get_user_total_octets(user), 10_000);
}
