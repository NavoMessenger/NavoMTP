use super::*;
use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Wake};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::Instant;

enum ReadStep {
    Data(Vec<u8>),
    Pending,
    Eof,
    Error,
}

struct ScriptedReader {
    scripted_reads: Arc<Mutex<VecDeque<ReadStep>>>,
    read_calls: Arc<AtomicUsize>,
}

impl ScriptedReader {
    fn new(script: Vec<ReadStep>, read_calls: Arc<AtomicUsize>) -> Self {
        Self {
            scripted_reads: Arc::new(Mutex::new(script.into())),
            read_calls,
        }
    }
}

impl AsyncRead for ScriptedReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.read_calls.fetch_add(1, Ordering::Relaxed);
        let step = this
            .scripted_reads
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pop_front()
            .unwrap_or(ReadStep::Eof);
        match step {
            ReadStep::Data(data) => {
                let n = data.len().min(buf.remaining());
                buf.put_slice(&data[..n]);
                Poll::Ready(Ok(()))
            }
            ReadStep::Pending => Poll::Pending,
            ReadStep::Eof => Poll::Ready(Ok(())),
            ReadStep::Error => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "forced read failure",
            ))),
        }
    }
}

struct NoopWake;

impl Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}

struct ScriptedWriter {
    scripted_writes: Arc<Mutex<VecDeque<usize>>>,
    write_calls: Arc<AtomicUsize>,
}

impl ScriptedWriter {
    fn new(script: &[usize], write_calls: Arc<AtomicUsize>) -> Self {
        Self {
            scripted_writes: Arc::new(Mutex::new(script.iter().copied().collect())),
            write_calls,
        }
    }
}

impl AsyncWrite for ScriptedWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.write_calls.fetch_add(1, Ordering::Relaxed);
        let planned = this
            .scripted_writes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pop_front()
            .unwrap_or(buf.len());
        Poll::Ready(Ok(planned.min(buf.len())))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn make_stats_io_with_script(
    user: &str,
    quota_limit: u64,
    precharged_quota: u64,
    script: &[usize],
) -> (
    StatsIo<ScriptedWriter>,
    Arc<Stats>,
    Arc<AtomicUsize>,
    Arc<AtomicBool>,
) {
    let stats = Arc::new(Stats::new());
    if precharged_quota > 0 {
        let user_stats = stats.get_or_create_user_stats_handle(user);
        stats.quota_charge_post_write(user_stats.as_ref(), precharged_quota);
    }

    let write_calls = Arc::new(AtomicUsize::new(0));
    let quota_exceeded = Arc::new(AtomicBool::new(false));
    let io = StatsIo::new(
        ScriptedWriter::new(script, write_calls.clone()),
        Arc::new(SharedCounters::new()),
        stats.clone(),
        user.to_string(),
        Some(quota_limit),
        quota_exceeded.clone(),
        Instant::now(),
    );

    (io, stats, write_calls, quota_exceeded)
}

fn make_stats_io_with_read_script(
    user: &str,
    quota_limit: u64,
    precharged_quota: u64,
    script: Vec<ReadStep>,
) -> (
    StatsIo<ScriptedReader>,
    Arc<Stats>,
    Arc<AtomicUsize>,
    Arc<AtomicBool>,
) {
    let stats = Arc::new(Stats::new());
    if precharged_quota > 0 {
        let user_stats = stats.get_or_create_user_stats_handle(user);
        stats.quota_charge_post_write(user_stats.as_ref(), precharged_quota);
    }

    let read_calls = Arc::new(AtomicUsize::new(0));
    let quota_exceeded = Arc::new(AtomicBool::new(false));
    let io = StatsIo::new(
        ScriptedReader::new(script, read_calls.clone()),
        Arc::new(SharedCounters::new()),
        stats.clone(),
        user.to_string(),
        Some(quota_limit),
        quota_exceeded.clone(),
        Instant::now(),
    );

    (io, stats, read_calls, quota_exceeded)
}

fn poll_read_once<R: AsyncRead + Unpin>(
    io: &mut StatsIo<R>,
    storage: &mut [u8],
) -> Poll<io::Result<usize>> {
    let waker = Arc::new(NoopWake).into();
    let mut cx = Context::from_waker(&waker);
    let mut read_buf = ReadBuf::new(storage);
    let before = read_buf.filled().len();
    match Pin::new(io).poll_read(&mut cx, &mut read_buf) {
        Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len() - before)),
        Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
        Poll::Pending => Poll::Pending,
    }
}

#[test]
fn direct_c2s_quota_refunds_unused_on_short_read() {
    let user = "direct-c2s-short-read-refund-user";
    let (mut io, stats, read_calls, quota_exceeded) =
        make_stats_io_with_read_script(user, 64, 0, vec![ReadStep::Data(vec![0x11; 5])]);
    let mut storage = [0u8; 16];

    let n = match poll_read_once(&mut io, &mut storage) {
        Poll::Ready(Ok(n)) => n,
        other => panic!("short read must complete, got {other:?}"),
    };

    assert_eq!(n, 5);
    assert_eq!(read_calls.load(Ordering::Relaxed), 1);
    assert_eq!(stats.get_user_quota_used(user), 5);
    assert_eq!(stats.get_quota_refund_bytes_total(), 11);
    assert!(!quota_exceeded.load(Ordering::Acquire));
}

#[test]
fn direct_c2s_quota_refunds_full_reservation_on_pending() {
    let user = "direct-c2s-pending-refund-user";
    let (mut io, stats, read_calls, quota_exceeded) =
        make_stats_io_with_read_script(user, 64, 0, vec![ReadStep::Pending]);
    let mut storage = [0u8; 16];

    assert!(matches!(
        poll_read_once(&mut io, &mut storage),
        Poll::Pending
    ));
    assert_eq!(read_calls.load(Ordering::Relaxed), 1);
    assert_eq!(stats.get_user_quota_used(user), 0);
    assert_eq!(stats.get_quota_refund_bytes_total(), 16);
    assert!(!quota_exceeded.load(Ordering::Acquire));
}

#[test]
fn direct_c2s_quota_refunds_full_reservation_on_eof() {
    let user = "direct-c2s-eof-refund-user";
    let (mut io, stats, read_calls, quota_exceeded) =
        make_stats_io_with_read_script(user, 64, 0, vec![ReadStep::Eof]);
    let mut storage = [0u8; 16];

    let n = match poll_read_once(&mut io, &mut storage) {
        Poll::Ready(Ok(n)) => n,
        other => panic!("EOF read must complete with zero bytes, got {other:?}"),
    };

    assert_eq!(n, 0);
    assert_eq!(read_calls.load(Ordering::Relaxed), 1);
    assert_eq!(stats.get_user_quota_used(user), 0);
    assert_eq!(stats.get_quota_refund_bytes_total(), 16);
    assert!(!quota_exceeded.load(Ordering::Acquire));
}

#[test]
fn direct_c2s_quota_refunds_full_reservation_on_error() {
    let user = "direct-c2s-error-refund-user";
    let (mut io, stats, read_calls, quota_exceeded) =
        make_stats_io_with_read_script(user, 64, 0, vec![ReadStep::Error]);
    let mut storage = [0u8; 16];

    let error = match poll_read_once(&mut io, &mut storage) {
        Poll::Ready(Err(error)) => error,
        other => panic!("error read must return error, got {other:?}"),
    };

    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(read_calls.load(Ordering::Relaxed), 1);
    assert_eq!(stats.get_user_quota_used(user), 0);
    assert_eq!(stats.get_quota_refund_bytes_total(), 16);
    assert!(!quota_exceeded.load(Ordering::Acquire));
}

#[tokio::test]
async fn direct_partial_write_charges_only_committed_bytes_without_double_charge() {
    let user = "direct-partial-charge-user";
    let (mut io, stats, write_calls, quota_exceeded) =
        make_stats_io_with_script(user, 1_048_576, 0, &[8 * 1024, 8 * 1024, 48 * 1024]);
    let payload = vec![0xAB; 64 * 1024];

    let n1 = io
        .write(&payload)
        .await
        .expect("first partial write must succeed");
    let n2 = io
        .write(&payload)
        .await
        .expect("second partial write must succeed");
    let n3 = io.write(&payload).await.expect("tail write must succeed");

    assert_eq!(n1, 8 * 1024);
    assert_eq!(n2, 8 * 1024);
    assert_eq!(n3, 48 * 1024);
    assert_eq!(write_calls.load(Ordering::Relaxed), 3);
    assert_eq!(
        stats.get_user_quota_used(user),
        (n1 + n2 + n3) as u64,
        "quota accounting must follow committed bytes only"
    );
    assert_eq!(
        stats.get_user_total_octets(user),
        (n1 + n2 + n3) as u64,
        "telemetry octets should match committed bytes on successful writes"
    );
    assert!(
        !quota_exceeded.load(Ordering::Acquire),
        "quota flag should stay false under large remaining budget"
    );
}

#[tokio::test]
async fn direct_hybrid_branch_selection_matches_contract() {
    let near_limit = 256 * 1024u64;
    let near_remaining = 32 * 1024u64;
    let (mut near_io, _stats, _calls, _flag) = make_stats_io_with_script(
        "direct-near-limit-hard-check-user",
        near_limit,
        near_limit - near_remaining,
        &[4 * 1024],
    );
    let near_payload = vec![0x11; 4 * 1024];
    let near_written = near_io
        .write(&near_payload)
        .await
        .expect("near-limit write must succeed");
    assert_eq!(near_written, 4 * 1024);
    assert_eq!(
        near_io.quota_bytes_since_check, 0,
        "near-limit branch must go through immediate hard check"
    );

    let (mut far_small_io, _stats, _calls, _flag) =
        make_stats_io_with_script("direct-far-small-amortized-user", 1_048_576, 0, &[4 * 1024]);
    let far_small_payload = vec![0x22; 4 * 1024];
    let far_small_written = far_small_io
        .write(&far_small_payload)
        .await
        .expect("small far-from-limit write must succeed");
    assert_eq!(far_small_written, 4 * 1024);
    assert_eq!(
        far_small_io.quota_bytes_since_check,
        4 * 1024,
        "small far-from-limit write must go through amortized path"
    );

    let (mut far_large_io, _stats, _calls, _flag) = make_stats_io_with_script(
        "direct-far-large-hard-check-user",
        1_048_576,
        0,
        &[32 * 1024],
    );
    let far_large_payload = vec![0x33; 32 * 1024];
    let far_large_written = far_large_io
        .write(&far_large_payload)
        .await
        .expect("large write must succeed");
    assert_eq!(far_large_written, 32 * 1024);
    assert_eq!(
        far_large_io.quota_bytes_since_check, 0,
        "large write must force immediate hard check even far from limit"
    );
}

#[tokio::test]
async fn remaining_before_zero_rejects_without_calling_inner_writer() {
    let user = "direct-zero-remaining-user";
    let limit = 8u64;
    let (mut io, stats, write_calls, quota_exceeded) =
        make_stats_io_with_script(user, limit, limit, &[1]);

    let err = io
        .write(&[0x44])
        .await
        .expect_err("write must fail when remaining quota is zero");

    assert!(
        is_quota_io_error(&err),
        "zero-remaining gate must return typed quota I/O error"
    );
    assert_eq!(
        write_calls.load(Ordering::Relaxed),
        0,
        "inner poll_write must not be called when remaining quota is zero"
    );
    assert!(
        quota_exceeded.load(Ordering::Acquire),
        "zero-remaining gate must set exceeded flag"
    );
    assert_eq!(stats.get_user_quota_used(user), limit);
}

#[tokio::test]
async fn exceeded_flag_blocks_following_poll_before_inner_write() {
    let user = "direct-exceeded-visibility-user";
    let (mut io, stats, write_calls, quota_exceeded) =
        make_stats_io_with_script(user, 1, 0, &[1, 1]);

    let first = io
        .write(&[0x55])
        .await
        .expect("first byte should consume remaining quota");
    assert_eq!(first, 1);
    assert!(
        quota_exceeded.load(Ordering::Acquire),
        "hard check should store quota_exceeded after boundary hit"
    );

    let second = io
        .write(&[0x66])
        .await
        .expect_err("next write must be rejected by early exceeded gate");
    assert!(
        is_quota_io_error(&second),
        "following write must fail with typed quota error"
    );
    assert_eq!(
        write_calls.load(Ordering::Relaxed),
        1,
        "second write must be cut before touching inner writer"
    );
    assert_eq!(stats.get_user_quota_used(user), 1);
}

#[test]
fn adaptive_interval_clamp_matches_contract() {
    assert_eq!(quota_adaptive_interval_bytes(0), 4 * 1024);
    assert_eq!(quota_adaptive_interval_bytes(2 * 1024), 4 * 1024);
    assert_eq!(quota_adaptive_interval_bytes(32 * 1024), 16 * 1024);
    assert_eq!(quota_adaptive_interval_bytes(256 * 1024), 64 * 1024);

    assert!(should_immediate_quota_check(32 * 1024, 4 * 1024));
    assert!(should_immediate_quota_check(1_048_576, 32 * 1024));
    assert!(!should_immediate_quota_check(1_048_576, 4 * 1024));
}
