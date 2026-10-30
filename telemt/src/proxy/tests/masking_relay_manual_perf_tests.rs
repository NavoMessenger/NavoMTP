use super::*;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Duration, Instant};

const PERF_TOTAL_BYTES: usize = 64 * 1024 * 1024;

struct PatternReader {
    remaining: usize,
    chunk: usize,
    read_calls: AtomicUsize,
}

impl PatternReader {
    fn new(total: usize, chunk: usize) -> Self {
        Self {
            remaining: total,
            chunk,
            read_calls: AtomicUsize::new(0),
        }
    }

    fn read_calls(&self) -> usize {
        self.read_calls.load(Ordering::Relaxed)
    }
}

impl AsyncRead for PatternReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.read_calls.fetch_add(1, Ordering::Relaxed);
        if self.remaining == 0 {
            return Poll::Ready(Ok(()));
        }

        let take = self.remaining.min(self.chunk).min(buf.remaining());
        if take == 0 {
            return Poll::Ready(Ok(()));
        }

        static PATTERN: [u8; MASK_BUFFER_MAX_SIZE] = [0xA5; MASK_BUFFER_MAX_SIZE];
        buf.put_slice(&PATTERN[..take]);
        self.remaining -= take;
        Poll::Ready(Ok(()))
    }
}

#[derive(Default)]
struct CountingWriter {
    written: usize,
}

impl AsyncWrite for CountingWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.written = self.written.saturating_add(buf.len());
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
#[ignore = "manual benchmark: throughput-sensitive and host-dependent"]
async fn masking_copy_with_idle_timeout_manual_throughput() {
    let mut reader = PatternReader::new(PERF_TOTAL_BYTES, MASK_BUFFER_MAX_SIZE);
    let mut writer = CountingWriter::default();
    let started = Instant::now();

    let outcome = copy_with_idle_timeout(
        &mut reader,
        &mut writer,
        PERF_TOTAL_BYTES,
        true,
        Duration::from_secs(30),
    )
    .await;

    let elapsed = started.elapsed();
    let mb = PERF_TOTAL_BYTES as f64 / (1024.0 * 1024.0);
    let mbps = mb / elapsed.as_secs_f64();

    assert_eq!(outcome.total, PERF_TOTAL_BYTES);
    assert_eq!(writer.written, PERF_TOTAL_BYTES);
    assert!(
        !outcome.ended_by_eof,
        "manual throughput run should terminate at byte cap"
    );

    eprintln!(
        "masking manual throughput: bytes={} elapsed_ms={} mib_per_sec={:.2} read_calls={}",
        PERF_TOTAL_BYTES,
        elapsed.as_millis(),
        mbps,
        reader.read_calls()
    );
}
