use crate::config::ProxyConfig;
use rand::SeedableRng;
use rand::rngs::StdRng;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::AsyncWrite;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{RawWaker, RawWakerVTable, Waker};

    unsafe fn wake_counter_clone(data: *const ()) -> RawWaker {
        let arc = Arc::<AtomicUsize>::from_raw(data.cast::<AtomicUsize>());
        let cloned = Arc::clone(&arc);
        let _ = Arc::into_raw(arc);
        RawWaker::new(
            Arc::into_raw(cloned).cast::<()>(),
            &WAKE_COUNTER_WAKER_VTABLE,
        )
    }

    unsafe fn wake_counter_wake(data: *const ()) {
        let arc = Arc::<AtomicUsize>::from_raw(data.cast::<AtomicUsize>());
        arc.fetch_add(1, Ordering::SeqCst);
    }

    unsafe fn wake_counter_wake_by_ref(data: *const ()) {
        let arc = Arc::<AtomicUsize>::from_raw(data.cast::<AtomicUsize>());
        arc.fetch_add(1, Ordering::SeqCst);
        let _ = Arc::into_raw(arc);
    }

    unsafe fn wake_counter_drop(data: *const ()) {
        let _ = Arc::<AtomicUsize>::from_raw(data.cast::<AtomicUsize>());
    }

    static WAKE_COUNTER_WAKER_VTABLE: RawWakerVTable = RawWakerVTable::new(
        wake_counter_clone,
        wake_counter_wake,
        wake_counter_wake_by_ref,
        wake_counter_drop,
    );

    fn wake_counter_waker(counter: Arc<AtomicUsize>) -> Waker {
        let raw = RawWaker::new(
            Arc::into_raw(counter).cast::<()>(),
            &WAKE_COUNTER_WAKER_VTABLE,
        );
        // SAFETY: `raw` points to a valid `Arc<AtomicUsize>` and uses a vtable
        // that preserves Arc reference-counting semantics.
        unsafe { Waker::from_raw(raw) }
    }

    #[test]
    fn pending_count_writer_write_pending_does_not_spurious_wake() {
        let counter = Arc::new(AtomicUsize::new(0));
        let waker = wake_counter_waker(Arc::clone(&counter));
        let mut cx = Context::from_waker(&waker);

        let mut writer = PendingCountWriter::new(RecordingWriter::new(), 1, 0);
        let poll = Pin::new(&mut writer).poll_write(&mut cx, b"x");

        assert!(matches!(poll, Poll::Pending));
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn pending_count_writer_flush_pending_does_not_spurious_wake() {
        let counter = Arc::new(AtomicUsize::new(0));
        let waker = wake_counter_waker(Arc::clone(&counter));
        let mut cx = Context::from_waker(&waker);

        let mut writer = PendingCountWriter::new(RecordingWriter::new(), 0, 1);
        let poll = Pin::new(&mut writer).poll_flush(&mut cx);

        assert!(matches!(poll, Poll::Pending));
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }
}

// In-memory AsyncWrite that records both per-write and per-flush granularity.
pub struct RecordingWriter {
    pub writes: Vec<Vec<u8>>,
    pub flushed: Vec<Vec<u8>>,
    current_record: Vec<u8>,
}

impl RecordingWriter {
    pub fn new() -> Self {
        Self {
            writes: Vec::new(),
            flushed: Vec::new(),
            current_record: Vec::new(),
        }
    }

    pub fn total_bytes(&self) -> usize {
        self.writes.iter().map(|w| w.len()).sum()
    }
}

impl Default for RecordingWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl AsyncWrite for RecordingWriter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.as_mut().get_mut();
        me.writes.push(buf.to_vec());
        me.current_record.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.as_mut().get_mut();
        let record = std::mem::take(&mut me.current_record);
        if !record.is_empty() {
            me.flushed.push(record);
        }
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

// Returns Poll::Pending for the first N write/flush calls, then delegates.
pub struct PendingCountWriter<W> {
    pub inner: W,
    pub write_pending_remaining: usize,
    pub flush_pending_remaining: usize,
}

impl<W> PendingCountWriter<W> {
    pub fn new(inner: W, write_pending: usize, flush_pending: usize) -> Self {
        Self {
            inner,
            write_pending_remaining: write_pending,
            flush_pending_remaining: flush_pending,
        }
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for PendingCountWriter<W> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.as_mut().get_mut();
        if me.write_pending_remaining > 0 {
            me.write_pending_remaining -= 1;
            return Poll::Pending;
        }
        Pin::new(&mut me.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let me = self.as_mut().get_mut();
        if me.flush_pending_remaining > 0 {
            me.flush_pending_remaining -= 1;
            return Poll::Pending;
        }
        Pin::new(&mut me.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

pub fn seeded_rng(seed: u64) -> StdRng {
    StdRng::seed_from_u64(seed)
}

pub fn tls_only_config() -> Arc<ProxyConfig> {
    let mut cfg = ProxyConfig::default();
    cfg.general.modes.tls = true;
    Arc::new(cfg)
}

pub fn handshake_test_config(secret_hex: &str) -> ProxyConfig {
    let mut cfg = ProxyConfig::default();
    cfg.access.users.clear();
    cfg.access
        .users
        .insert("test-user".to_string(), secret_hex.to_string());
    cfg.access.ignore_time_skew = true;
    cfg.censorship.mask = true;
    cfg.censorship.mask_host = Some("127.0.0.1".to_string());
    cfg.censorship.mask_port = 0;
    cfg
}
