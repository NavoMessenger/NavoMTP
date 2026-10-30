use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

// ============= CombinedStream =============

/// Combines separate read and write halves into a single bidirectional stream.
///
/// `copy_bidirectional` requires `AsyncRead + AsyncWrite` on each side,
/// but the handshake layer produces split reader/writer pairs
/// (e.g. `CryptoReader<FakeTlsReader<OwnedReadHalf>>` + `CryptoWriter<...>`).
///
/// This wrapper reunifies them with zero overhead — each trait method
/// delegates directly to the corresponding half. No buffering, no copies.
///
/// Safety: `poll_read` only touches `reader`, `poll_write` only touches `writer`,
/// so there's no aliasing even though both are called on the same `&mut self`.
pub(in crate::proxy::relay) struct CombinedStream<R, W> {
    reader: R,
    writer: W,
}

impl<R, W> CombinedStream<R, W> {
    pub(in crate::proxy::relay) fn new(reader: R, writer: W) -> Self {
        Self { reader, writer }
    }
}

impl<R: AsyncRead + Unpin, W: Unpin> AsyncRead for CombinedStream<R, W> {
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().reader).poll_read(cx, buf)
    }
}

impl<R: Unpin, W: AsyncWrite + Unpin> AsyncWrite for CombinedStream<R, W> {
    #[inline]
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().writer).poll_write(cx, buf)
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().writer).poll_shutdown(cx)
    }
}
