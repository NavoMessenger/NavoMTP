use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::futures::OwnedNotified;

use crate::web::session::{StreamIdentity, WebSession};

/// Async byte stream that maps one WEB stream identifier onto carrier frames.
pub(crate) struct WebLogicalStream {
    session: Arc<WebSession>,
    stream: StreamIdentity,
    budget_wait: Option<Pin<Box<OwnedNotified>>>,
}

impl WebLogicalStream {
    /// Binds a virtual byte stream to one live carrier stream identifier.
    pub(crate) fn new(session: Arc<WebSession>, stream: StreamIdentity) -> Self {
        Self {
            session,
            stream,
            budget_wait: None,
        }
    }
}

impl AsyncRead for WebLogicalStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.session.poll_read(self.stream, cx, output)
    }
}

impl AsyncWrite for WebLogicalStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = self.session.poll_write(self.stream, cx, input);
        if !result.is_pending() {
            self.budget_wait = None;
            return result;
        }

        // Register before retrying so a concurrent global-capacity release cannot be lost.
        loop {
            if self.budget_wait.is_none()
                && let Some(notify) = self.session.budget_notify()
            {
                self.budget_wait = Some(Box::pin(notify.notified_owned()));
            }
            let Some(wait) = self.budget_wait.as_mut() else {
                break;
            };
            if wait.as_mut().poll(cx).is_pending() {
                break;
            }
            self.budget_wait = None;
        }
        match self.session.poll_write(self.stream, cx, input) {
            Poll::Ready(result) => {
                self.budget_wait = None;
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}
