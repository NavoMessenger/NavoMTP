use super::*;
use std::task::{Context, Poll};

/// Writer-local physical lifetime, independent of registry visibility.
pub(in crate::transport::middle_proxy) struct ReplacementHandoff {
    state: parking_lot::Mutex<HandoffState>,
}

enum HandoffState {
    Open(Option<WriterOpenReservation>),
    Closed,
}

impl ReplacementHandoff {
    /// Creates a handoff that may accept one physical-overlap token.
    pub(in crate::transport::middle_proxy) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: parking_lot::Mutex::new(HandoffState::Open(None)),
        })
    }

    fn close(&self) {
        *self.state.lock() = HandoffState::Closed;
    }

    /// Keeps attachment reversible until the final registry validation has succeeded.
    pub(super) fn commit(
        &self,
        permit: &mut Option<WriterOpenReservation>,
        validate: impl FnOnce() -> bool,
    ) -> bool {
        let mut state = self.state.lock();
        match &mut *state {
            HandoffState::Open(slot) if slot.is_none() && permit.is_some() && validate() => {
                *slot = permit.take();
                true
            }
            _ => false,
        }
    }
}

/// Destroys transport futures before releasing either opening or retiring capacity.
pub(super) struct WriterTransport {
    future: Option<Pin<Box<dyn Future<Output = ()> + Send + 'static>>>,
    /// Shared with the registry but closed only by transport destruction.
    pub(super) lifetime: Arc<ReplacementHandoff>,
    /// Moves to the victim on replacement or is released after normal publication.
    pub(super) opening: Option<WriterOpenReservation>,
}

impl WriterTransport {
    /// Owns prepared transports even if their task is never polled or published.
    pub(super) fn new(
        future: Pin<Box<dyn Future<Output = ()> + Send + 'static>>,
        opening: WriterOpenReservation,
    ) -> Self {
        Self {
            future: Some(future),
            lifetime: ReplacementHandoff::new(),
            opening: Some(opening),
        }
    }
}

impl Future for WriterTransport {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        match self.future.as_mut() {
            Some(future) => future.as_mut().poll(cx),
            None => Poll::Ready(()),
        }
    }
}

impl Drop for WriterTransport {
    fn drop(&mut self) {
        // Explicit order also applies to unpolled futures, panic unwinding and abort.
        drop(self.future.take());
        self.lifetime.close();
        drop(self.opening.take());
    }
}

#[cfg(test)]
mod tests;
