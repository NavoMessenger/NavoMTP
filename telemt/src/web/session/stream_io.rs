use std::io;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};
use std::time::Instant;

use tokio::io::ReadBuf;
use tokio::sync::Notify;

use super::{DeferredSessionEffects, QUEUE_ITEM_COST, SessionCloseReason, SessionState};
use super::{StreamIdentity, WebSession};
use crate::web::frame;

enum ReadAttempt {
    Ready,
    Pending,
    Backpressure,
}

enum WriteAttempt {
    Ready(usize),
    Pending,
    Closed,
}

impl WebSession {
    /// Polls client-to-server bytes and returns consumed flow-control credit.
    pub(in crate::web) fn poll_read(
        &self,
        stream: StreamIdentity,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let first = self.with_state_effects(|state, effects| {
            self.try_read_locked(state, effects, stream, output, None)
        });
        if !matches!(first, ReadAttempt::Pending) {
            return self.finish_read_attempt(first);
        }

        // Cloning an arbitrary RawWaker may invoke caller code, so it is never
        // performed while the session state is locked.
        let waker = cx.waker().clone();
        let second = self.with_state_effects(|state, effects| {
            self.try_read_locked(state, effects, stream, output, Some(waker))
        });
        self.finish_read_attempt(second)
    }

    fn try_read_locked(
        &self,
        state: &mut SessionState,
        effects: &mut DeferredSessionEffects,
        stream: StreamIdentity,
        output: &mut ReadBuf<'_>,
        prepared_waker: Option<Waker>,
    ) -> ReadAttempt {
        let (count, finished) = {
            let Some(stream_state) = state
                .streams
                .get_mut(&stream.id)
                .filter(|state| state.instance == stream.instance)
            else {
                if let Some(waker) = prepared_waker {
                    effects.drop_waker(waker);
                }
                return ReadAttempt::Ready;
            };
            let Some(chunk) = stream_state.inbound.front_mut() else {
                if let Some(waker) = prepared_waker {
                    if let Some(previous) = stream_state.read_waker.replace(waker) {
                        effects.drop_waker(previous);
                    }
                }
                return ReadAttempt::Pending;
            };
            if let Some(waker) = prepared_waker {
                effects.drop_waker(waker);
            }
            let available = &chunk.bytes[chunk.offset..];
            let count = available.len().min(output.remaining());
            output.put_slice(&available[..count]);
            chunk.offset += count;
            let finished = chunk.offset == chunk.bytes.len();
            if finished {
                stream_state.inbound.pop_front();
            }
            stream_state.receive_window = stream_state.receive_window.saturating_add(count as u32);
            (count, finished)
        };
        let overhead = if finished { QUEUE_ITEM_COST } else { 0 };
        self.release_locked(
            state,
            effects,
            count + overhead,
            usize::from(finished),
            false,
        );
        if !self.queue_window_locked(state, effects, stream.id, count as u32) {
            return ReadAttempt::Backpressure;
        }
        ReadAttempt::Ready
    }

    fn finish_read_attempt(&self, attempt: ReadAttempt) -> Poll<io::Result<()>> {
        match attempt {
            ReadAttempt::Ready => Poll::Ready(Ok(())),
            ReadAttempt::Pending => Poll::Pending,
            ReadAttempt::Backpressure => {
                self.close(SessionCloseReason::Backpressure);
                Poll::Ready(Err(io::Error::other(
                    "WEB session control budget exhausted",
                )))
            }
        }
    }

    /// Polls server-to-client writes against stream credit and bounded queues.
    pub(in crate::web) fn poll_write(
        &self,
        stream: StreamIdentity,
        cx: &mut Context<'_>,
        input: &[u8],
    ) -> Poll<io::Result<usize>> {
        if input.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let first = self.with_state_effects(|state, effects| {
            self.try_write_locked(state, effects, stream, input, None)
        });
        if !matches!(first, WriteAttempt::Pending) {
            return finish_write_attempt(first);
        }

        // The second locked check closes the producer-versus-registration race.
        let waker = cx.waker().clone();
        let second = self.with_state_effects(|state, effects| {
            self.try_write_locked(state, effects, stream, input, Some(waker))
        });
        finish_write_attempt(second)
    }

    fn try_write_locked(
        &self,
        state: &mut SessionState,
        effects: &mut DeferredSessionEffects,
        stream: StreamIdentity,
        input: &[u8],
        prepared_waker: Option<Waker>,
    ) -> WriteAttempt {
        let Some(stream_state) = state
            .streams
            .get_mut(&stream.id)
            .filter(|state| state.instance == stream.instance)
        else {
            if let Some(waker) = prepared_waker {
                effects.drop_waker(waker);
            }
            return WriteAttempt::Closed;
        };
        let count = input
            .len()
            .min(frame::DATA_CHUNK_BYTES)
            .min(self.limits.max_frame_payload_bytes)
            .min(if self.carrier().uses_lanes() {
                self.limits
                    .pending_bytes_per_lane
                    .saturating_sub(frame::HEADER_BYTES + QUEUE_ITEM_COST)
            } else {
                usize::MAX
            })
            .min(stream_state.send_credit as usize);
        if count == 0 {
            install_waker(&mut stream_state.write_waker, prepared_waker, effects);
            return WriteAttempt::Pending;
        }
        if !self.queue_data_locked(state, effects, stream.id, &input[..count]) {
            if let Some(stream_state) = state
                .streams
                .get_mut(&stream.id)
                .filter(|state| state.instance == stream.instance)
            {
                install_waker(&mut stream_state.write_waker, prepared_waker, effects);
            } else if let Some(waker) = prepared_waker {
                effects.drop_waker(waker);
            }
            return WriteAttempt::Pending;
        }
        if let Some(waker) = prepared_waker {
            effects.drop_waker(waker);
        }
        let Some(stream_state) = state
            .streams
            .get_mut(&stream.id)
            .filter(|state| state.instance == stream.instance)
        else {
            return WriteAttempt::Closed;
        };
        stream_state.send_credit -= count as u64;
        state.activity.touch_progress(Instant::now());
        if self.carrier().is_multiplexed() {
            effects.notify(Arc::clone(&self.down_notify));
        }
        WriteAttempt::Ready(count)
    }

    /// Returns the process queue-capacity notification source while the manager lives.
    pub(in crate::web) fn budget_notify(&self) -> Option<Arc<Notify>> {
        self.manager
            .upgrade()
            .map(|manager| manager.budget_notify())
    }
}

fn install_waker(
    slot: &mut Option<Waker>,
    prepared: Option<Waker>,
    effects: &mut DeferredSessionEffects,
) {
    if let Some(prepared) = prepared
        && let Some(previous) = slot.replace(prepared)
    {
        effects.drop_waker(previous);
    }
}

fn finish_write_attempt(attempt: WriteAttempt) -> Poll<io::Result<usize>> {
    match attempt {
        WriteAttempt::Ready(count) => Poll::Ready(Ok(count)),
        WriteAttempt::Pending => Poll::Pending,
        WriteAttempt::Closed => Poll::Ready(Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "WEB logical stream is closed",
        ))),
    }
}

#[cfg(test)]
mod tests;
