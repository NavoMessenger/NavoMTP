use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Limited};
use hyper::Request;
use hyper::body::{Body, Frame, Incoming, SizeHint};

use crate::web::manager::WebProcessRuntime;
use crate::web::trace::{HttpTraceExchange, TraceBodyState, TraceDirection};

/// Incoming request body wrapper that observes frames without changing streaming semantics.
pub(super) struct RequestBody {
    inner: Incoming,
    trace: Option<Arc<HttpTraceExchange>>,
    terminal: bool,
}

impl RequestBody {
    /// Wraps one Hyper request body with optional enabled-only capture state.
    pub(super) fn new(inner: Incoming, trace: Option<Arc<HttpTraceExchange>>) -> Self {
        Self {
            inner,
            trace,
            terminal: false,
        }
    }

    /// Completes observation for a request whose Hyper body is already empty.
    pub(super) fn finish_empty(&mut self) -> bool {
        if !self.inner.is_end_stream() {
            return false;
        }
        self.finish(TraceBodyState::Complete);
        true
    }

    fn finish(&mut self, state: TraceBodyState) {
        if self.terminal {
            return;
        }
        self.terminal = true;
        if let Some(trace) = &self.trace {
            trace.body_finished(TraceDirection::Request, state);
        }
    }
}

impl Body for RequestBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let result = Pin::new(&mut self.inner).poll_frame(context);
        match &result {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref()
                    && let Some(trace) = &self.trace
                {
                    trace.body_data(TraceDirection::Request, data);
                }
                if self.inner.is_end_stream() {
                    self.finish(TraceBodyState::Complete);
                }
            }
            Poll::Ready(Some(Err(_))) => self.finish(TraceBodyState::Error),
            Poll::Ready(None) => self.finish(TraceBodyState::Complete),
            Poll::Pending => {}
        }
        result
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

impl Drop for RequestBody {
    fn drop(&mut self) {
        self.finish(TraceBodyState::Aborted);
    }
}

/// Collected carrier request retaining its process-wide body reservation.
pub(super) struct CollectedBody {
    /// Request head reconstructed without the consumed network body.
    pub(super) request: Request<Empty<Bytes>>,
    /// Fully collected bounded carrier payload.
    pub(super) body: Bytes,
    /// Byte-budget reservation held through request processing.
    pub(super) _body_budget: tokio::sync::OwnedSemaphorePermit,
}

// Keep rejected requests inline to avoid attacker-controlled allocations on invalid bodies.
#[allow(clippy::large_enum_variant)]
/// Body collection failure with sanitized request context when decoy routing is safe.
pub(super) enum CollectBodyError {
    /// The body shape, size, or deadline failed after retaining the request head.
    Invalid(Request<Empty<Bytes>>),
    /// Process-wide body reader or byte capacity is temporarily exhausted.
    Limit,
}

/// Collects one bounded carrier body under reader, byte, and deadline ownership.
pub(super) async fn collect_body(
    request: Request<RequestBody>,
    runtime: &WebProcessRuntime,
    body_timeout: Duration,
    limit: usize,
    allow_empty: bool,
) -> Result<CollectedBody, CollectBodyError> {
    let request_deadline = super::request_deadline(&request);
    let exceeds_limit = request.body().size_hint().lower() > limit as u64
        || request
            .body()
            .size_hint()
            .upper()
            .is_some_and(|upper| upper > limit as u64);
    let (parts, body) = request.into_parts();
    if exceeds_limit {
        return Err(CollectBodyError::Invalid(Request::from_parts(
            parts,
            Empty::new(),
        )));
    }
    let Some((reader_budget, body_budget)) = runtime.try_body_budget(limit) else {
        return Err(CollectBodyError::Limit);
    };
    let _deadline_lease = match request_deadline {
        Some(deadline) => Some(
            deadline
                .lease_for(body_timeout)
                .ok_or(CollectBodyError::Limit)?,
        ),
        None => None,
    };
    let body = match tokio::time::timeout(body_timeout, Limited::new(body, limit).collect()).await {
        Ok(Ok(body)) => body.to_bytes(),
        _ => {
            return Err(CollectBodyError::Invalid(Request::from_parts(
                parts,
                Empty::new(),
            )));
        }
    };
    drop(reader_budget);
    let request = Request::from_parts(parts, Empty::new());
    if !allow_empty && body.is_empty() {
        return Err(CollectBodyError::Invalid(request));
    }
    Ok(CollectedBody {
        request,
        body,
        _body_budget: body_budget,
    })
}
