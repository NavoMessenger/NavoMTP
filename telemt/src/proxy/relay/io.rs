use crate::proxy::traffic_limiter::{RateDirection, TrafficLease, next_refill_delay};
use crate::stats::{Stats, UserQuotaHandle, UserStats};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep};
use tracing::trace;

mod combined;
mod counters;
mod quota;

pub(super) use self::combined::CombinedStream;
pub(super) use self::counters::SharedCounters;
pub(super) use self::quota::is_quota_io_error;
use self::quota::{QUOTA_RESERVE_MAX_ATTEMPTS_PER_POLL, quota_io_error};
pub(super) use self::quota::{quota_adaptive_interval_bytes, should_immediate_quota_check};

/// Transparent I/O wrapper that tracks per-user statistics and activity.
///
/// Wraps the **client** side of the relay. Direction mapping:
///
/// | poll method  | direction | stats updated                        |
/// |-------------|-----------|--------------------------------------|
/// | `poll_read`  | C→S       | `octets_from`, `msgs_from`, counters |
/// | `poll_write` | S→C       | `octets_to`, `msgs_to`, counters     |
///
/// Both update the shared activity timestamp for the watchdog.
///
/// Note on message counts: the original code counted one `read()`/`write_all()`
/// as one "message". Here we count `poll_read`/`poll_write` completions instead.
/// Byte counts are identical; op counts may differ slightly due to different
/// internal buffering in `copy_bidirectional`. This is fine for monitoring.
pub(super) struct StatsIo<S> {
    inner: S,
    counters: Arc<SharedCounters>,
    stats: Arc<Stats>,
    user: String,
    user_stats: Arc<UserStats>,
    quota_handle: UserQuotaHandle,
    traffic_lease: Option<Arc<TrafficLease>>,
    c2s_rate_debt_bytes: u64,
    c2s_wait: RateWaitState,
    s2c_wait: RateWaitState,
    quota_wait: RateWaitState,
    quota_limit: Option<u64>,
    quota_exceeded: Arc<AtomicBool>,
    pub(super) quota_bytes_since_check: u64,
    epoch: Instant,
}

#[derive(Default)]
struct RateWaitState {
    sleep: Option<Pin<Box<Sleep>>>,
    started_at: Option<Instant>,
    blocked_user: bool,
    blocked_cidr: bool,
}

impl<S> StatsIo<S> {
    /// Creates a StatsIo wrapper without a traffic lease for relay unit tests.
    #[cfg(test)]
    pub(super) fn new(
        inner: S,
        counters: Arc<SharedCounters>,
        stats: Arc<Stats>,
        user: String,
        quota_limit: Option<u64>,
        quota_exceeded: Arc<AtomicBool>,
        epoch: Instant,
    ) -> Self {
        let quota_handle = stats.current_user_quota_handle(&user);
        Self::new_with_traffic_lease(
            inner,
            counters,
            stats,
            user,
            quota_handle,
            None,
            quota_limit,
            quota_exceeded,
            epoch,
        )
    }

    pub(super) fn new_with_traffic_lease(
        inner: S,
        counters: Arc<SharedCounters>,
        stats: Arc<Stats>,
        user: String,
        quota_handle: UserQuotaHandle,
        traffic_lease: Option<Arc<TrafficLease>>,
        quota_limit: Option<u64>,
        quota_exceeded: Arc<AtomicBool>,
        epoch: Instant,
    ) -> Self {
        // Mark initial activity so the watchdog doesn't fire before data flows
        counters.touch(Instant::now(), epoch);
        let user_stats = stats.get_or_create_user_stats_handle(&user);
        Self {
            inner,
            counters,
            stats,
            user,
            user_stats,
            quota_handle,
            traffic_lease,
            c2s_rate_debt_bytes: 0,
            c2s_wait: RateWaitState::default(),
            s2c_wait: RateWaitState::default(),
            quota_wait: RateWaitState::default(),
            quota_limit,
            quota_exceeded,
            quota_bytes_since_check: 0,
            epoch,
        }
    }

    fn record_wait(
        wait: &mut RateWaitState,
        lease: Option<&Arc<TrafficLease>>,
        direction: RateDirection,
    ) {
        let Some(started_at) = wait.started_at.take() else {
            return;
        };
        let wait_ms = started_at.elapsed().as_millis().min(u128::from(u64::MAX)) as u64;
        if let Some(lease) = lease {
            lease.observe_wait_ms(direction, wait.blocked_user, wait.blocked_cidr, wait_ms);
        }
        wait.blocked_user = false;
        wait.blocked_cidr = false;
    }

    fn arm_wait(wait: &mut RateWaitState, blocked_user: bool, blocked_cidr: bool) {
        if wait.sleep.is_none() {
            wait.sleep = Some(Box::pin(tokio::time::sleep(next_refill_delay())));
            wait.started_at = Some(Instant::now());
        }
        wait.blocked_user |= blocked_user;
        wait.blocked_cidr |= blocked_cidr;
    }

    fn poll_wait(
        wait: &mut RateWaitState,
        cx: &mut Context<'_>,
        lease: Option<&Arc<TrafficLease>>,
        direction: RateDirection,
    ) -> Poll<()> {
        let Some(sleep) = wait.sleep.as_mut() else {
            return Poll::Ready(());
        };
        if sleep.as_mut().poll(cx).is_pending() {
            return Poll::Pending;
        }
        wait.sleep = None;
        Self::record_wait(wait, lease, direction);
        Poll::Ready(())
    }

    fn settle_c2s_rate_debt(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        let Some(lease) = self.traffic_lease.as_ref() else {
            self.c2s_rate_debt_bytes = 0;
            return Poll::Ready(());
        };

        while self.c2s_rate_debt_bytes > 0 {
            let consume = lease.try_consume(RateDirection::Up, self.c2s_rate_debt_bytes);
            if consume.granted > 0 {
                self.c2s_rate_debt_bytes = self.c2s_rate_debt_bytes.saturating_sub(consume.granted);
                continue;
            }
            Self::arm_wait(
                &mut self.c2s_wait,
                consume.blocked_user,
                consume.blocked_cidr,
            );
            if Self::poll_wait(&mut self.c2s_wait, cx, Some(lease), RateDirection::Up).is_pending()
            {
                return Poll::Pending;
            }
        }

        if Self::poll_wait(&mut self.c2s_wait, cx, Some(lease), RateDirection::Up).is_pending() {
            return Poll::Pending;
        }

        Poll::Ready(())
    }

    fn arm_quota_wait(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        Self::arm_wait(&mut self.quota_wait, false, false);
        Self::poll_wait(&mut self.quota_wait, cx, None, RateDirection::Up)
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for StatsIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.quota_exceeded.load(Ordering::Acquire) {
            return Poll::Ready(Err(quota_io_error()));
        }
        if this.settle_c2s_rate_debt(cx).is_pending() {
            return Poll::Pending;
        }
        if buf.remaining() == 0 {
            return Pin::new(&mut this.inner).poll_read(cx, buf);
        }

        let mut remaining_before = None;
        let mut quota_reservation = None;
        let mut read_limit = buf.remaining();
        if let Some(limit) = this.quota_limit {
            for _ in 0..QUOTA_RESERVE_MAX_ATTEMPTS_PER_POLL {
                let used_before = this.quota_handle.used();
                let remaining = limit.saturating_sub(used_before);
                if remaining == 0 {
                    this.quota_exceeded.store(true, Ordering::Release);
                    return Poll::Ready(Err(quota_io_error()));
                }
                let desired = remaining.min(read_limit as u64);
                match this.quota_handle.try_reserve(desired, limit) {
                    Ok(reservation) => {
                        remaining_before = Some(remaining);
                        read_limit = desired as usize;
                        quota_reservation = Some(reservation);
                        break;
                    }
                    Err(crate::stats::QuotaReserveError::LimitExceeded)
                    | Err(crate::stats::QuotaReserveError::Contended) => {
                        this.stats.increment_quota_contention_total();
                    }
                }
            }
            if quota_reservation.is_none() {
                this.stats.increment_quota_contention_timeout_total();
                if this.arm_quota_wait(cx).is_ready() {
                    cx.waker().wake_by_ref();
                }
                return Poll::Pending;
            }
        }

        let limited_read = read_limit < buf.remaining();
        let read_result = if limited_read {
            let mut limited_buf = ReadBuf::new(buf.initialize_unfilled_to(read_limit));
            match Pin::new(&mut this.inner).poll_read(cx, &mut limited_buf) {
                Poll::Ready(Ok(())) => {
                    let n = limited_buf.filled().len();
                    buf.advance(n);
                    Poll::Ready(Ok(n))
                }
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Pending,
            }
        } else {
            let before = buf.filled().len();
            match Pin::new(&mut this.inner).poll_read(cx, buf) {
                Poll::Ready(Ok(())) => {
                    let n = buf.filled().len() - before;
                    Poll::Ready(Ok(n))
                }
                Poll::Ready(Err(err)) => Poll::Ready(Err(err)),
                Poll::Pending => Poll::Pending,
            }
        };

        match read_result {
            Poll::Ready(Ok(n)) => {
                if let Some(reservation) = quota_reservation.take() {
                    let refund_bytes = reservation.reserved_bytes().saturating_sub(n as u64);
                    reservation.settle(n as u64);
                    this.stats.add_quota_refund_bytes_total(refund_bytes);
                }
                if n > 0 {
                    let n_to_charge = n as u64;

                    if let Some(remaining) = remaining_before {
                        if should_immediate_quota_check(remaining, n_to_charge) {
                            this.quota_bytes_since_check = 0;
                        } else {
                            this.quota_bytes_since_check =
                                this.quota_bytes_since_check.saturating_add(n_to_charge);
                            let interval = quota_adaptive_interval_bytes(remaining);
                            if this.quota_bytes_since_check >= interval {
                                this.quota_bytes_since_check = 0;
                            }
                        }
                    }
                    if let Some(limit) = this.quota_limit
                        && this.quota_handle.used() >= limit
                    {
                        this.quota_exceeded.store(true, Ordering::Release);
                    }

                    // C→S: client sent data
                    this.counters
                        .c2s_bytes
                        .fetch_add(n_to_charge, Ordering::Relaxed);
                    this.counters.c2s_ops.fetch_add(1, Ordering::Relaxed);
                    this.counters.touch(Instant::now(), this.epoch);

                    this.stats
                        .add_user_traffic_from_handle(this.user_stats.as_ref(), n_to_charge);
                    if this.traffic_lease.is_some() {
                        this.c2s_rate_debt_bytes =
                            this.c2s_rate_debt_bytes.saturating_add(n_to_charge);
                        let _ = this.settle_c2s_rate_debt(cx);
                    }

                    trace!(user = %this.user, bytes = n, "C->S");
                }
                Poll::Ready(Ok(()))
            }
            Poll::Pending => {
                if let Some(reservation) = quota_reservation.take() {
                    this.stats
                        .add_quota_refund_bytes_total(reservation.reserved_bytes());
                }
                Poll::Pending
            }
            Poll::Ready(Err(err)) => {
                if let Some(reservation) = quota_reservation.take() {
                    this.stats
                        .add_quota_refund_bytes_total(reservation.reserved_bytes());
                }
                Poll::Ready(Err(err))
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for StatsIo<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.quota_exceeded.load(Ordering::Acquire) {
            return Poll::Ready(Err(quota_io_error()));
        }

        let mut shaper_reservation = None;
        let mut write_buf = buf;
        if let Some(lease) = this.traffic_lease.as_ref() {
            if !buf.is_empty() {
                loop {
                    let reservation = lease.try_reserve(RateDirection::Down, buf.len() as u64);
                    let consume = reservation.result();
                    if consume.granted > 0 {
                        shaper_reservation = Some(reservation);
                        if consume.granted < buf.len() as u64 {
                            write_buf = &buf[..consume.granted as usize];
                        }
                        let _ = Self::poll_wait(
                            &mut this.s2c_wait,
                            cx,
                            Some(lease),
                            RateDirection::Down,
                        );
                        break;
                    }

                    Self::arm_wait(
                        &mut this.s2c_wait,
                        consume.blocked_user,
                        consume.blocked_cidr,
                    );
                    if Self::poll_wait(&mut this.s2c_wait, cx, Some(lease), RateDirection::Down)
                        .is_pending()
                    {
                        return Poll::Pending;
                    }
                }
            } else {
                let _ = Self::poll_wait(&mut this.s2c_wait, cx, Some(lease), RateDirection::Down);
            }
        }

        let mut remaining_before = None;
        let mut quota_reservation = None;
        if let Some(limit) = this.quota_limit {
            if !write_buf.is_empty() {
                for _ in 0..QUOTA_RESERVE_MAX_ATTEMPTS_PER_POLL {
                    let used_before = this.quota_handle.used();
                    let remaining = limit.saturating_sub(used_before);
                    if remaining == 0 {
                        this.quota_exceeded.store(true, Ordering::Release);
                        return Poll::Ready(Err(quota_io_error()));
                    }
                    remaining_before = Some(remaining);

                    let desired = remaining.min(write_buf.len() as u64);
                    match this.quota_handle.try_reserve(desired, limit) {
                        Ok(reservation) => {
                            quota_reservation = Some(reservation);
                            write_buf = &write_buf[..desired as usize];
                            break;
                        }
                        Err(crate::stats::QuotaReserveError::LimitExceeded)
                        | Err(crate::stats::QuotaReserveError::Contended) => {
                            this.stats.increment_quota_contention_total();
                        }
                    }
                }
                if quota_reservation.is_none() {
                    this.stats.increment_quota_contention_timeout_total();
                    Self::arm_wait(&mut this.quota_wait, false, false);
                    if Self::poll_wait(&mut this.quota_wait, cx, None, RateDirection::Up).is_ready()
                    {
                        cx.waker().wake_by_ref();
                    }
                    return Poll::Pending;
                }
            } else {
                let used_before = this.quota_handle.used();
                let remaining = limit.saturating_sub(used_before);
                if remaining == 0 {
                    this.quota_exceeded.store(true, Ordering::Release);
                    return Poll::Ready(Err(quota_io_error()));
                }
                remaining_before = Some(remaining);
            }
        }

        match Pin::new(&mut this.inner).poll_write(cx, write_buf) {
            Poll::Ready(Ok(n)) => {
                if let Some(reservation) = quota_reservation.take() {
                    let refund_bytes = reservation.reserved_bytes().saturating_sub(n as u64);
                    reservation.settle(n as u64);
                    this.stats.add_quota_refund_bytes_total(refund_bytes);
                }
                if let Some(reservation) = shaper_reservation.take() {
                    reservation.settle_written(n as u64);
                }
                if n > 0 {
                    if let Some(lease) = this.traffic_lease.as_ref() {
                        Self::record_wait(&mut this.s2c_wait, Some(lease), RateDirection::Down);
                    }
                    let n_to_charge = n as u64;

                    // S→C: data written to client
                    this.counters
                        .s2c_bytes
                        .fetch_add(n_to_charge, Ordering::Relaxed);
                    this.counters.s2c_ops.fetch_add(1, Ordering::Relaxed);
                    this.counters.touch(Instant::now(), this.epoch);

                    this.stats
                        .add_user_traffic_to_handle(this.user_stats.as_ref(), n_to_charge);

                    if let (Some(limit), Some(remaining)) = (this.quota_limit, remaining_before) {
                        if should_immediate_quota_check(remaining, n_to_charge) {
                            this.quota_bytes_since_check = 0;
                            if this.quota_handle.used() >= limit {
                                this.quota_exceeded.store(true, Ordering::Release);
                            }
                        } else {
                            this.quota_bytes_since_check =
                                this.quota_bytes_since_check.saturating_add(n_to_charge);
                            let interval = quota_adaptive_interval_bytes(remaining);
                            if this.quota_bytes_since_check >= interval {
                                this.quota_bytes_since_check = 0;
                                if this.quota_handle.used() >= limit {
                                    this.quota_exceeded.store(true, Ordering::Release);
                                }
                            }
                        }
                    }

                    trace!(user = %this.user, bytes = n, "S->C");
                }
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(err)) => {
                if let Some(reservation) = quota_reservation.take() {
                    this.stats
                        .add_quota_refund_bytes_total(reservation.reserved_bytes());
                }
                Poll::Ready(Err(err))
            }
            Poll::Pending => {
                if let Some(reservation) = quota_reservation.take() {
                    this.stats
                        .add_quota_refund_bytes_total(reservation.reserved_bytes());
                }
                Poll::Pending
            }
        }
    }

    #[inline]
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    #[inline]
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
