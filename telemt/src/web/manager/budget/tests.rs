use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};

use super::*;

struct WakeCounter(AtomicUsize);

impl Wake for WakeCounter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::AcqRel);
    }
}

#[test]
fn downlink_reservation_preserves_one_uplink_and_websocket_batch() {
    let limits = WebLimitsConfig::default();
    let uplink_bytes = limits
        .max_body_bytes
        .saturating_add(limits.max_frames_per_body.saturating_mul(QUEUE_ITEM_COST));
    let downlink_bytes = limits
        .pending_bytes_global
        .saturating_sub(limits.control_bytes_global)
        .saturating_sub(uplink_bytes)
        .saturating_sub(limits.carrier_batch_bytes);
    let budget = WebDataBudget::new(limits);

    assert!(budget.try_reserve_queue([1; 32], downlink_bytes, 1, false, true));
    assert!(!budget.try_reserve_queue([1; 32], 1, 1, false, true));
}

#[test]
fn item_limit_rejection_does_not_request_websocket_eviction() {
    let limits = WebLimitsConfig::default();
    let rejected_items = limits.pending_items_global.saturating_add(1);
    let budget = WebDataBudget::new(limits);
    let _websocket = budget
        .try_reserve_websocket([1; 32], 1, WebSocketBudgetClass::Data)
        .unwrap();

    assert!(!budget.try_reserve_queue([2; 32], 1, rejected_items, false, false));
    assert!(!budget.take_pressure());
}

#[test]
fn websocket_byte_conflict_requests_pressure_eviction() {
    let limits = WebLimitsConfig::default();
    let data_bytes = limits
        .pending_bytes_global
        .saturating_sub(limits.control_bytes_global);
    let budget = WebDataBudget::new(limits);
    let _websocket = budget
        .try_reserve_websocket([1; 32], 1, WebSocketBudgetClass::Data)
        .unwrap();

    assert!(!budget.try_reserve_queue([2; 32], data_bytes, 1, false, false));
    assert!(budget.take_pressure());
}

#[test]
fn quiet_queue_release_updates_accounting_before_notification_dispatch() {
    let budget = WebDataBudget::new(WebLimitsConfig::default());
    assert!(budget.try_reserve_queue([1; 32], 64, 1, false, false));
    let counter = Arc::new(WakeCounter(AtomicUsize::new(0)));
    let waker = Waker::from(Arc::clone(&counter));
    let mut context = Context::from_waker(&waker);
    let mut notified = Box::pin(budget.notify.notified());
    assert!(matches!(
        notified.as_mut().poll(&mut context),
        Poll::Pending
    ));

    let notify = budget.release_queue_quiet([1; 32], 64, 1, false);

    assert_eq!(budget.snapshot().queue_bytes, 0);
    assert_eq!(budget.snapshot().queue_items, 0);
    assert_eq!(counter.0.load(Ordering::Acquire), 0);
    notify.notify_waiters();
    assert_eq!(counter.0.load(Ordering::Acquire), 1);
}
