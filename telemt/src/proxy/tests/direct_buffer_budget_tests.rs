use super::*;
use tokio::sync::Semaphore;

#[test]
fn lease_drop_releases_the_complete_reservation() {
    let budget = DirectBufferBudget::new(16 * 1024);
    {
        let lease = budget
            .try_reserve(12 * 1024, false)
            .expect("minimum reservation must fit");
        assert_eq!(lease.reserved_bytes(), 12 * 1024);
        assert_eq!(budget.snapshot().reserved_bytes, 12 * 1024);
    }
    assert_eq!(budget.snapshot().reserved_bytes, 0);
}

#[test]
fn absolute_ceiling_rejects_excess_minimum_reservations() {
    let budget = DirectBufferBudget::new(16 * 1024);
    let _lease = budget
        .try_reserve(12 * 1024, true)
        .expect("first minimum reservation must fit");
    assert!(budget.try_reserve(8 * 1024, true).is_none());
    assert_eq!(budget.snapshot().reserved_bytes, 12 * 1024);
}

#[test]
fn growth_and_shrink_keep_accounting_balanced() {
    let budget = DirectBufferBudget::new(32 * 1024);
    let mut lease = budget
        .try_reserve(12 * 1024, false)
        .expect("base reservation must fit");
    assert!(lease.try_grow_to(24 * 1024));
    assert_eq!(budget.snapshot().reserved_bytes, 24 * 1024);
    lease.shrink_to(16 * 1024);
    assert_eq!(budget.snapshot().reserved_bytes, 16 * 1024);
    drop(lease);
    assert_eq!(budget.snapshot().reserved_bytes, 0);
}

#[test]
fn runtime_generations_share_one_absolute_reservation_envelope() {
    let first_generation = DirectBufferBudget::new(16 * 1024);
    let second_generation = Arc::clone(&first_generation);
    let first = first_generation
        .try_reserve(12 * 1024, true)
        .expect("first generation reservation must fit");

    assert!(second_generation.try_reserve(8 * 1024, true).is_none());
    assert_eq!(second_generation.snapshot().reserved_bytes, 12 * 1024);

    drop(first);
    assert!(second_generation.try_reserve(8 * 1024, true).is_some());
}

#[test]
fn stale_runtime_cannot_reclaim_direct_controller_ownership() {
    let budget = DirectBufferBudget::new(16 * 1024);
    budget.activate_controller(2);
    budget.activate_controller(1);

    assert_eq!(
        budget.active_controller_generation.load(Ordering::Acquire),
        2
    );
}

#[test]
fn controller_handoff_waits_for_inflight_update_and_fences_old_generation() {
    let budget = DirectBufferBudget::new(16 * 1024);
    budget.activate_controller(1);
    let update = budget.begin_controller_update(1).unwrap();
    let (activated_tx, activated_rx) = std::sync::mpsc::channel();
    let next_budget = Arc::clone(&budget);
    let activation = std::thread::spawn(move || {
        next_budget.activate_controller(2);
        activated_tx.send(()).unwrap();
    });

    assert!(
        activated_rx
            .recv_timeout(Duration::from_millis(50))
            .is_err()
    );
    drop(update);
    activated_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    activation.join().unwrap();

    assert!(budget.begin_controller_update(1).is_none());
    assert!(budget.begin_controller_update(2).is_some());
}

#[test]
fn connection_pressure_uses_process_wide_slot_ownership() {
    let slots = Arc::new(Semaphore::new(10));
    let _old_generation = Arc::clone(&slots).try_acquire_many_owned(3).unwrap();
    let _new_generation = Arc::clone(&slots).try_acquire_many_owned(2).unwrap();

    assert_eq!(connection_fill_pct(slots.as_ref(), 10), Some(50));
}
