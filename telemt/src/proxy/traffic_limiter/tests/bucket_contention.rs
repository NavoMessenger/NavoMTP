use super::*;
use proptest::prelude::*;

#[test]
fn reserve_stops_after_the_attempt_limit() {
    let bucket = Arc::new(DirectionBucket::default());
    bucket.force_reserve_failures(RESERVE_CAS_ATTEMPT_LIMIT);
    let mut budget = ReserveCasBudget::new();

    let reservation = bucket.try_reserve_at(1, 100, 1, &mut budget);

    assert!(matches!(reservation, Err(BucketReserveError::Contended)));
    assert_eq!(
        bucket.reserve_cas_attempts(),
        RESERVE_CAS_ATTEMPT_LIMIT as u64
    );
    assert_eq!(bucket.used_at(1), None);
}

#[test]
fn reserve_succeeds_on_the_last_allowed_attempt() {
    let bucket = Arc::new(DirectionBucket::default());
    bucket.force_reserve_failures(RESERVE_CAS_ATTEMPT_LIMIT - 1);
    let mut budget = ReserveCasBudget::new();

    let mut debit = bucket
        .try_reserve_at(1, 100, 80, &mut budget)
        .unwrap()
        .unwrap();

    assert_eq!(debit.commit_all(), 80);
    assert_eq!(
        bucket.reserve_cas_attempts(),
        RESERVE_CAS_ATTEMPT_LIMIT as u64
    );
    assert!(budget.is_exhausted());
    assert_eq!(bucket.used_at(1), Some(80));
}

#[test]
fn refund_stops_after_the_attempt_limit() {
    let bucket = Arc::new(DirectionBucket::default());
    let debit = reserve_at(&bucket, 1, 100, 80).unwrap().unwrap();
    bucket.force_refund_failures(REFUND_CAS_ATTEMPT_LIMIT);

    drop(debit);

    assert_eq!(
        bucket.refund_cas_attempts(),
        REFUND_CAS_ATTEMPT_LIMIT as u64
    );
    assert_eq!(bucket.used_at(1), Some(80));
    assert_eq!(
        bucket
            .contention
            .refund_exhausted_total
            .load(Ordering::Relaxed),
        1
    );

    let mut tail = reserve_at(&bucket, 1, 100, 100).unwrap().unwrap();
    assert_eq!(tail.commit_all(), 20);
    assert!(reserve_at(&bucket, 1, 100, 1).unwrap().is_none());
    assert_eq!(bucket.used_at(1), Some(100));

    let mut next = reserve_at(&bucket, 2, 100, 100).unwrap().unwrap();
    assert_eq!(next.commit_all(), 100);
}

#[test]
fn refund_succeeds_on_the_last_allowed_attempt() {
    let bucket = Arc::new(DirectionBucket::default());
    let debit = reserve_at(&bucket, 1, 100, 80).unwrap().unwrap();
    bucket.force_refund_failures(REFUND_CAS_ATTEMPT_LIMIT - 1);

    drop(debit);

    assert_eq!(
        bucket.refund_cas_attempts(),
        REFUND_CAS_ATTEMPT_LIMIT as u64
    );
    assert_eq!(bucket.used_at(1), Some(0));
    assert_eq!(
        bucket
            .contention
            .refund_exhausted_total
            .load(Ordering::Relaxed),
        0
    );
}

#[test]
fn partial_refund_exhaustion_retains_the_full_charge() {
    let bucket = Arc::new(DirectionBucket::default());
    let mut debit = reserve_at(&bucket, 1, 100, 80).unwrap().unwrap();
    bucket.force_refund_failures(REFUND_CAS_ATTEMPT_LIMIT);

    debit.settle(30);
    drop(debit);

    assert_eq!(bucket.used_at(1), Some(80));
    assert_eq!(
        bucket.refund_cas_attempts(),
        REFUND_CAS_ATTEMPT_LIMIT as u64
    );
    assert_eq!(
        bucket
            .contention
            .refund_exhausted_total
            .load(Ordering::Relaxed),
        1
    );
}

#[test]
fn lease_contention_is_not_reported_as_throttling() {
    let limiter = TrafficLimiter::new();
    let mut user_limits = HashMap::new();
    user_limits.insert("alice".to_string(), rate(400_000, 400_000));
    limiter.apply_policy(user_limits, HashMap::new());
    let lease = limiter
        .acquire_lease("alice", "203.0.113.7".parse().unwrap())
        .unwrap();
    let bucket = Arc::clone(&lease.binding.load_full().user_bucket.as_ref().unwrap().down);
    bucket.force_reserve_failures(RESERVE_CAS_ATTEMPT_LIMIT);

    let result = lease.try_consume(RateDirection::Down, 1);
    let metrics = limiter.metrics_snapshot();

    assert_eq!(result.granted, 0);
    assert!(!result.blocked_user);
    assert!(!result.blocked_cidr);
    assert_eq!(metrics.user_reserve_cas_retry_exhausted_down_total, 1);
    assert_eq!(metrics.user_throttle_down_total, 0);
}

#[test]
fn cidr_contention_rolls_back_provisional_user_debits() {
    let limiter = TrafficLimiter::new();
    let mut user_limits = HashMap::new();
    user_limits.insert("alice".to_string(), rate(400_000, 400_000));
    let mut cidr_limits = HashMap::new();
    cidr_limits.insert(
        CidrRateLimitKey::Network("203.0.113.0/24".parse().unwrap()),
        rate(400_000, 400_000),
    );
    limiter.apply_policy(user_limits, cidr_limits);
    let lease = limiter
        .acquire_lease("alice", "203.0.113.7".parse().unwrap())
        .unwrap();
    let binding = lease.binding.load_full();
    let cidr_bucket = binding.cidr_bucket.as_ref().unwrap();
    cidr_bucket
        .down
        .used
        .force_reserve_failures(RESERVE_CAS_ATTEMPT_LIMIT);

    let reservation = lease.try_reserve(RateDirection::Down, 800);
    let result = reservation.result();
    let epoch = reservation.user.as_ref().unwrap().epoch;
    let user_attempts = binding
        .user_bucket
        .as_ref()
        .unwrap()
        .down
        .reserve_cas_attempts();
    let active_user_attempts = cidr_bucket.down.active_users.reserve_cas_attempts();
    let cidr_user_attempts = binding
        .cidr_user_share
        .as_ref()
        .unwrap()
        .down
        .used
        .reserve_cas_attempts();
    let aggregate_attempts = cidr_bucket.down.used.reserve_cas_attempts();
    drop(reservation);

    assert_eq!(result.granted, 0);
    assert!(!result.blocked_user);
    assert!(!result.blocked_cidr);
    assert_eq!(
        binding.user_bucket.as_ref().unwrap().down.used_at(epoch),
        Some(0)
    );
    assert_eq!(cidr_bucket.down.used.used_at(epoch), None);
    assert_eq!(
        user_attempts + active_user_attempts + cidr_user_attempts + aggregate_attempts,
        RESERVE_CAS_ATTEMPT_LIMIT as u64
    );
    assert_eq!(
        binding
            .cidr_user_share
            .as_ref()
            .unwrap()
            .down
            .used
            .used_at(epoch),
        Some(0)
    );
    let metrics = limiter.metrics_snapshot();
    assert_eq!(metrics.cidr_reserve_cas_retry_exhausted_down_total, 1);
    assert_eq!(metrics.cidr_throttle_down_total, 0);
}

#[test]
fn contention_snapshot_preserves_scope_direction_and_operation() {
    let limiter = TrafficLimiter::new();
    limiter
        .user_scope
        .contention_up
        .reserve_exhausted_total
        .store(1, Ordering::Relaxed);
    limiter
        .user_scope
        .contention_down
        .reserve_exhausted_total
        .store(2, Ordering::Relaxed);
    limiter
        .user_scope
        .contention_up
        .refund_exhausted_total
        .store(3, Ordering::Relaxed);
    limiter
        .user_scope
        .contention_down
        .refund_exhausted_total
        .store(4, Ordering::Relaxed);
    limiter
        .cidr_scope
        .contention_up
        .reserve_exhausted_total
        .store(5, Ordering::Relaxed);
    limiter
        .cidr_scope
        .contention_down
        .reserve_exhausted_total
        .store(6, Ordering::Relaxed);
    limiter
        .cidr_scope
        .contention_up
        .refund_exhausted_total
        .store(7, Ordering::Relaxed);
    limiter
        .cidr_scope
        .contention_down
        .refund_exhausted_total
        .store(8, Ordering::Relaxed);

    let snapshot = limiter.metrics_snapshot();

    assert_eq!(snapshot.user_reserve_cas_retry_exhausted_up_total, 1);
    assert_eq!(snapshot.user_reserve_cas_retry_exhausted_down_total, 2);
    assert_eq!(snapshot.user_refund_cas_retry_exhausted_up_total, 3);
    assert_eq!(snapshot.user_refund_cas_retry_exhausted_down_total, 4);
    assert_eq!(snapshot.cidr_reserve_cas_retry_exhausted_up_total, 5);
    assert_eq!(snapshot.cidr_reserve_cas_retry_exhausted_down_total, 6);
    assert_eq!(snapshot.cidr_refund_cas_retry_exhausted_up_total, 7);
    assert_eq!(snapshot.cidr_refund_cas_retry_exhausted_down_total, 8);
}

#[test]
fn cidr_activation_consumes_one_shared_attempt_budget() {
    let bucket = CidrDirectionBucket::default();
    let user = CidrUserDirectionState::default();
    user.used.force_reserve_failures(RESERVE_CAS_ATTEMPT_LIMIT);
    let mut budget = ReserveCasBudget::new();

    let activation = user.ensure_active(13, &bucket.active_users, &mut budget);

    assert_eq!(activation, Err(BucketReserveError::Contended));
    assert_eq!(
        user.used.reserve_cas_attempts() + bucket.active_users.reserve_cas_attempts(),
        RESERVE_CAS_ATTEMPT_LIMIT as u64
    );
    assert_eq!(bucket.active_users.used_at(13), Some(0));
    assert_eq!(user.used.used_at(13), None);
    assert_eq!(
        bucket
            .active_users
            .contention
            .refund_exhausted_total
            .load(Ordering::Relaxed),
        0
    );
}

#[test]
fn cidr_activation_reports_refund_contention_without_reserve_exhaustion() {
    let bucket = CidrDirectionBucket::default();
    let user = CidrUserDirectionState::default();
    user.used.force_reserve_failures(1);
    bucket
        .active_users
        .force_refund_failures(REFUND_CAS_ATTEMPT_LIMIT);
    let mut budget = ReserveCasBudget::new();

    let activation = user.ensure_active(13, &bucket.active_users, &mut budget);

    assert_eq!(activation, Err(BucketReserveError::RefundContended));
    assert!(!budget.is_exhausted());
    assert!(!activation.unwrap_err().exhausted_reserve_budget());
    assert_eq!(bucket.active_users.used_at(13), Some(1));
    assert_eq!(user.used.used_at(13), None);
    assert_eq!(
        bucket
            .active_users
            .contention
            .refund_exhausted_total
            .load(Ordering::Relaxed),
        1
    );
}

#[test]
fn cidr_activation_preserves_combined_contention_cause() {
    let bucket = CidrDirectionBucket::default();
    let user = CidrUserDirectionState::default();
    bucket
        .active_users
        .force_refund_failures(REFUND_CAS_ATTEMPT_LIMIT);
    let mut budget = ReserveCasBudget { remaining: 1 };

    let activation = user.ensure_active(13, &bucket.active_users, &mut budget);

    assert_eq!(
        activation,
        Err(BucketReserveError::ReserveAndRefundContended)
    );
    assert!(budget.is_exhausted());
    assert!(activation.unwrap_err().exhausted_reserve_budget());
    assert_eq!(bucket.active_users.used_at(13), Some(1));
    assert_eq!(user.used.used_at(13), None);
    assert_eq!(
        bucket
            .active_users
            .contention
            .refund_exhausted_total
            .load(Ordering::Relaxed),
        1
    );
}

#[test]
fn cidr_first_grants_preserve_the_current_soft_fair_share() {
    let bucket = CidrDirectionBucket::default();
    let first = CidrUserDirectionState::default();
    let second = CidrUserDirectionState::default();
    assert_eq!(
        first.ensure_active(17, &bucket.active_users, &mut ReserveCasBudget::new(),),
        Ok(true)
    );
    assert_eq!(
        second.ensure_active(17, &bucket.active_users, &mut ReserveCasBudget::new(),),
        Ok(true)
    );

    let mut first_reservation = bucket
        .try_reserve(&first, 17, 100, 100, &mut ReserveCasBudget::new())
        .unwrap();
    let mut second_reservation = bucket
        .try_reserve(&second, 17, 100, 100, &mut ReserveCasBudget::new())
        .unwrap();

    assert_eq!(first_reservation.granted, 50);
    assert_eq!(second_reservation.granted, 50);
    assert_eq!(bucket.active_users.used_at(17), Some(2));
    first_reservation
        .aggregate_debit
        .as_mut()
        .unwrap()
        .commit_all();
    first_reservation.user_debit.as_mut().unwrap().commit_all();
    second_reservation
        .aggregate_debit
        .as_mut()
        .unwrap()
        .commit_all();
    second_reservation.user_debit.as_mut().unwrap().commit_all();
    assert_eq!(bucket.used.used_at(17), Some(100));
    assert_eq!(first.used.used_at(17), Some(50));
    assert_eq!(second.used.used_at(17), Some(50));
}

#[test]
fn concurrent_commit_and_refund_preserve_fail_closed_accounting() {
    const WORKERS: usize = 32;
    const OPERATIONS_PER_WORKER: usize = 1_024;
    const EPOCH: u64 = 19;
    const CAP: u64 = (WORKERS * OPERATIONS_PER_WORKER) as u64;

    let bucket = Arc::new(DirectionBucket::default());
    let committed = Arc::new(AtomicU64::new(0));
    let barrier = Arc::new(std::sync::Barrier::new(WORKERS));
    let mut threads = Vec::with_capacity(WORKERS);
    for worker in 0..WORKERS {
        let bucket = Arc::clone(&bucket);
        let committed = Arc::clone(&committed);
        let barrier = Arc::clone(&barrier);
        threads.push(std::thread::spawn(move || {
            barrier.wait();
            for operation in 0..OPERATIONS_PER_WORKER {
                match reserve_at(&bucket, EPOCH, CAP, 1) {
                    Ok(Some(mut debit)) if (worker + operation) % 2 == 0 => {
                        committed.fetch_add(debit.commit_all(), Ordering::Relaxed);
                    }
                    Ok(Some(debit)) => drop(debit),
                    Err(BucketReserveError::Contended) => {}
                    Ok(None) => panic!("capacity exhausted before every operation ran"),
                    Err(error) => panic!("unexpected reservation error: {error:?}"),
                }
            }
        }));
    }
    for thread in threads {
        thread.join().unwrap();
    }

    let committed = committed.load(Ordering::Relaxed);
    let leaked = bucket
        .contention
        .refund_exhausted_total
        .load(Ordering::Relaxed);
    let used = bucket.used_at(EPOCH).unwrap();
    assert_eq!(used, committed + leaked);
    assert!(used <= CAP);
}

proptest! {
    #[test]
    fn sequential_debit_lifecycle_matches_the_epoch_model(
        operations in prop::collection::vec((0u8..4, 1u64..128), 1..128),
    ) {
        const CAP: u64 = 512;

        let bucket = Arc::new(DirectionBucket::default());
        let mut epoch = 1u64;
        let mut model_used = 0u64;
        for (operation, requested) in operations {
            if operation == 3 {
                epoch += 1;
                model_used = 0;
                let debit = reserve_at(&bucket, epoch, CAP, 1).unwrap().unwrap();
                drop(debit);
                prop_assert_eq!(bucket.used_at(epoch), Some(0));
                continue;
            }

            let reservation = reserve_at(&bucket, epoch, CAP, requested).unwrap();
            let expected_grant = requested.min(CAP.saturating_sub(model_used));
            if expected_grant == 0 {
                prop_assert!(reservation.is_none());
                continue;
            }
            let mut debit = reservation.unwrap();
            prop_assert_eq!(debit.refundable, expected_grant);
            match operation {
                0 => {
                    model_used += debit.commit_all();
                }
                1 => {
                    let committed = expected_grant / 2;
                    debit.settle(committed);
                    model_used += committed;
                }
                2 => drop(debit),
                _ => unreachable!(),
            }
            prop_assert_eq!(bucket.used_at(epoch), Some(model_used));
        }
    }
}
