use super::*;
use crate::web::manager::{CarrierCapabilities, CarrierRequest};

fn request(hash: u8) -> CarrierRequest {
    CarrierRequest::automatic(
        CarrierClientClass::Bridge,
        CarrierCapabilities::all(),
        1,
        None,
        [hash; 32],
    )
}

fn context(hash: u8) -> CarrierLearningContext {
    CarrierLearningContext {
        profile_key: [1; 32],
        client_ip: IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, hash)),
        class: CarrierClientClass::Bridge,
        user_agent_hash: [hash; 32],
        epoch: 1,
        ip_learning_eligible: true,
    }
}

fn apply_epoch(
    learning: &mut CarrierLearning,
    now: Instant,
    enabled: bool,
    aggressiveness: WebCarrierNegotiationAggressiveness,
    lifetime: Duration,
) -> u64 {
    let outcome = learning.apply_policy(
        now,
        1,
        enabled,
        aggressiveness,
        lifetime,
        Duration::from_secs(3),
    );
    drop(outcome.detached);
    outcome.epoch.unwrap()
}

#[test]
fn policy_epoch_rejects_late_outcomes_and_clears_state() {
    let now = Instant::now();
    let mut learning = CarrierLearning::new(6);
    let epoch = apply_epoch(
        &mut learning,
        now,
        true,
        WebCarrierNegotiationAggressiveness::Aggressive,
        Duration::from_secs(10),
    );
    learning.record_chain(now, epoch, context(1), &[], WebCarrier::Websocket);
    assert_eq!(learning.entries.len(), 3);
    let next = apply_epoch(
        &mut learning,
        now,
        false,
        WebCarrierNegotiationAggressiveness::Aggressive,
        Duration::from_secs(10),
    );
    assert_ne!(epoch, next);
    learning.record_chain(now, epoch, context(1), &[], WebCarrier::Https);
    assert!(learning.entries.is_empty());
}

#[test]
fn aggressive_policy_ranks_one_atomic_chain_sample() {
    let now = Instant::now();
    let mut learning = CarrierLearning::new(6);
    let epoch = apply_epoch(
        &mut learning,
        now,
        true,
        WebCarrierNegotiationAggressiveness::Aggressive,
        Duration::from_secs(10),
    );
    learning.record_chain(now, epoch, context(2), &[], WebCarrier::Websocket);
    let (ranked, scores) = learning.rank(
        now,
        &[
            WebCarrier::Https,
            WebCarrier::Websocket,
            WebCarrier::HttpsLanes,
        ],
        request(2),
        [1; 32],
        context(2).client_ip,
        true,
    );
    assert_eq!(
        ranked,
        [
            WebCarrier::Websocket,
            WebCarrier::Https,
            WebCarrier::HttpsLanes,
        ]
    );
    assert_eq!(scores[WebCarrier::Websocket.index()], 33);
}

#[test]
fn two_half_windows_expire_without_sliding_updates() {
    let start = Instant::now();
    let mut learning = CarrierLearning::new(6);
    let epoch = apply_epoch(
        &mut learning,
        start,
        true,
        WebCarrierNegotiationAggressiveness::Aggressive,
        Duration::from_secs(10),
    );
    learning.record_chain(start, epoch, context(3), &[], WebCarrier::Websocket);
    learning.record_chain(
        start + Duration::from_secs(6),
        epoch,
        context(3),
        &[],
        WebCarrier::Websocket,
    );
    learning.prune(start + Duration::from_secs(11));
    assert_eq!(learning.entries.len(), 3);
    learning.prune(start + Duration::from_secs(16));
    assert!(learning.entries.is_empty());
}

#[test]
fn exhausted_epoch_and_insertion_identifiers_fail_closed() {
    let now = Instant::now();
    let mut learning = CarrierLearning::new(3);
    learning.epoch = Some(u64::MAX);
    let exhausted = learning.apply_policy(
        now,
        1,
        true,
        WebCarrierNegotiationAggressiveness::Aggressive,
        Duration::from_secs(10),
        Duration::from_secs(3),
    );
    assert_eq!(exhausted.epoch, None);
    drop(exhausted.detached);
    assert_eq!(
        learning.record_chain(now, u64::MAX, context(4), &[], WebCarrier::Https),
        CarrierLearningRecordOutcome::StaleEpoch
    );
    assert!(learning.entries.is_empty());

    learning.epoch = Some(1);
    learning.insertion_sequence = u64::MAX;
    assert_eq!(
        learning.record_chain(now, 1, context(4), &[], WebCarrier::Https),
        CarrierLearningRecordOutcome::SequenceExhausted
    );
    assert!(learning.entries.is_empty());
    assert!(learning.insertion_order.is_empty());
}

#[test]
fn client_reported_failures_do_not_create_negative_evidence() {
    let now = Instant::now();
    let mut learning = CarrierLearning::new(3);
    let epoch = apply_epoch(
        &mut learning,
        now,
        true,
        WebCarrierNegotiationAggressiveness::Aggressive,
        Duration::from_secs(10),
    );
    learning.record_chain(
        now,
        epoch,
        context(5),
        &[WebCarrier::Websocket],
        WebCarrier::Https,
    );
    let (_, scores) = learning.rank(
        now,
        &[WebCarrier::Websocket, WebCarrier::HttpsLanes],
        request(5),
        [1; 32],
        context(5).client_ip,
        true,
    );
    assert_eq!(scores[WebCarrier::Websocket.index()], 0);
}

#[test]
fn old_new_old_policy_rejects_both_stale_epochs() {
    let now = Instant::now();
    let mut learning = CarrierLearning::new(3);
    let old = apply_epoch(
        &mut learning,
        now,
        true,
        WebCarrierNegotiationAggressiveness::Aggressive,
        Duration::from_secs(10),
    );
    let middle = apply_epoch(
        &mut learning,
        now,
        true,
        WebCarrierNegotiationAggressiveness::Balanced,
        Duration::from_secs(10),
    );
    let current = apply_epoch(
        &mut learning,
        now,
        true,
        WebCarrierNegotiationAggressiveness::Aggressive,
        Duration::from_secs(10),
    );
    assert_ne!(old, middle);
    assert_ne!(middle, current);
    assert_ne!(old, current);
    assert_eq!(
        learning.record_chain(now, old, context(6), &[], WebCarrier::Https),
        CarrierLearningRecordOutcome::StaleEpoch
    );
    assert_eq!(
        learning.record_chain(now, middle, context(6), &[], WebCarrier::Https),
        CarrierLearningRecordOutcome::StaleEpoch
    );
    assert!(learning.entries.is_empty());
    assert_eq!(
        learning.record_chain(now, current, context(6), &[], WebCarrier::Https),
        CarrierLearningRecordOutcome::Recorded
    );
    assert_eq!(learning.entries.len(), 3);
}

#[test]
fn generation_rollover_preserves_same_policy_evidence() {
    let now = Instant::now();
    let mut learning = CarrierLearning::new(3);
    let first = learning.apply_policy(
        now,
        1,
        true,
        WebCarrierNegotiationAggressiveness::Aggressive,
        Duration::from_secs(10),
        Duration::from_secs(3),
    );
    let epoch = first.epoch.unwrap();
    assert!(first.detached.is_some());
    drop(first.detached);
    assert_eq!(
        learning.record_chain(now, epoch, context(8), &[], WebCarrier::Https),
        CarrierLearningRecordOutcome::Recorded
    );

    let second = learning.apply_policy(
        now,
        2,
        true,
        WebCarrierNegotiationAggressiveness::Aggressive,
        Duration::from_secs(10),
        Duration::from_secs(3),
    );

    assert!(second.applied);
    assert_eq!(second.epoch, Some(epoch));
    assert!(second.detached.is_none());
    assert_eq!(learning.entries.len(), 3);
    assert_eq!(
        learning.epoch_for_policy(
            1,
            true,
            WebCarrierNegotiationAggressiveness::Aggressive,
            Duration::from_secs(10),
            Duration::from_secs(3),
        ),
        CarrierLearningEpoch::Pending
    );
    assert_eq!(
        learning.epoch_for_policy(
            2,
            true,
            WebCarrierNegotiationAggressiveness::Aggressive,
            Duration::from_secs(10),
            Duration::from_secs(3),
        ),
        CarrierLearningEpoch::Ready(epoch)
    );
}

#[test]
fn stale_generation_cannot_restore_an_old_policy() {
    let now = Instant::now();
    let mut learning = CarrierLearning::new(3);
    let current = learning.apply_policy(
        now,
        2,
        true,
        WebCarrierNegotiationAggressiveness::Balanced,
        Duration::from_secs(10),
        Duration::from_secs(3),
    );
    let epoch = current.epoch;
    drop(current.detached);

    let stale = learning.apply_policy(
        now,
        1,
        true,
        WebCarrierNegotiationAggressiveness::Aggressive,
        Duration::from_secs(20),
        Duration::from_secs(4),
    );
    let status = learning.status(now);

    assert!(!stale.applied);
    assert_eq!(stale.epoch, epoch);
    assert!(stale.detached.is_none());
    assert_eq!(status.policy_generation, Some(2));
    assert_eq!(
        status.aggressiveness,
        WebCarrierNegotiationAggressiveness::Balanced
    );
    assert_eq!(status.lifetime_secs, 10);
    assert_eq!(status.health_secs, 3);
}

#[test]
fn health_window_change_starts_a_new_empty_epoch() {
    let now = Instant::now();
    let mut learning = CarrierLearning::new(3);
    let first = learning.apply_policy(
        now,
        1,
        true,
        WebCarrierNegotiationAggressiveness::Aggressive,
        Duration::from_secs(10),
        Duration::from_secs(3),
    );
    let epoch = first.epoch.unwrap();
    drop(first.detached);
    assert_eq!(
        learning.record_chain(now, epoch, context(9), &[], WebCarrier::Https),
        CarrierLearningRecordOutcome::Recorded
    );

    let changed = learning.apply_policy(
        now,
        2,
        true,
        WebCarrierNegotiationAggressiveness::Aggressive,
        Duration::from_secs(10),
        Duration::from_secs(4),
    );

    assert_ne!(changed.epoch, Some(epoch));
    assert_eq!(
        changed
            .detached
            .as_ref()
            .map(|detached| detached.entries.len()),
        Some(3)
    );
    assert!(learning.entries.is_empty());
    drop(changed.detached);
}

#[test]
fn capacity_rejection_does_not_partially_mutate_the_store() {
    let now = Instant::now();
    let mut learning = CarrierLearning::new(2);
    let epoch = apply_epoch(
        &mut learning,
        now,
        true,
        WebCarrierNegotiationAggressiveness::Aggressive,
        Duration::from_secs(10),
    );
    let sequence = learning.insertion_sequence;

    assert_eq!(
        learning.record_chain(now, epoch, context(10), &[], WebCarrier::Https),
        CarrierLearningRecordOutcome::CapacityRejected
    );
    assert!(learning.entries.is_empty());
    assert!(learning.insertion_order.is_empty());
    assert_eq!(learning.insertion_sequence, sequence);
}

#[test]
fn fifo_metadata_stays_within_the_entry_capacity() {
    let now = Instant::now();
    let mut learning = CarrierLearning::new(3);
    let epoch = apply_epoch(
        &mut learning,
        now,
        true,
        WebCarrierNegotiationAggressiveness::Aggressive,
        Duration::from_secs(10),
    );
    for hash in 1..=32 {
        learning.record_chain(now, epoch, context(hash), &[], WebCarrier::Https);
        assert!(learning.entries.len() <= 3);
        assert!(learning.insertion_order.len() <= 3);
    }
}

#[tokio::test]
async fn runtime_activation_publishes_matching_policy_and_generation() {
    let mut config = crate::config::ProxyConfig::default();
    config.web.carriers = crate::config::WebCarriers::Enabled(vec![WebCarrier::Websocket]);
    config.web.carrier_learning = true;
    config.web.carrier_negotiation_aggressiveness = WebCarrierNegotiationAggressiveness::Aggressive;
    config.web.timeouts.carrier_learning_secs = 10;
    config.web.timeouts.carrier_health_secs = 3;
    let first = crate::maestro::generation::test_runtime_generation(1, config.clone());
    let runtime = crate::web::manager::WebProcessRuntime::start(std::sync::Arc::new(
        arc_swap::ArcSwap::from(first.clone()),
    ));
    let epoch = {
        let mut learning = runtime.learning.lock();
        let epoch = learning.status(Instant::now()).epoch.unwrap();
        assert_eq!(
            learning.record_chain(
                Instant::now(),
                epoch,
                context(11),
                &[],
                WebCarrier::Websocket,
            ),
            CarrierLearningRecordOutcome::Recorded
        );
        epoch
    };
    let second = crate::maestro::generation::test_runtime_generation(2, config);

    let replaced = runtime.activate_generation(second.clone());

    assert!(std::sync::Arc::ptr_eq(&replaced, &first));
    assert_eq!(runtime.active_generation().id, 2);
    {
        let learning = runtime.learning.lock();
        let status = learning.status(Instant::now());
        assert_eq!(status.policy_generation, Some(2));
        assert_eq!(status.epoch, Some(epoch));
        assert_eq!(status.entries, 3);
    }

    runtime.shutdown().await;
    first.stop_sessions().await;
    first.stop_background_tasks().await;
    second.stop_sessions().await;
    second.stop_background_tasks().await;
}

#[tokio::test]
async fn explicit_reset_preserves_policy_and_rejects_old_epoch_outcomes() {
    let generation = crate::maestro::generation::test_runtime_generation(
        1,
        crate::config::ProxyConfig::default(),
    );
    let runtime = crate::web::manager::WebProcessRuntime::start(std::sync::Arc::new(
        arc_swap::ArcSwap::from(generation.clone()),
    ));
    let now = Instant::now();
    let old_epoch = {
        let mut learning = runtime.learning.lock();
        let outcome = learning.apply_policy(
            now,
            1,
            true,
            WebCarrierNegotiationAggressiveness::Aggressive,
            Duration::from_secs(10),
            Duration::from_secs(3),
        );
        let epoch = outcome.epoch.unwrap();
        drop(outcome.detached);
        learning.record_chain(now, epoch, context(7), &[], WebCarrier::Websocket);
        epoch
    };

    let outcome = runtime.reset_carrier_learning().unwrap();
    {
        let mut learning = runtime.learning.lock();
        learning.record_chain(
            Instant::now(),
            old_epoch,
            context(7),
            &[],
            WebCarrier::Https,
        );
        let status = learning.status(Instant::now());
        assert!(status.enabled);
        assert_eq!(
            status.aggressiveness,
            WebCarrierNegotiationAggressiveness::Aggressive
        );
        assert_eq!(status.entries, 0);
        assert_eq!(status.epoch, Some(outcome.epoch));
    }

    runtime.shutdown().await;
    generation.stop_sessions().await;
    generation.stop_background_tasks().await;
}
