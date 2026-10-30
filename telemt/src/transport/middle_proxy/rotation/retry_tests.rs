use super::objective::RetryObjective;
use super::*;

#[tokio::test(start_paused = true)]
async fn retry_objective_survives_unlimited_failures_and_ready_storms() {
    let mut objective = RetryObjective::new(1, 2, REINIT_TRIGGER_PERIODIC, Duration::ZERO);
    assert!(objective.deadline.is_some());
    for _ in 0..100 {
        objective.deadline = None;
        tokio::time::advance(Duration::from_secs(70)).await;
        let completed = tokio::time::Instant::now();
        objective.failed(Duration::from_secs(30));
        assert_eq!(
            objective.deadline,
            Some(completed + Duration::from_secs(30))
        );
    }
    objective.ready((3, 4, 2));
    objective.failed(Duration::from_secs(30));
    let deadline = objective.deadline;
    for _ in 0..100 {
        objective.ready((3, 4, 2));
    }
    assert_eq!(objective.deadline, deadline);
    objective.not_ready();
    objective.ready((3, 4, 2));
    assert!(
        objective.deadline < deadline,
        "a genuine loss and recovery of the same floor re-arms wakeup"
    );
    assert!(!objective.matches((1, 1)));
    assert!(!objective.matches((2, 2)));
}

#[tokio::test]
async fn pre_pending_failure_remains_live_without_a_periodic_trigger() {
    let pool = crate::transport::middle_proxy::pool_writer_security_tests::make_pool().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    pool.update_proxy_maps(
        std::collections::HashMap::from([(2, vec![(addr.ip(), addr.port())])]),
        None,
    )
    .await;
    pool.set_family_runtime_state(
        crate::network::IpFamily::V4,
        crate::transport::middle_proxy::pool::MeFamilyRuntimeState::Suppressed,
        MePool::now_epoch_secs(),
        MePool::now_epoch_secs() + 3600,
        5,
        0,
    );
    pool.reinit
        .me_hardswap_warmup_pass_backoff_base_ms
        .store(10, std::sync::atomic::Ordering::Relaxed);
    pool.reinit
        .me_hardswap_warmup_delay_min_ms
        .store(0, std::sync::atomic::Ordering::Relaxed);
    pool.reinit
        .me_hardswap_warmup_delay_max_ms
        .store(0, std::sync::atomic::Ordering::Relaxed);
    let mut config = ProxyConfig::default();
    config.general.me_reinit_coalesce_window_ms = 0;
    let (_config_tx, config_rx) = watch::channel(Arc::new(config));
    let (tx, rx) = mpsc::channel(1);
    let (ready_tx, _) = watch::channel(0);
    tx.send(MeReinitTrigger::Periodic).await.unwrap();
    drop(tx);
    let scheduler = tokio::spawn(me_reinit_scheduler(
        pool.clone(),
        pool.rng.clone(),
        config_rx,
        rx,
        ready_tx,
    ));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !scheduler.is_finished(),
        "false before pending creation must not discard recovery intent"
    );
    assert!(pool.reinit.coordinator.lock().pending.is_none());
    // Family policy changes do not emit endpoint or writer epochs.
    pool.set_family_runtime_state(
        crate::network::IpFamily::V4,
        crate::transport::middle_proxy::pool::MeFamilyRuntimeState::Healthy,
        MePool::now_epoch_secs(),
        0,
        0,
        0,
    );
    let (stream, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
        .await
        .expect("autonomous retry must actually reach TCP without another trigger")
        .unwrap();
    assert!(pool.shutdown_until(Duration::from_secs(1)).await);
    tokio::time::timeout(Duration::from_secs(1), scheduler)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        pool.reinit
            .scheduler_inflight
            .load(std::sync::atomic::Ordering::Acquire),
        0
    );
    drop(stream);
}

#[tokio::test]
async fn panic_retains_the_task_identity_for_retry() {
    let mut tasks = JoinSet::<bool>::new();
    let id = tasks.spawn(async { panic!("injected reinit panic") }).id();
    let error = tasks.join_next_with_id().await.unwrap().unwrap_err();
    assert_eq!(error.id(), id);
}

async fn check_inflight_trigger(trigger: MeReinitTrigger, starts_successor: bool) {
    let pool = crate::transport::middle_proxy::pool_writer_security_tests::make_pool().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    pool.update_proxy_maps(
        std::collections::HashMap::from([(2, vec![(addr.ip(), addr.port())])]),
        None,
    )
    .await;
    pool.reinit
        .me_hardswap_warmup_delay_min_ms
        .store(0, std::sync::atomic::Ordering::Relaxed);
    pool.reinit
        .me_hardswap_warmup_delay_max_ms
        .store(0, std::sync::atomic::Ordering::Relaxed);
    let mut config = ProxyConfig::default();
    config.general.me_reinit_coalesce_window_ms = 0;
    config.general.me_reinit_singleflight = false;
    config.general.me_reinit_max_concurrency = 2;
    let (_config_tx, config_rx) = watch::channel(Arc::new(config));
    let (tx, rx) = mpsc::channel(1);
    let (ready_tx, _) = watch::channel(0);
    tx.send(MeReinitTrigger::MapChanged).await.unwrap();
    let scheduler = tokio::spawn(me_reinit_scheduler(
        pool.clone(),
        pool.rng.clone(),
        config_rx,
        rx,
        ready_tx,
    ));
    let (first, _) = tokio::time::timeout(Duration::from_secs(1), listener.accept())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        pool.reinit
            .scheduler_inflight
            .load(std::sync::atomic::Ordering::Acquire),
        1
    );
    // Keep the first attempt blocked before handshake completion while delivering another trigger.
    tx.send(trigger).await.unwrap();
    let successor = tokio::time::timeout(Duration::from_millis(100), listener.accept()).await;
    let inflight = pool
        .reinit
        .scheduler_inflight
        .load(std::sync::atomic::Ordering::Acquire);
    assert!(pool.shutdown_until(Duration::from_secs(1)).await);
    tokio::time::timeout(Duration::from_secs(1), scheduler)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(successor.is_ok(), starts_successor);
    assert_eq!(inflight, if starts_successor { 2 } else { 1 });
    assert_eq!(
        pool.reinit
            .scheduler_inflight
            .load(std::sync::atomic::Ordering::Acquire),
        0
    );
    drop(first);
}

#[tokio::test]
async fn duplicate_map_change_coalesces_with_its_inflight_revision() {
    check_inflight_trigger(MeReinitTrigger::MapChanged, false).await;
}

#[tokio::test]
async fn periodic_trigger_retains_successor_intent_while_map_change_runs() {
    check_inflight_trigger(MeReinitTrigger::Periodic, true).await;
}
