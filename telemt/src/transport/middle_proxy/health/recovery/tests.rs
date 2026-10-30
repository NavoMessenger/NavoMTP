use std::sync::atomic::Ordering;

use super::*;
use crate::transport::middle_proxy::admission_test_support::unregistered_writer;
use crate::transport::middle_proxy::pool_writer_security_tests::make_pool;

async fn single_endpoint_reaches_tcp_with_a_full_cap(bypass_quarantine: bool) {
    let pool = make_pool().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let donor = SocketAddr::new(endpoint.ip(), 1);
    pool.update_proxy_maps(
        HashMap::from([
            (2, vec![(endpoint.ip(), endpoint.port())]),
            (3, vec![(donor.ip(), donor.port())]),
        ]),
        None,
    )
    .await;
    pool.floor_runtime
        .me_adaptive_floor_cpu_cores_override
        .store(1, Ordering::Relaxed);
    pool.floor_runtime
        .me_adaptive_floor_max_active_writers_per_core
        .store(1, Ordering::Relaxed);
    pool.floor_runtime
        .me_adaptive_floor_max_active_writers_global
        .store(1, Ordering::Relaxed);
    pool.single_endpoint_runtime
        .me_single_endpoint_outage_disable_quarantine
        .store(bypass_quarantine, Ordering::Relaxed);
    let (writer, _receiver) = unregistered_writer(
        &pool,
        1,
        3,
        donor,
        pool.current_generation(),
        WriterContour::Active,
    );
    pool.writers.write().await.push(writer);
    if bypass_quarantine {
        pool.endpoint_quarantine
            .lock()
            .await
            .insert(endpoint, Instant::now() + Duration::from_secs(60));
    }
    let rng = Arc::new(SecureRandom::new());
    let key = (2, IpFamily::V4);
    let mut backoff = HashMap::new();
    let mut next_attempt = HashMap::new();
    let semaphore = Arc::new(Semaphore::new(1));
    let required = pool.required_writers_for_dc(1);
    // TCP acceptance proves capacity admission; closing the peer deliberately rejects the handshake.
    tokio::time::timeout(Duration::from_secs(1), async {
        tokio::join!(
            recover_single_endpoint_outage(
                &pool,
                &rng,
                key,
                endpoint,
                required,
                &mut backoff,
                &mut next_attempt,
                &semaphore,
            ),
            async {
                let (stream, _) = listener.accept().await.unwrap();
                drop(stream);
            },
        );
    })
    .await
    .expect("missing-DC recovery must reach TCP even when another DC fills the cap");
    assert_eq!(
        pool.stats
            .get_me_single_endpoint_outage_reconnect_attempt_total(),
        1
    );
    assert_eq!(
        pool.stats
            .get_me_single_endpoint_outage_reconnect_success_total(),
        0
    );
    assert_eq!(
        pool.stats.get_me_single_endpoint_quarantine_bypass_total(),
        u64::from(bypass_quarantine)
    );
    assert!(next_attempt.contains_key(&key));
    assert!(backoff.contains_key(&key));
    assert_eq!(semaphore.available_permits(), 1);
    assert_eq!(
        pool.writer_connect_active_reserved.load(Ordering::Acquire),
        0
    );
}

#[tokio::test]
async fn single_endpoint_quarantine_bypass_recovers_coverage_at_cap() {
    single_endpoint_reaches_tcp_with_a_full_cap(true).await;
}

#[tokio::test]
async fn single_endpoint_round_robin_recovers_coverage_at_cap() {
    single_endpoint_reaches_tcp_with_a_full_cap(false).await;
}

#[tokio::test]
async fn restored_coverage_preserves_family_suppression_hysteresis() {
    let pool = make_pool().await;
    let now = MePool::now_epoch_secs();
    let until = now + 3600;
    pool.set_family_runtime_state(
        IpFamily::V4,
        MeFamilyRuntimeState::Suppressed,
        now,
        until,
        5,
        0,
    );
    super::super::update_family_runtime_state(&pool, IpFamily::V4, false);
    assert_eq!(
        pool.family_runtime_state(IpFamily::V4),
        MeFamilyRuntimeState::Suppressed
    );
    assert_eq!(pool.family_suppressed_until_epoch_secs(IpFamily::V4), until);
    assert_eq!(pool.family_recover_success_streak(IpFamily::V4), 0);

    pool.set_family_runtime_state(
        IpFamily::V4,
        MeFamilyRuntimeState::Suppressed,
        now,
        now - 1,
        5,
        0,
    );
    super::super::update_family_runtime_state(&pool, IpFamily::V4, false);
    assert_eq!(
        pool.family_runtime_state(IpFamily::V4),
        MeFamilyRuntimeState::Recovering
    );
    assert_eq!(pool.family_recover_success_streak(IpFamily::V4), 1);
    super::super::update_family_runtime_state(&pool, IpFamily::V4, false);
    assert_eq!(
        pool.family_runtime_state(IpFamily::V4),
        MeFamilyRuntimeState::Healthy
    );
    assert_eq!(pool.family_fail_streak(IpFamily::V4), 0);
}
