use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::*;
use crate::network::{IpFamily, probe::NetworkDecision};
use crate::transport::middle_proxy::admission_test_support::unregistered_writer;
use crate::transport::middle_proxy::pool::MeFamilyRuntimeState;
use crate::transport::middle_proxy::pool_writer_security_tests::{
    make_pool, make_pool_with_decision,
};

fn cap_at_one(pool: &MePool) {
    pool.floor_runtime
        .me_adaptive_floor_cpu_cores_override
        .store(1, Ordering::Relaxed);
    pool.floor_runtime
        .me_adaptive_floor_max_active_writers_per_core
        .store(1, Ordering::Relaxed);
    pool.floor_runtime
        .me_adaptive_floor_max_active_writers_global
        .store(1, Ordering::Relaxed);
}

fn suppress(pool: &MePool, family: IpFamily) {
    let now = MePool::now_epoch_secs();
    pool.set_family_runtime_state(
        family,
        MeFamilyRuntimeState::Suppressed,
        now,
        now + 3600,
        5,
        0,
    );
}

fn prepared<'a>(
    pool: &'a Arc<MePool>,
    writer: MeWriter,
    intent: WriterOpenIntent,
    reservation: WriterOpenReservation,
    task_started: Arc<AtomicBool>,
) -> PreparedWriter<'a> {
    let cancel = writer.cancel.clone();
    PreparedWriter {
        tx: writer.tx.clone(),
        byte_budget: writer.byte_budget.clone(),
        writer,
        task_registration: pool.lifecycle.try_register().unwrap(),
        writer_task: WriterTransport::new(
            Box::pin(async move {
                task_started.store(true, Ordering::Release);
                cancel.cancelled().await;
            }),
            reservation,
        ),
        intent,
    }
}

#[tokio::test]
async fn suppressed_active_coverage_publishes_only_the_missing_floor() {
    let pool = make_pool().await;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
    pool.update_proxy_maps(HashMap::from([(2, vec![(addr.ip(), addr.port())])]), None)
        .await;
    cap_at_one(&pool);
    suppress(&pool, IpFamily::V4);
    let required = pool.required_writers_for_dc(1);
    let mut receivers = Vec::new();
    for id in 1..=required as u64 {
        let reservation = pool
            .reserve_writer_open(WriterContour::Active, WriterOpenIntent::Coverage, 2, addr)
            .await
            .expect("missing coverage must have a reservation despite suppression");
        let (writer, receiver) = unregistered_writer(
            &pool,
            id,
            2,
            addr,
            pool.current_generation(),
            WriterContour::Active,
        );
        receivers.push(receiver);
        pool.publish_connected_writer(prepared(
            &pool,
            writer,
            WriterOpenIntent::Coverage,
            reservation,
            Arc::new(AtomicBool::new(false)),
        ))
        .await
        .expect("authenticated coverage must publish without waiting for suppression expiry");
        assert_eq!(pool.conn_count.load(Ordering::Relaxed), id as usize);
        assert_eq!(
            pool.writer_connect_active_reserved.load(Ordering::Acquire),
            0
        );
    }
    assert!(
        pool.reserve_writer_open(WriterContour::Active, WriterOpenIntent::Coverage, 2, addr)
            .await
            .is_none()
    );
    let (extra, _receiver) = unregistered_writer(
        &pool,
        99,
        2,
        addr,
        pool.current_generation(),
        WriterContour::Active,
    );
    assert!(
        pool.authorize_writer_publication_capacity(
            &extra,
            WriterContour::Active,
            WriterOpenIntent::Coverage,
            &pool.writers.read().await,
        )
        .is_err()
    );
    assert_eq!(
        pool.family_runtime_state(IpFamily::V4),
        MeFamilyRuntimeState::Suppressed
    );
    assert!(pool.shutdown_until(Duration::from_secs(1)).await);
}

#[tokio::test]
async fn concurrent_suppressed_coverage_publications_cannot_overfill_a_group() {
    let pool = make_pool().await;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
    pool.update_proxy_maps(HashMap::from([(2, vec![(addr.ip(), addr.port())])]), None)
        .await;
    cap_at_one(&pool);
    suppress(&pool, IpFamily::V4);
    let required = pool.required_writers_for_dc(1);
    let mut receivers = Vec::new();
    let mut publications = Vec::new();
    for id in 1..=(required + 1) as u64 {
        let reservation = pool
            .reserve_writer_open(WriterContour::Active, WriterOpenIntent::Coverage, 2, addr)
            .await
            .unwrap();
        let (writer, receiver) = unregistered_writer(
            &pool,
            id,
            2,
            addr,
            pool.current_generation(),
            WriterContour::Active,
        );
        receivers.push(receiver);
        publications.push(pool.publish_connected_writer(prepared(
            &pool,
            writer,
            WriterOpenIntent::Coverage,
            reservation,
            Arc::new(AtomicBool::new(false)),
        )));
    }
    let guard = pool.writers.write().await;
    let results = futures::future::join_all(publications);
    tokio::pin!(results);
    tokio::select! {
        biased;
        results = &mut results => panic!("publication bypassed the writer barrier: {results:?}"),
        _ = tokio::task::yield_now() => {}
    }
    drop(guard);
    let results = results.await;
    assert_eq!(
        results.iter().filter(|result| result.is_ok()).count(),
        required
    );
    assert_eq!(results.iter().filter(|result| result.is_err()).count(), 1);
    assert_eq!(pool.writers.read().await.len(), required);
    assert_eq!(pool.conn_count.load(Ordering::Relaxed), required);
    assert_eq!(
        pool.registry.writer_idle_since_snapshot().await.len(),
        required
    );
    assert_eq!(
        pool.writer_connect_active_reserved.load(Ordering::Acquire),
        0
    );
    assert!(pool.shutdown_until(Duration::from_secs(1)).await);
}

#[tokio::test]
async fn committed_warm_writer_uses_resolved_active_coverage_authority() {
    let pool = make_pool().await;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
    pool.update_proxy_maps(HashMap::from([(2, vec![(addr.ip(), addr.port())])]), None)
        .await;
    suppress(&pool, IpFamily::V4);
    let reservation = pool
        .reserve_writer_open(WriterContour::Warm, WriterOpenIntent::Coverage, 2, addr)
        .await
        .unwrap();
    let (writer, _receiver) = unregistered_writer(
        &pool,
        1,
        2,
        addr,
        pool.current_generation(),
        WriterContour::Warm,
    );
    pool.publish_connected_writer(prepared(
        &pool,
        writer,
        WriterOpenIntent::Coverage,
        reservation,
        Arc::new(AtomicBool::new(false)),
    ))
    .await
    .expect("a committed generation must resolve warm coverage to its active role");
    assert_eq!(
        pool.writers.read().await[0].contour.load(Ordering::Acquire),
        WriterContour::Active.as_u8()
    );
    assert_eq!(pool.writer_connect_warm_reserved.load(Ordering::Acquire), 0);
    assert!(pool.shutdown_until(Duration::from_secs(1)).await);
}

#[tokio::test]
async fn suppressed_families_keep_their_full_coverage_reservation_budget() {
    let pool = make_pool_with_decision(NetworkDecision {
        ipv4_me: true,
        ipv6_me: true,
        ..NetworkDecision::default()
    })
    .await;
    let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
    let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443);
    pool.update_proxy_maps(
        HashMap::from([(2, vec![(v4.ip(), v4.port())])]),
        Some(HashMap::from([(2, vec![(v6.ip(), v6.port())])])),
    )
    .await;
    cap_at_one(&pool);
    suppress(&pool, IpFamily::V4);
    suppress(&pool, IpFamily::V6);
    let required = pool.required_writers_for_dc(1);
    assert_eq!(pool.active_coverage_required_total().await, required * 4);

    let mut receivers = Vec::new();
    let mut writers = pool.writers.write().await;
    for (index, (dc, addr)) in [(2, v4), (-2, v4), (-2, v6)].into_iter().enumerate() {
        for offset in 0..required {
            let (writer, receiver) = unregistered_writer(
                &pool,
                (index * required + offset + 1) as u64,
                dc,
                addr,
                pool.current_generation(),
                WriterContour::Active,
            );
            writers.push(writer);
            receivers.push(receiver);
        }
    }
    drop(writers);
    let reservation = pool
        .reserve_writer_open(WriterContour::Active, WriterOpenIntent::Coverage, 2, v6)
        .await
        .expect("other covered groups must not consume the suppressed family's floor budget");
    assert_eq!(
        pool.writer_connect_active_reserved.load(Ordering::Acquire),
        1
    );
    drop(reservation);
    assert_eq!(
        pool.writer_connect_active_reserved.load(Ordering::Acquire),
        0
    );
}

#[tokio::test]
async fn coverage_reservations_remain_bounded_and_release_on_drop() {
    let pool = make_pool().await;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
    pool.update_proxy_maps(HashMap::from([(2, vec![(addr.ip(), addr.port())])]), None)
        .await;
    cap_at_one(&pool);
    suppress(&pool, IpFamily::V4);
    let limit = pool.required_writers_for_dc(1) * 2
        + pool
            .reconnect_runtime
            .me_reconnect_max_concurrent_per_dc
            .max(1) as usize;
    let mut reservations = Vec::new();
    for _ in 0..limit {
        reservations.push(
            pool.reserve_writer_open(WriterContour::Active, WriterOpenIntent::Coverage, 2, addr)
                .await
                .expect("the configured coverage budget must remain available"),
        );
    }
    assert!(
        pool.reserve_writer_open(WriterContour::Active, WriterOpenIntent::Coverage, 2, addr,)
            .await
            .is_none()
    );
    assert_eq!(
        pool.writer_connect_active_reserved.load(Ordering::Acquire),
        limit
    );
    drop(reservations);
    assert_eq!(
        pool.writer_connect_active_reserved.load(Ordering::Acquire),
        0
    );
}

#[tokio::test]
async fn suppression_exception_does_not_admit_growth_replacement_or_pending_warm() {
    let pool = make_pool().await;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
    pool.update_proxy_maps(HashMap::from([(2, vec![(addr.ip(), addr.port())])]), None)
        .await;
    suppress(&pool, IpFamily::V4);
    for (contour, intent) in [
        (WriterContour::Active, WriterOpenIntent::Normal),
        (WriterContour::Active, WriterOpenIntent::Replacement),
        (WriterContour::Warm, WriterOpenIntent::Coverage),
        (WriterContour::Warm, WriterOpenIntent::Normal),
    ] {
        let (writer, _receiver) =
            unregistered_writer(&pool, 1, 2, addr, pool.current_generation(), contour);
        assert!(
            pool.authorize_writer_publication_capacity(&writer, contour, intent, &[])
                .is_err()
        );
    }
}

#[tokio::test]
async fn coverage_exception_never_enables_a_disabled_family() {
    let pool = make_pool().await;
    let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
    let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443);
    pool.update_proxy_maps(
        HashMap::from([(2, vec![(v4.ip(), v4.port())])]),
        Some(HashMap::from([(2, vec![(v6.ip(), v6.port())])])),
    )
    .await;
    suppress(&pool, IpFamily::V6);
    assert_eq!(
        pool.active_coverage_required_total().await,
        pool.required_writers_for_dc(1) * 2
    );
    let (writer, _receiver) = unregistered_writer(
        &pool,
        1,
        2,
        v6,
        pool.current_generation(),
        WriterContour::Active,
    );
    assert!(
        pool.authorize_writer_publication_capacity(
            &writer,
            WriterContour::Active,
            WriterOpenIntent::Coverage,
            &[],
        )
        .is_err()
    );
}

#[tokio::test]
async fn suppressed_coverage_cannot_publish_a_stale_generation() {
    let pool = make_pool().await;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
    pool.update_proxy_maps(HashMap::from([(2, vec![(addr.ip(), addr.port())])]), None)
        .await;
    suppress(&pool, IpFamily::V4);
    let reservation = pool
        .reserve_writer_open(WriterContour::Active, WriterOpenIntent::Coverage, 2, addr)
        .await
        .unwrap();
    let (writer, _receiver) = unregistered_writer(
        &pool,
        1,
        2,
        addr,
        pool.current_generation().saturating_sub(1),
        WriterContour::Active,
    );
    let task_started = Arc::new(AtomicBool::new(false));
    let error = pool
        .publish_connected_writer(prepared(
            &pool,
            writer,
            WriterOpenIntent::Coverage,
            reservation,
            task_started.clone(),
        ))
        .await
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("generation lost publication authority")
    );
    assert!(pool.writers.read().await.is_empty());
    assert!(pool.registry.writer_idle_since_snapshot().await.is_empty());
    assert_eq!(pool.conn_count.load(Ordering::Relaxed), 0);
    assert_eq!(
        pool.writer_connect_active_reserved.load(Ordering::Acquire),
        0
    );
    assert!(!task_started.load(Ordering::Acquire));
    assert!(pool.shutdown_until(Duration::from_secs(1)).await);
}

#[tokio::test]
async fn suppressed_coverage_rechecks_endpoints_after_publication_waits() {
    let pool = make_pool().await;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
    pool.update_proxy_maps(HashMap::from([(2, vec![(addr.ip(), addr.port())])]), None)
        .await;
    suppress(&pool, IpFamily::V4);
    let reservation = pool
        .reserve_writer_open(WriterContour::Active, WriterOpenIntent::Coverage, 2, addr)
        .await
        .unwrap();
    let (writer, _receiver) = unregistered_writer(
        &pool,
        1,
        2,
        addr,
        pool.current_generation(),
        WriterContour::Active,
    );
    let task_started = Arc::new(AtomicBool::new(false));
    let publication = pool.publish_connected_writer(prepared(
        &pool,
        writer,
        WriterOpenIntent::Coverage,
        reservation,
        task_started.clone(),
    ));
    tokio::pin!(publication);
    let guard = pool.writers.write().await;
    tokio::select! {
        biased;
        result = &mut publication => panic!("publication bypassed the writer barrier: {result:?}"),
        _ = tokio::task::yield_now() => {}
    }
    pool.update_proxy_maps(HashMap::from([(2, vec![(addr.ip(), 444)])]), None)
        .await;
    drop(guard);
    let error = publication.await.unwrap_err();
    assert!(
        error
            .to_string()
            .contains("target changed before publication")
    );
    assert!(pool.writers.read().await.is_empty());
    assert!(pool.registry.writer_idle_since_snapshot().await.is_empty());
    assert_eq!(pool.conn_count.load(Ordering::Relaxed), 0);
    assert_eq!(
        pool.writer_connect_active_reserved.load(Ordering::Acquire),
        0
    );
    assert!(!task_started.load(Ordering::Acquire));
    assert!(pool.shutdown_until(Duration::from_secs(1)).await);
}
