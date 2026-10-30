use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::Ordering;

use super::tests::{insert_writer, insert_writer_floor};
use crate::network::probe::NetworkDecision;
use crate::transport::middle_proxy::pool::WriterContour;
use crate::transport::middle_proxy::pool_writer_security_tests::make_pool_with_decision;

#[tokio::test]
async fn nonpreferred_family_warm_generation_retains_authority_and_commits() {
    let pool = make_pool_with_decision(NetworkDecision {
        ipv4_me: true,
        ipv6_me: true,
        effective_prefer: 4,
        effective_multipath: false,
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
    let desired = pool.desired_dc_endpoints().await;
    let map_hash = super::MePool::desired_map_hash(&desired);
    let endpoint_revision = pool.endpoint_snapshot.load().revision;
    let reservation = pool
        .reserve_reinit_attempt(true, map_hash, endpoint_revision, 100)
        .expect("current endpoint revision must admit the hardswap");
    assert!(pool.hardswap_warmup_is_authoritative(
        reservation.attempt.generation,
        map_hash,
        endpoint_revision,
    ));
    let generation = reservation.attempt.generation;
    let fresh_v4 = insert_writer_floor(&pool, 10, 2, v4, generation, WriterContour::Warm).await;
    let fresh_v6 = insert_writer_floor(&pool, 20, 2, v6, generation, WriterContour::Warm).await;
    let fresh_v4_media =
        insert_writer_floor(&pool, 30, -2, v4, generation, WriterContour::Warm).await;
    let fresh_v6_media =
        insert_writer_floor(&pool, 40, -2, v6, generation, WriterContour::Warm).await;

    assert_eq!(pool.reconcile_writer_generation_roles().await, 0);
    for writer in fresh_v4
        .iter()
        .chain(&fresh_v6)
        .chain(&fresh_v4_media)
        .chain(&fresh_v6_media)
    {
        assert!(!writer.draining.load(Ordering::Acquire));
    }

    let outcome = pool
        .commit_reinit_attempt(&reservation.attempt, &desired, 1.0)
        .await
        .expect("full dual-family floor must commit without multipath selection");

    assert!(outcome.missing_groups.is_empty());
    assert_eq!(pool.current_generation(), generation);
}

#[tokio::test]
async fn endpoint_revision_fences_pending_hardswap_after_map_aba() {
    let pool = make_pool_with_decision(NetworkDecision {
        ipv4_me: true,
        effective_prefer: 4,
        ..NetworkDecision::default()
    })
    .await;
    let endpoint_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 10)), 443);
    let endpoint_b = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 11)), 443);
    pool.update_proxy_maps(
        HashMap::from([(2, vec![(endpoint_a.ip(), endpoint_a.port())])]),
        None,
    )
    .await;
    let desired_a = pool.desired_dc_endpoints().await;
    let map_hash = super::MePool::desired_map_hash(&desired_a);
    let endpoint_revision = pool.endpoint_snapshot.load().revision;
    let reservation = pool
        .reserve_reinit_attempt(true, map_hash, endpoint_revision, 100)
        .expect("current endpoint revision must admit the hardswap");
    assert!(pool.hardswap_warmup_is_authoritative(
        reservation.attempt.generation,
        map_hash,
        endpoint_revision,
    ));
    let warm = insert_writer(
        &pool,
        100,
        2,
        endpoint_a,
        reservation.attempt.generation,
        WriterContour::Warm,
    )
    .await;

    pool.update_proxy_maps(
        HashMap::from([(2, vec![(endpoint_b.ip(), endpoint_b.port())])]),
        None,
    )
    .await;
    assert!(!pool.hardswap_warmup_is_authoritative(
        reservation.attempt.generation,
        map_hash,
        endpoint_revision,
    ));
    pool.update_proxy_maps(
        HashMap::from([(2, vec![(endpoint_a.ip(), endpoint_a.port())])]),
        None,
    )
    .await;
    assert!(!pool.hardswap_warmup_is_authoritative(
        reservation.attempt.generation,
        map_hash,
        endpoint_revision,
    ));

    let snapshot = pool.api_hardswap_snapshot().await;

    assert!(snapshot.pending);
    assert_eq!(snapshot.pending_map_current, Some(false));
    assert_eq!(snapshot.pending_writers_current, 0);
    assert_eq!(snapshot.orphan_warm_writers_current, 1);
    assert!(!warm.draining.load(Ordering::Acquire));
}
