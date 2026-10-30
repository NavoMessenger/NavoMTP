use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::time::Instant;

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::{DcFamilyGroup, MePool, ReinitCommitFailure, commit_reinit_state};
use crate::config::MeBindStaleMode;
use crate::transport::middle_proxy::codec::WriterCommand;
use crate::transport::middle_proxy::pool::{
    MeWriter, ReinitAttemptState, ReinitCoordinatorState, ReinitPendingState, WriterContour,
};
use crate::transport::middle_proxy::pool_writer_security_tests::make_pool;

fn addr(octet: u8, port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, octet)), port)
}

fn addr_v6(segment: u16, port: u16) -> SocketAddr {
    SocketAddr::new(
        IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, segment)),
        port,
    )
}

pub(super) async fn insert_writer(
    pool: &Arc<MePool>,
    writer_id: u64,
    writer_dc: i32,
    endpoint: SocketAddr,
    generation: u64,
    contour: WriterContour,
) -> MeWriter {
    let (tx, _rx) = mpsc::channel::<WriterCommand>(8);
    let byte_budget = pool.new_writer_byte_budget();
    let writer = MeWriter {
        id: writer_id,
        addr: endpoint,
        source_ip: endpoint.ip(),
        writer_dc,
        generation,
        contour: Arc::new(AtomicU8::new(contour.as_u8())),
        created_at: Instant::now(),
        tx: tx.clone(),
        byte_budget: byte_budget.clone(),
        cancel: CancellationToken::new(),
        degraded: Arc::new(AtomicBool::new(false)),
        rtt_ema_ms_x10: Arc::new(AtomicU32::new(0)),
        draining: Arc::new(AtomicBool::new(false)),
        draining_started_at_epoch_secs: Arc::new(AtomicU64::new(0)),
        drain_deadline_epoch_secs: Arc::new(AtomicU64::new(0)),
        allow_drain_fallback: Arc::new(AtomicBool::new(false)),
    };

    pool.registry
        .register_writer(writer_id, tx, byte_budget)
        .await;
    pool.writers.write().await.push(writer.clone());
    pool.conn_count.fetch_add(1, Ordering::Relaxed);
    writer
}

pub(super) async fn insert_writer_floor(
    pool: &Arc<MePool>,
    first_writer_id: u64,
    writer_dc: i32,
    endpoint: SocketAddr,
    generation: u64,
    contour: WriterContour,
) -> Vec<MeWriter> {
    let required = pool.required_writers_for_dc(1);
    let mut writers = Vec::with_capacity(required);
    for offset in 0..required {
        writers.push(
            insert_writer(
                pool,
                first_writer_id + offset as u64,
                writer_dc,
                endpoint,
                generation,
                contour,
            )
            .await,
        );
    }
    writers
}

fn desired_two_dcs() -> HashMap<i32, HashSet<SocketAddr>> {
    HashMap::from([
        (1, HashSet::from([addr(1, 2001)])),
        (2, HashSet::from([addr(2, 2002)])),
    ])
}

#[test]
fn coverage_ratio_counts_dc_coverage_not_floor() {
    let dc1 = addr(1, 2001);
    let dc2 = addr(2, 2002);

    let mut desired_by_dc = HashMap::<i32, HashSet<SocketAddr>>::new();
    desired_by_dc.insert(1, HashSet::from([dc1]));
    desired_by_dc.insert(2, HashSet::from([dc2]));

    let active_writer_addrs = HashSet::from([(1, dc1)]);
    let (ratio, missing_dc) = MePool::coverage_ratio(&desired_by_dc, &active_writer_addrs);

    assert_eq!(ratio, 0.5);
    assert_eq!(missing_dc, vec![2]);
}

#[test]
fn coverage_ratio_ignores_empty_dc_groups() {
    let dc1 = addr(1, 2001);

    let mut desired_by_dc = HashMap::<i32, HashSet<SocketAddr>>::new();
    desired_by_dc.insert(1, HashSet::from([dc1]));
    desired_by_dc.insert(2, HashSet::new());

    let active_writer_addrs = HashSet::from([(1, dc1)]);
    let (ratio, missing_dc) = MePool::coverage_ratio(&desired_by_dc, &active_writer_addrs);

    assert_eq!(ratio, 1.0);
    assert!(missing_dc.is_empty());
}

#[test]
fn coverage_ratio_reports_missing_dcs_sorted() {
    let dc1 = addr(1, 2001);
    let dc2 = addr(2, 2002);

    let mut desired_by_dc = HashMap::<i32, HashSet<SocketAddr>>::new();
    desired_by_dc.insert(2, HashSet::from([dc2]));
    desired_by_dc.insert(1, HashSet::from([dc1]));

    let (ratio, missing_dc) = MePool::coverage_ratio(&desired_by_dc, &HashSet::new());

    assert_eq!(ratio, 0.0);
    assert_eq!(missing_dc, vec![1, 2]);
}

#[test]
fn stale_concurrent_attempt_cannot_regress_active_generation() {
    let mut state = ReinitCoordinatorState {
        next_attempt_id: 3,
        active_generation: 1,
        desired_map_hash: 22,
        endpoint_revision: 7,
        floor_policy_revision: 1,
        pending: Some(ReinitPendingState {
            generation: 3,
            started_at_epoch_secs: 1,
            map_hash: 22,
            endpoint_revision: 7,
        }),
        attempts: HashMap::from([
            (
                1,
                ReinitAttemptState {
                    generation: 2,
                    map_hash: 11,
                    endpoint_revision: 6,
                    hardswap: true,
                    committed: false,
                },
            ),
            (
                2,
                ReinitAttemptState {
                    generation: 3,
                    map_hash: 22,
                    endpoint_revision: 7,
                    hardswap: true,
                    committed: false,
                },
            ),
        ]),
    };

    assert!(commit_reinit_state(&mut state, 2, 3, 22, 7, true));
    assert_eq!(state.active_generation, 3);
    assert!(!commit_reinit_state(&mut state, 1, 2, 11, 6, true));
    assert_eq!(state.active_generation, 3);
    assert!(state.pending.is_none());
}

#[tokio::test]
async fn partial_hardswap_is_rejected_when_stale_binding_is_disabled() {
    let pool = make_pool().await;
    let desired_by_dc = desired_two_dcs();
    let active_generation = pool.current_generation();
    let old_dc1 = insert_writer(
        &pool,
        101,
        1,
        addr(1, 2001),
        active_generation,
        WriterContour::Active,
    )
    .await;
    let old_dc2 = insert_writer(
        &pool,
        102,
        2,
        addr(2, 2002),
        active_generation,
        WriterContour::Active,
    )
    .await;
    let map_hash = MePool::desired_map_hash(&desired_by_dc);
    let endpoint_revision = pool.endpoint_snapshot.load().revision;
    let reservation = pool
        .reserve_reinit_attempt(true, map_hash, endpoint_revision, 100)
        .expect("endpoint revision must remain current");
    insert_writer_floor(
        &pool,
        201,
        1,
        addr(1, 2001),
        reservation.attempt.generation,
        WriterContour::Warm,
    )
    .await;

    let result = pool
        .commit_reinit_attempt(&reservation.attempt, &desired_by_dc, 0.5)
        .await;

    assert!(matches!(
        result,
        Err(ReinitCommitFailure::Redundancy { .. })
    ));
    assert_eq!(pool.current_generation(), active_generation);
    assert!(!old_dc1.draining.load(Ordering::Acquire));
    assert!(!old_dc2.draining.load(Ordering::Acquire));
}

#[tokio::test]
async fn partial_hardswap_preserves_fallback_only_for_missing_dc() {
    let pool = make_pool().await;
    pool.binding_policy
        .me_bind_stale_mode
        .store(MeBindStaleMode::Ttl.as_u8(), Ordering::Release);
    let desired_by_dc = desired_two_dcs();
    let active_generation = pool.current_generation();
    let old_dc1 = insert_writer(
        &pool,
        301,
        1,
        addr(1, 2001),
        active_generation,
        WriterContour::Active,
    )
    .await;
    let old_dc2 = insert_writer(
        &pool,
        302,
        2,
        addr(9, 2999),
        active_generation,
        WriterContour::Active,
    )
    .await;
    let map_hash = MePool::desired_map_hash(&desired_by_dc);
    let endpoint_revision = pool.endpoint_snapshot.load().revision;
    let reservation = pool
        .reserve_reinit_attempt(true, map_hash, endpoint_revision, 100)
        .expect("endpoint revision must remain current");
    let fresh_dc1 = insert_writer_floor(
        &pool,
        401,
        1,
        addr(1, 2001),
        reservation.attempt.generation,
        WriterContour::Warm,
    )
    .await;

    let outcome = pool
        .commit_reinit_attempt(&reservation.attempt, &desired_by_dc, 0.5)
        .await
        .expect("partial hardswap must commit when bounded stale fallback is enabled");

    assert_eq!(pool.current_generation(), reservation.attempt.generation);
    assert_eq!(outcome.missing_dc, vec![2]);
    assert_eq!(outcome.force_close_writer_ids, vec![301]);
    assert!(old_dc1.draining.load(Ordering::Acquire));
    assert!(!old_dc1.allow_drain_fallback.load(Ordering::Acquire));
    assert!(old_dc2.draining.load(Ordering::Acquire));
    assert!(old_dc2.allow_drain_fallback.load(Ordering::Acquire));
    assert_eq!(
        WriterContour::from_u8(fresh_dc1[0].contour.load(Ordering::Acquire)),
        WriterContour::Active
    );
}

#[tokio::test]
async fn partial_hardswap_preserves_fallback_only_for_underfloor_family() {
    let pool = make_pool().await;
    pool.binding_policy
        .me_bind_stale_mode
        .store(MeBindStaleMode::Ttl.as_u8(), Ordering::Release);
    let v4 = addr(1, 2001);
    let v6 = addr_v6(1, 2001);
    let desired_by_dc = HashMap::from([(1, HashSet::from([v4, v6]))]);
    let active_generation = pool.current_generation();
    let old_v4 = insert_writer(&pool, 451, 1, v4, active_generation, WriterContour::Active).await;
    let old_v6 = insert_writer(&pool, 452, 1, v6, active_generation, WriterContour::Active).await;
    let map_hash = MePool::desired_map_hash(&desired_by_dc);
    let endpoint_revision = pool.endpoint_snapshot.load().revision;
    let reservation = pool
        .reserve_reinit_attempt(true, map_hash, endpoint_revision, 100)
        .expect("endpoint revision must remain current");
    insert_writer_floor(
        &pool,
        461,
        1,
        v4,
        reservation.attempt.generation,
        WriterContour::Warm,
    )
    .await;

    let outcome = pool
        .commit_reinit_attempt(&reservation.attempt, &desired_by_dc, 0.5)
        .await
        .expect("one covered family satisfies the configured weighted quorum");

    assert_eq!(
        outcome.missing_groups,
        vec![DcFamilyGroup {
            dc: 1,
            family: crate::network::IpFamily::V6,
        }]
    );
    assert!(outcome.force_close_writer_ids.contains(&old_v4.id));
    assert!(!outcome.force_close_writer_ids.contains(&old_v6.id));
    assert!(!old_v4.allow_drain_fallback.load(Ordering::Acquire));
    assert!(old_v6.allow_drain_fallback.load(Ordering::Acquire));
}

#[tokio::test]
async fn complete_hardswap_promotes_fresh_generation_and_retires_old_writers() {
    let pool = make_pool().await;
    let desired_by_dc = desired_two_dcs();
    let active_generation = pool.current_generation();
    let old_dc1 = insert_writer(
        &pool,
        501,
        1,
        addr(1, 2001),
        active_generation,
        WriterContour::Active,
    )
    .await;
    let old_dc2 = insert_writer(
        &pool,
        502,
        2,
        addr(2, 2002),
        active_generation,
        WriterContour::Active,
    )
    .await;
    let map_hash = MePool::desired_map_hash(&desired_by_dc);
    let endpoint_revision = pool.endpoint_snapshot.load().revision;
    let reservation = pool
        .reserve_reinit_attempt(true, map_hash, endpoint_revision, 100)
        .expect("endpoint revision must remain current");
    let fresh_dc1 = insert_writer_floor(
        &pool,
        601,
        1,
        addr(1, 2001),
        reservation.attempt.generation,
        WriterContour::Warm,
    )
    .await;
    let fresh_dc2 = insert_writer_floor(
        &pool,
        611,
        2,
        addr(2, 2002),
        reservation.attempt.generation,
        WriterContour::Warm,
    )
    .await;

    let outcome = pool
        .commit_reinit_attempt(&reservation.attempt, &desired_by_dc, 1.0)
        .await
        .expect("fully covered hardswap must commit");

    assert_eq!(pool.current_generation(), reservation.attempt.generation);
    assert!(outcome.missing_dc.is_empty());
    assert_eq!(outcome.force_close_writer_ids, vec![501, 502]);
    assert!(old_dc1.draining.load(Ordering::Acquire));
    assert!(old_dc2.draining.load(Ordering::Acquire));
    assert_eq!(
        WriterContour::from_u8(fresh_dc1[0].contour.load(Ordering::Acquire)),
        WriterContour::Active
    );
    assert_eq!(
        WriterContour::from_u8(fresh_dc2[0].contour.load(Ordering::Acquire)),
        WriterContour::Active
    );
}

#[tokio::test]
async fn endpoint_revision_change_supersedes_hardswap_before_writer_drain() {
    let pool = make_pool().await;
    let old_endpoint = addr(1, 2001);
    pool.update_proxy_maps(
        HashMap::from([(1, vec![(old_endpoint.ip(), old_endpoint.port())])]),
        None,
    )
    .await;
    let active_generation = pool.current_generation();
    let old_writer = insert_writer(
        &pool,
        651,
        1,
        old_endpoint,
        active_generation,
        WriterContour::Active,
    )
    .await;
    let desired_by_dc = HashMap::from([(1, HashSet::from([old_endpoint]))]);
    let map_hash = MePool::desired_map_hash(&desired_by_dc);
    let endpoint_revision = pool.endpoint_snapshot.load().revision;
    let reservation = pool
        .reserve_reinit_attempt(true, map_hash, endpoint_revision, 100)
        .expect("endpoint revision must remain current");
    let fresh_writer = insert_writer(
        &pool,
        652,
        1,
        old_endpoint,
        reservation.attempt.generation,
        WriterContour::Warm,
    )
    .await;

    let replacement_endpoint = addr(3, 2003);
    pool.update_proxy_maps(
        HashMap::from([(
            1,
            vec![(replacement_endpoint.ip(), replacement_endpoint.port())],
        )]),
        None,
    )
    .await;

    let result = pool
        .commit_reinit_attempt(&reservation.attempt, &desired_by_dc, 1.0)
        .await;

    assert!(matches!(result, Err(ReinitCommitFailure::Superseded)));
    assert_eq!(pool.current_generation(), active_generation);
    assert!(!old_writer.draining.load(Ordering::Acquire));
    assert!(!fresh_writer.draining.load(Ordering::Acquire));
    assert_eq!(
        WriterContour::from_u8(fresh_writer.contour.load(Ordering::Acquire)),
        WriterContour::Warm
    );
}

#[tokio::test]
async fn generation_role_reconciliation_promotes_active_warm_and_drains_orphans() {
    let pool = make_pool().await;
    let endpoint = addr(1, 2001);
    pool.update_proxy_maps(
        HashMap::from([(1, vec![(endpoint.ip(), endpoint.port())])]),
        None,
    )
    .await;
    let desired_by_dc = pool.desired_dc_endpoints().await;
    let map_hash = MePool::desired_map_hash(&desired_by_dc);
    let endpoint_revision = pool.endpoint_snapshot.load().revision;
    let reservation = pool
        .reserve_reinit_attempt(true, map_hash, endpoint_revision, 100)
        .expect("endpoint revision must remain current");
    let active_warm = insert_writer(
        &pool,
        701,
        1,
        endpoint,
        pool.current_generation(),
        WriterContour::Warm,
    )
    .await;
    let pending_warm = insert_writer(
        &pool,
        702,
        1,
        endpoint,
        reservation.attempt.generation,
        WriterContour::Warm,
    )
    .await;
    let orphan_warm = insert_writer(
        &pool,
        703,
        1,
        endpoint,
        reservation.attempt.generation + 10,
        WriterContour::Warm,
    )
    .await;

    let changed = pool.reconcile_writer_generation_roles().await;

    assert_eq!(changed, 2);
    assert_eq!(
        WriterContour::from_u8(active_warm.contour.load(Ordering::Acquire)),
        WriterContour::Active
    );
    assert_eq!(
        WriterContour::from_u8(pending_warm.contour.load(Ordering::Acquire)),
        WriterContour::Warm
    );
    assert!(orphan_warm.draining.load(Ordering::Acquire));
    assert!(!orphan_warm.allow_drain_fallback.load(Ordering::Acquire));
    let snapshot = pool.api_hardswap_snapshot().await;
    let desired = pool.desired_dc_endpoints().await;
    let coverage = pool.hardswap_coverage(&desired, &[(1, endpoint)]);
    assert_eq!(snapshot.orphan_warm_writers_current, 0);
    assert_eq!(snapshot.pending_writer_deficit, coverage.writer_deficit);
    assert_eq!(
        snapshot.pending_missing_dc_groups,
        coverage.missing_groups.len()
    );
}
