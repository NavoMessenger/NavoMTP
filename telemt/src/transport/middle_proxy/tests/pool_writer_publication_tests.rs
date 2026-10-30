use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use super::codec::WriterCommand;
use super::pool::{MeWriter, WriterContour, WriterOpenIntent};
use super::pool_writer_security_tests::{make_pool, make_pool_with_decision};
use super::registry::ConnMeta;
use crate::network::probe::NetworkDecision;

fn unregistered_writer(
    pool: &Arc<super::pool::MePool>,
    writer_id: u64,
    addr: SocketAddr,
    generation: u64,
    contour: WriterContour,
) -> MeWriter {
    let (tx, _rx) = mpsc::channel::<WriterCommand>(8);
    MeWriter {
        id: writer_id,
        addr,
        source_ip: addr.ip(),
        writer_dc: 2,
        generation,
        contour: Arc::new(AtomicU8::new(contour.as_u8())),
        created_at: Instant::now(),
        tx,
        byte_budget: pool.new_writer_byte_budget(),
        cancel: CancellationToken::new(),
        degraded: Arc::new(AtomicBool::new(false)),
        rtt_ema_ms_x10: Arc::new(AtomicU32::new(0)),
        draining: Arc::new(AtomicBool::new(false)),
        draining_started_at_epoch_secs: Arc::new(AtomicU64::new(0)),
        drain_deadline_epoch_secs: Arc::new(AtomicU64::new(0)),
        allow_drain_fallback: Arc::new(AtomicBool::new(false)),
    }
}

#[tokio::test]
async fn normal_warm_publication_cannot_race_past_the_dc_floor() {
    let pool = make_pool().await;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
    pool.update_proxy_maps(
        std::collections::HashMap::from([(2, vec![(addr.ip(), addr.port())])]),
        None,
    )
    .await;
    let generation = 2;
    let writers = (1..=3)
        .map(|writer_id| {
            unregistered_writer(&pool, writer_id, addr, generation, WriterContour::Warm)
        })
        .collect::<Vec<_>>();
    let candidate = unregistered_writer(&pool, 4, addr, generation, WriterContour::Warm);

    assert!(
        pool.authorize_writer_publication_capacity(
            &candidate,
            WriterContour::Warm,
            WriterOpenIntent::Normal,
            &writers[..2],
        )
        .is_ok()
    );
    assert!(
        pool.authorize_writer_publication_capacity(
            &candidate,
            WriterContour::Warm,
            WriterOpenIntent::Normal,
            &writers,
        )
        .is_err()
    );
    assert!(
        pool.authorize_writer_publication_capacity(
            &candidate,
            WriterContour::Warm,
            WriterOpenIntent::Replacement,
            &writers,
        )
        .is_ok()
    );
}

#[tokio::test]
async fn normal_active_publication_cannot_race_past_the_family_floor() {
    let pool = make_pool().await;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
    pool.update_proxy_maps(
        std::collections::HashMap::from([(2, vec![(addr.ip(), addr.port())])]),
        None,
    )
    .await;
    let generation = pool.current_generation();
    let writers = (1..=3)
        .map(|writer_id| {
            unregistered_writer(&pool, writer_id, addr, generation, WriterContour::Active)
        })
        .collect::<Vec<_>>();
    let candidate = unregistered_writer(&pool, 4, addr, generation, WriterContour::Active);

    assert!(
        pool.authorize_writer_publication_capacity(
            &candidate,
            WriterContour::Active,
            WriterOpenIntent::Coverage,
            &writers[..2],
        )
        .is_ok()
    );
    assert!(
        pool.authorize_writer_publication_capacity(
            &candidate,
            WriterContour::Active,
            WriterOpenIntent::Coverage,
            &writers,
        )
        .is_err()
    );
}

#[tokio::test]
async fn stale_same_family_writers_do_not_satisfy_current_endpoint_coverage() {
    let pool = make_pool().await;
    let current_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
    let stale_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)), 443);
    pool.update_proxy_maps(
        std::collections::HashMap::from([(2, vec![(current_addr.ip(), current_addr.port())])]),
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
    let generation = pool.current_generation();
    let required = pool.required_writers_for_dc_with_floor_mode(1, false);
    pool.writers
        .write()
        .await
        .extend((1..=required.saturating_mul(2)).map(|writer_id| {
            unregistered_writer(
                &pool,
                writer_id as u64,
                stale_addr,
                generation,
                WriterContour::Active,
            )
        }));

    assert!(
        pool.can_open_writer_for_contour(
            WriterContour::Active,
            WriterOpenIntent::Coverage,
            2,
            current_addr,
        )
        .await
    );
    assert!(
        !pool
            .can_open_writer_for_contour(
                WriterContour::Active,
                WriterOpenIntent::Coverage,
                2,
                stale_addr,
            )
            .await
    );
}

#[tokio::test]
async fn covered_group_does_not_consume_another_group_coverage_slot() {
    let pool = make_pool().await;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
    pool.update_proxy_maps(
        std::collections::HashMap::from([(2, vec![(addr.ip(), addr.port())])]),
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
    let generation = pool.current_generation();
    let required = pool.required_writers_for_dc_with_floor_mode(1, false);
    pool.writers
        .write()
        .await
        .extend((1..=required).map(|writer_id| {
            unregistered_writer(
                &pool,
                writer_id as u64,
                addr,
                generation,
                WriterContour::Active,
            )
        }));

    assert!(
        !pool
            .can_open_writer_for_contour(
                WriterContour::Active,
                WriterOpenIntent::Coverage,
                2,
                addr,
            )
            .await
    );
}

#[tokio::test]
async fn normal_active_publication_allows_adaptive_growth_above_family_floor() {
    let pool = make_pool().await;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
    pool.update_proxy_maps(
        std::collections::HashMap::from([(2, vec![(addr.ip(), addr.port())])]),
        None,
    )
    .await;
    let generation = pool.current_generation();
    let writers = (1..=3)
        .map(|writer_id| {
            unregistered_writer(&pool, writer_id, addr, generation, WriterContour::Active)
        })
        .collect::<Vec<_>>();
    let candidate = unregistered_writer(&pool, 4, addr, generation, WriterContour::Active);

    assert!(
        pool.authorize_writer_publication_capacity(
            &candidate,
            WriterContour::Active,
            WriterOpenIntent::Normal,
            &writers,
        )
        .is_ok()
    );
}

#[tokio::test]
async fn normal_active_publication_rejects_configured_contour_cap() {
    let pool = make_pool().await;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
    pool.update_proxy_maps(
        std::collections::HashMap::from([(2, vec![(addr.ip(), addr.port())])]),
        None,
    )
    .await;
    pool.floor_runtime
        .me_adaptive_floor_cpu_cores_override
        .store(1, Ordering::Relaxed);
    pool.floor_runtime
        .me_adaptive_floor_max_active_writers_per_core
        .store(3, Ordering::Relaxed);
    pool.floor_runtime
        .me_adaptive_floor_max_active_writers_global
        .store(3, Ordering::Relaxed);
    let generation = pool.current_generation();
    let writers = (1..=3)
        .map(|writer_id| {
            unregistered_writer(&pool, writer_id, addr, generation, WriterContour::Active)
        })
        .collect::<Vec<_>>();
    let candidate = unregistered_writer(&pool, 4, addr, generation, WriterContour::Active);

    assert!(
        pool.authorize_writer_publication_capacity(
            &candidate,
            WriterContour::Active,
            WriterOpenIntent::Normal,
            &writers,
        )
        .is_err()
    );
}

#[tokio::test]
async fn nonpreferred_enabled_family_retains_writer_publication_authority() {
    let pool = make_pool_with_decision(NetworkDecision {
        ipv4_me: true,
        ipv6_me: true,
        effective_prefer: 4,
        effective_multipath: false,
        ..NetworkDecision::default()
    })
    .await;
    let v4_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
    let v6_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443);
    pool.update_proxy_maps(
        std::collections::HashMap::from([(2, vec![(v4_addr.ip(), v4_addr.port())])]),
        Some(std::collections::HashMap::from([(
            2,
            vec![(v6_addr.ip(), v6_addr.port())],
        )])),
    )
    .await;
    let candidate = unregistered_writer(
        &pool,
        1,
        v6_addr,
        pool.current_generation(),
        WriterContour::Active,
    );

    assert!(
        pool.authorize_writer_publication_capacity(
            &candidate,
            WriterContour::Active,
            WriterOpenIntent::Coverage,
            &[],
        )
        .is_ok()
    );
}

#[tokio::test]
async fn successful_writer_publication_is_fully_visible_and_removable() {
    let pool = make_pool().await;
    let writer_id = 76_002;
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
    let (tx, _rx) = mpsc::channel::<WriterCommand>(8);
    let byte_budget = pool.new_writer_byte_budget();
    let cancel = CancellationToken::new();
    let writer = MeWriter {
        id: writer_id,
        addr,
        source_ip: addr.ip(),
        writer_dc: 2,
        generation: pool.current_generation(),
        contour: Arc::new(AtomicU8::new(WriterContour::Active.as_u8())),
        created_at: Instant::now(),
        tx: tx.clone(),
        byte_budget: byte_budget.clone(),
        cancel: cancel.clone(),
        degraded: Arc::new(AtomicBool::new(false)),
        rtt_ema_ms_x10: Arc::new(AtomicU32::new(0)),
        draining: Arc::new(AtomicBool::new(false)),
        draining_started_at_epoch_secs: Arc::new(AtomicU64::new(0)),
        drain_deadline_epoch_secs: Arc::new(AtomicU64::new(0)),
        allow_drain_fallback: Arc::new(AtomicBool::new(false)),
    };
    let task_started = Arc::new(AtomicBool::new(false));
    let task_started_writer = Arc::clone(&task_started);
    let writer_task = async move {
        task_started_writer.store(true, Ordering::Release);
        cancel.cancelled().await;
    };
    let task_registration = pool.lifecycle.try_register().unwrap();

    pool.publish_prepared_writer(writer, tx, byte_budget, task_registration, writer_task)
        .await;

    assert_eq!(pool.writers.read().await.len(), 1);
    assert_eq!(pool.conn_count.load(Ordering::Relaxed), 1);
    tokio::time::timeout(Duration::from_secs(1), async {
        while !task_started.load(Ordering::Acquire) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("published writer task must start");

    let (conn_id, _response_rx) = pool.registry.register().await;
    assert!(
        pool.registry
            .bind_writer(
                conn_id,
                writer_id,
                ConnMeta {
                    target_dc: 2,
                    client_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 7300),
                    our_addr: addr,
                    proto_flags: 0,
                },
            )
            .await
    );
    assert_eq!(
        pool.registry.get_writer(conn_id).await.unwrap().writer_id,
        writer_id
    );

    pool.remove_writer_and_close_clients(writer_id).await;

    assert!(pool.writers.read().await.is_empty());
    assert_eq!(pool.conn_count.load(Ordering::Relaxed), 0);
    assert!(pool.registry.get_writer(conn_id).await.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn published_writer_removal_race_preserves_count() {
    let pool = make_pool().await;

    for writer_id in 80_000..90_000 {
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443);
        let (tx, _rx) = mpsc::channel::<WriterCommand>(1);
        let byte_budget = pool.new_writer_byte_budget();
        let cancel = CancellationToken::new();
        let writer = MeWriter {
            id: writer_id,
            addr,
            source_ip: addr.ip(),
            writer_dc: 2,
            generation: pool.current_generation(),
            contour: Arc::new(AtomicU8::new(WriterContour::Active.as_u8())),
            created_at: Instant::now(),
            tx: tx.clone(),
            byte_budget: byte_budget.clone(),
            cancel: cancel.clone(),
            degraded: Arc::new(AtomicBool::new(false)),
            rtt_ema_ms_x10: Arc::new(AtomicU32::new(0)),
            draining: Arc::new(AtomicBool::new(false)),
            draining_started_at_epoch_secs: Arc::new(AtomicU64::new(0)),
            drain_deadline_epoch_secs: Arc::new(AtomicU64::new(0)),
            allow_drain_fallback: Arc::new(AtomicBool::new(false)),
        };
        let writer_task = async move {
            cancel.cancelled().await;
        };
        let task_registration = pool.lifecycle.try_register().unwrap();
        let remover_pool = Arc::clone(&pool);
        let remover = tokio::spawn(async move {
            loop {
                if remover_pool
                    .writers
                    .snapshot()
                    .iter()
                    .any(|writer| writer.id == writer_id)
                {
                    remover_pool
                        .remove_writer_and_close_clients(writer_id)
                        .await;
                    return;
                }
                tokio::task::yield_now().await;
            }
        });

        pool.publish_prepared_writer(writer, tx, byte_budget, task_registration, writer_task)
            .await;
        tokio::time::timeout(Duration::from_secs(1), remover)
            .await
            .expect("published writer must become removable")
            .expect("writer remover task must not panic");

        assert!(pool.writers.read().await.is_empty());
        assert_eq!(pool.conn_count.load(Ordering::Relaxed), 0);
    }
}
