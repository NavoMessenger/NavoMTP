use super::*;
use crate::transport::middle_proxy::registry::ConnMeta;

#[tokio::test]
async fn busy_obsolete_donor_preserves_clients_and_rechecks_policy() {
    for stale in [false, true] {
        let pool = make_pool().await;
        let obsolete = endpoint(21);
        let receiver = endpoint(22);
        pool.update_proxy_maps(
            HashMap::from([(2, vec![(receiver.ip(), receiver.port())])]),
            None,
        )
        .await;
        let victim = install_writer(&pool, 9001, 1, obsolete).await;
        let (client, _messages) = pool.registry.register().await;
        assert!(
            pool.registry
                .bind_writer(
                    client,
                    victim.id,
                    ConnMeta {
                        target_dc: 1,
                        client_addr: obsolete,
                        our_addr: obsolete,
                        proto_flags: 0,
                    }
                )
                .await
        );
        let authority = pool.floor_authority();
        let mut reservation = pool
            .registry
            .try_reserve_writer_replacement_preserving_clients(victim.id)
            .await
            .unwrap();
        let prepared = prepared_writer(&pool, 9002, 2, receiver).await;
        if stale {
            pool.reinit.coordinator.lock().floor_policy_revision += 1;
        }
        let result = pool
            .publish_prepared_replacement_writer(
                prepared,
                WriterRole::from_writer(&victim),
                WriterReplacementPurpose::CoverageTransfer {
                    authority,
                    receiver_floor: pool.required_writers_for_dc(1),
                },
                &mut reservation,
            )
            .await;
        assert_eq!(result.is_ok(), !stale);
        assert_eq!(victim.draining.load(Ordering::Acquire), !stale);
        assert_eq!(
            pool.registry.get_writer(client).await.unwrap().writer_id,
            victim.id
        );
        assert_eq!(
            pool.writer_replacement_open_reserved
                .load(Ordering::Acquire),
            usize::from(!stale)
        );
    }
}

#[tokio::test]
async fn transfer_commit_matches_independent_donor_floor_model() {
    // The model counts only current endpoints; obsolete sockets contribute no coverage.
    for obsolete in [false, true] {
        for donor_delta in [0usize, 1] {
            for receiver_full in [false, true] {
                let pool = make_pool().await;
                let donor = endpoint(31);
                let receiver = endpoint(32);
                pool.update_proxy_maps(
                    HashMap::from([
                        (1, vec![(donor.ip(), donor.port())]),
                        (2, vec![(receiver.ip(), receiver.port())]),
                    ]),
                    None,
                )
                .await;
                let floor = pool.required_writers_for_dc(1);
                let mut victim = None;
                for id in 0..(floor + donor_delta) {
                    let writer = install_writer(&pool, 10000 + id as u64, 1, donor).await;
                    if id == 0 {
                        victim = Some(writer);
                    }
                }
                let mut victim = victim.unwrap();
                if obsolete {
                    let mut writers = pool.writers.write().await;
                    writers
                        .iter_mut()
                        .find(|writer| writer.id == victim.id)
                        .unwrap()
                        .addr = endpoint(33);
                    victim.addr = endpoint(33);
                }
                if receiver_full {
                    for id in 0..floor {
                        install_writer(&pool, 11000 + id as u64, 2, receiver).await;
                    }
                }
                let mut reservation = pool
                    .registry
                    .try_reserve_writer_replacement(victim.id)
                    .await
                    .unwrap();
                let prepared = prepared_writer(&pool, 12000, 2, receiver).await;
                let result = pool
                    .publish_prepared_replacement_writer(
                        prepared,
                        WriterRole::from_writer(&victim),
                        WriterReplacementPurpose::CoverageTransfer {
                            authority: pool.floor_authority(),
                            receiver_floor: floor,
                        },
                        &mut reservation,
                    )
                    .await;
                assert_eq!(
                    result.is_ok(),
                    !receiver_full && (obsolete || donor_delta > 0),
                    "obsolete={obsolete}, surplus={donor_delta}, receiver_full={receiver_full}"
                );
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_transfers_cannot_overfill_receiver_or_steal_donor_floor() {
    let pool = make_pool().await;
    let donor = endpoint(41);
    let receiver = endpoint(42);
    pool.update_proxy_maps(
        HashMap::from([
            (1, vec![(donor.ip(), donor.port())]),
            (2, vec![(receiver.ip(), receiver.port())]),
        ]),
        None,
    )
    .await;
    pool.set_adaptive_floor_runtime_caps(pool.floor_authority(), 128, 128, 128, 128, 6, 0, 0);
    let floor = pool.required_writers_for_dc(1);
    let count = floor + 8;
    let mut victims = Vec::new();
    for id in 0..count {
        victims.push(install_writer(&pool, 20000 + id as u64, 1, donor).await);
    }
    let mut tasks = tokio::task::JoinSet::new();
    for (index, victim) in victims.into_iter().enumerate() {
        let pool = pool.clone();
        tasks.spawn(async move {
            let authority = pool.floor_authority();
            let mut reservation = pool
                .registry
                .try_reserve_writer_replacement(victim.id)
                .await
                .unwrap();
            let prepared = prepared_writer(&pool, 21000 + index as u64, 2, receiver).await;
            tokio::task::yield_now().await;
            pool.publish_prepared_replacement_writer(
                prepared,
                WriterRole::from_writer(&victim),
                WriterReplacementPurpose::CoverageTransfer {
                    authority,
                    receiver_floor: floor,
                },
                &mut reservation,
            )
            .await
            .is_ok()
        });
    }
    let mut committed = 0;
    while let Some(result) = tasks.join_next().await {
        committed += usize::from(result.unwrap());
    }
    assert_eq!(committed, floor);
    let writers = pool.writers.read().await;
    let live = |dc| {
        writers
            .iter()
            .filter(|writer| writer.writer_dc == dc && !writer.draining.load(Ordering::Acquire))
            .count()
    };
    assert_eq!(live(2), floor);
    assert_eq!(live(1), count - floor);
    assert!(live(1) >= floor);
    assert_eq!(
        pool.writer_replacement_open_reserved
            .load(Ordering::Acquire),
        committed
    );
}
