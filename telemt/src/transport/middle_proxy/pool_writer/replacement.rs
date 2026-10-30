use super::*;

impl MePool {
    /// Opens a replacement and atomically publishes it before retiring its reserved victim.
    pub(in crate::transport::middle_proxy) async fn replace_writer_with_generation_contour_for_dc(
        self: &Arc<Self>,
        addr: SocketAddr,
        rng: &SecureRandom,
        generation: u64,
        contour: WriterContour,
        writer_dc: i32,
        expected_victim_role: WriterRole,
        purpose: WriterReplacementPurpose,
        reservation: &mut WriterReplacementReservation<'_>,
    ) -> Result<()> {
        let prepared = self
            .prepare_writer_with_intent(
                addr,
                rng,
                generation,
                contour,
                writer_dc,
                WriterOpenIntent::Replacement,
            )
            .await?;
        self.publish_prepared_replacement_writer(
            prepared,
            expected_victim_role,
            purpose,
            reservation,
        )
        .await
    }

    async fn publish_prepared_replacement_writer(
        self: &Arc<Self>,
        prepared: PreparedWriter<'_>,
        expected_victim_role: WriterRole,
        purpose: WriterReplacementPurpose,
        reservation: &mut WriterReplacementReservation<'_>,
    ) -> Result<()> {
        let PreparedWriter {
            writer,
            tx,
            byte_budget,
            task_registration,
            mut writer_task,
            intent: _,
        } = prepared;
        let replacement_writer_id = writer.id;
        let victim_writer_id = reservation.writer_id();

        // Lock order is writers -> registry binding. No cancellation point follows acquisition of
        // the registry guard, so publication and victim retirement commit as one state change.
        let mut writers = self.writers.write().await;
        let mut registry_registration = self.registry.prepare_writer_registration().await;
        let coordinator = self.reinit.coordinator.lock();
        let contour = self.authorize_writer_publication(&writer, &coordinator)?;
        // Only this victim-backed transaction may replace Active coverage during suppression.
        let family = if writer.addr.is_ipv4() {
            crate::network::IpFamily::V4
        } else {
            crate::network::IpFamily::V6
        };
        let configured = if writer.addr.is_ipv4() {
            self.decision.ipv4_me
        } else {
            self.decision.ipv6_me
        };
        if !configured
            || (contour != WriterContour::Active
                && self.is_family_temporarily_suppressed(family, Self::now_epoch_secs()))
        {
            return Err(ProxyError::Proxy(
                "ME replacement family lost publication authority".into(),
            ));
        }
        writer.contour.store(contour.as_u8(), Ordering::Release);
        let Some(victim_pos) = writers
            .iter()
            .position(|candidate| candidate.id == victim_writer_id)
        else {
            return Err(ProxyError::Proxy(
                "ME replacement victim disappeared before commit".into(),
            ));
        };
        let victim = &writers[victim_pos];
        if victim.draining.load(Ordering::Acquire) || !expected_victim_role.matches(victim) {
            return Err(ProxyError::Proxy(
                "ME replacement victim changed role before commit".into(),
            ));
        }
        if !matches!(
            purpose,
            WriterReplacementPurpose::FloorRebalance { .. }
                | WriterReplacementPurpose::CoverageTransfer { .. }
        ) && (expected_victim_role.dc != writer.writer_dc
            || expected_victim_role.family != family)
        {
            return Err(ProxyError::Proxy(
                "ME replacement purpose cannot move coverage between groups".into(),
            ));
        }
        if let WriterReplacementPurpose::FloorRebalance {
            donor_floor,
            receiver_floor,
        } = purpose
        {
            if expected_victim_role.generation != coordinator.active_generation
                || writer.generation != coordinator.active_generation
            {
                return Err(ProxyError::Proxy(
                    "ME floor rebalance lost active-generation authority".into(),
                ));
            }
            let endpoint_snapshot = self.endpoint_snapshot.load();
            let donor_count = writers
                .iter()
                .filter(|candidate| {
                    !candidate.draining.load(Ordering::Acquire)
                        && candidate.writer_dc == expected_victim_role.dc
                        && candidate.generation == expected_victim_role.generation
                        && WriterContour::from_u8(candidate.contour.load(Ordering::Acquire))
                            == WriterContour::Active
                        && endpoint_snapshot
                            .contains_dc_endpoint(candidate.writer_dc, candidate.addr)
                        && (candidate.addr.is_ipv4()
                            == matches!(expected_victim_role.family, crate::network::IpFamily::V4))
                })
                .count();
            let receiver_family = if writer.addr.is_ipv4() {
                crate::network::IpFamily::V4
            } else {
                crate::network::IpFamily::V6
            };
            let receiver_count = writers
                .iter()
                .filter(|candidate| {
                    !candidate.draining.load(Ordering::Acquire)
                        && candidate.writer_dc == writer.writer_dc
                        && candidate.generation == writer.generation
                        && WriterContour::from_u8(candidate.contour.load(Ordering::Acquire))
                            == WriterContour::Active
                        && endpoint_snapshot
                            .contains_dc_endpoint(candidate.writer_dc, candidate.addr)
                        && (if candidate.addr.is_ipv4() {
                            crate::network::IpFamily::V4
                        } else {
                            crate::network::IpFamily::V6
                        }) == receiver_family
                })
                .count();
            let protected_floor = self.required_writers_for_dc_with_floor_mode(
                endpoint_snapshot
                    .endpoints_for_dc_family(expected_victim_role.dc, expected_victim_role.family)
                    .len(),
                false,
            );
            let current_receiver_floor = self.required_writers_for_dc_with_floor_mode(
                endpoint_snapshot
                    .endpoints_for_dc_family(writer.writer_dc, receiver_family)
                    .len(),
                false,
            );
            if donor_count <= donor_floor.max(protected_floor)
                || receiver_count >= receiver_floor.min(current_receiver_floor)
            {
                return Err(ProxyError::Proxy(
                    "ME floor rebalance became unnecessary before commit".into(),
                ));
            }
        }
        if let WriterReplacementPurpose::CoverageTransfer {
            authority,
            receiver_floor,
        } = purpose
        {
            if authority
                != (
                    coordinator.endpoint_revision,
                    coordinator.floor_policy_revision,
                )
                || contour != WriterContour::Active
                || expected_victim_role.contour != WriterContour::Active
            {
                return Err(ProxyError::Proxy(
                    "ME coverage transfer lost policy authority".into(),
                ));
            }
            let endpoints = self.endpoint_snapshot.load();
            let count = |dc, family| {
                writers
                    .iter()
                    .filter(|candidate| {
                        !candidate.draining.load(Ordering::Acquire)
                            && candidate.generation == coordinator.active_generation
                            && candidate.writer_dc == dc
                            && WriterContour::from_u8(candidate.contour.load(Ordering::Acquire))
                                == WriterContour::Active
                            && candidate.addr.is_ipv4()
                                == matches!(family, crate::network::IpFamily::V4)
                            && endpoints.contains_dc_endpoint(dc, candidate.addr)
                    })
                    .count()
            };
            let donor_is_current = victim.generation == coordinator.active_generation
                && endpoints.contains_dc_endpoint(victim.writer_dc, victim.addr);
            let donor_floor = self.required_writers_for_dc_with_floor_mode(
                endpoints
                    .endpoints_for_dc_family(victim.writer_dc, expected_victim_role.family)
                    .len(),
                false,
            );
            if (donor_is_current
                && count(victim.writer_dc, expected_victim_role.family) <= donor_floor)
                || count(writer.writer_dc, family)
                    >= receiver_floor.min(
                        self.required_writers_for_dc_with_floor_mode(
                            endpoints
                                .endpoints_for_dc_family(writer.writer_dc, family)
                                .len(),
                            false,
                        ),
                    )
            {
                return Err(ProxyError::Proxy(
                    "ME coverage transfer no longer preserves floors".into(),
                ));
            }
        }
        let lifetime = registry_registration
            .writer_lifetime(victim_writer_id)
            .ok_or_else(|| {
                ProxyError::Proxy("ME replacement victim transport disappeared".into())
            })?;
        if !lifetime.commit(&mut writer_task.opening, || {
            registry_registration.prepare_replacement_commit(reservation)
        }) {
            return Err(ProxyError::Proxy(
                "ME replacement victim became active before commit".into(),
            ));
        }

        registry_registration.install_with_lifetime(
            replacement_writer_id,
            tx,
            byte_budget,
            writer_task.lifetime.clone(),
        );
        writers.push(writer);
        self.conn_count.fetch_add(1, Ordering::Relaxed);
        writers.publish_current();
        self.apply_writer_draining_state(&writers[victim_pos], self.force_close_timeout(), false);
        self.lifecycle
            .spawn_registered_writer(task_registration, writer_task);
        reservation.mark_committed();
        drop(coordinator);
        drop(registry_registration);
        drop(writers);
        self.notify_writer_epoch();
        info!(
            victim_writer_id,
            replacement_writer_id,
            purpose = purpose.as_str(),
            "ME writer replacement committed"
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    mod convergence;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr};

    use crate::transport::middle_proxy::pool_writer_security_tests::make_pool;

    use super::*;

    fn endpoint(octet: u8) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, octet)), 443)
    }

    async fn install_writer(
        pool: &Arc<MePool>,
        writer_id: u64,
        writer_dc: i32,
        addr: SocketAddr,
    ) -> MeWriter {
        let (tx, _rx) = mpsc::channel::<WriterCommand>(8);
        let byte_budget = pool.new_writer_byte_budget();
        let writer = MeWriter {
            id: writer_id,
            addr,
            source_ip: addr.ip(),
            writer_dc,
            generation: pool.current_generation(),
            contour: Arc::new(AtomicU8::new(WriterContour::Active.as_u8())),
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
        let mut writers = pool.writers.write().await;
        let mut registry_registration = pool.registry.prepare_writer_registration().await;
        registry_registration.install(writer_id, tx, byte_budget);
        writers.push(writer.clone());
        pool.conn_count.fetch_add(1, Ordering::Relaxed);
        drop(registry_registration);
        drop(writers);
        writer
    }

    async fn prepared_writer<'a>(
        pool: &'a Arc<MePool>,
        writer_id: u64,
        writer_dc: i32,
        addr: SocketAddr,
    ) -> PreparedWriter<'a> {
        let open_reservation = pool
            .reserve_writer_open(
                WriterContour::Active,
                WriterOpenIntent::Replacement,
                writer_dc,
                addr,
            )
            .await
            .expect("replacement open must be admitted");
        let task_registration = pool
            .lifecycle
            .try_register()
            .expect("test pool lifecycle must be open");
        let (tx, rx) = mpsc::channel::<WriterCommand>(8);
        let byte_budget = pool.new_writer_byte_budget();
        PreparedWriter {
            writer: MeWriter {
                id: writer_id,
                addr,
                source_ip: addr.ip(),
                writer_dc,
                generation: pool.current_generation(),
                contour: Arc::new(AtomicU8::new(WriterContour::Active.as_u8())),
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
            },
            tx,
            byte_budget,
            task_registration,
            writer_task: WriterTransport::new(
                Box::pin(async move {
                    drop(rx);
                }),
                open_reservation,
            ),
            intent: WriterOpenIntent::Replacement,
        }
    }

    #[tokio::test]
    async fn suppressed_victim_backed_replacement_keeps_coverage() {
        let pool = make_pool().await;
        let addr = endpoint(8);
        pool.update_proxy_maps(HashMap::from([(2, vec![(addr.ip(), addr.port())])]), None)
            .await;
        let victim = install_writer(&pool, 8001, 2, addr).await;
        pool.set_family_runtime_state(
            crate::network::IpFamily::V4,
            crate::transport::middle_proxy::pool::MeFamilyRuntimeState::Suppressed,
            MePool::now_epoch_secs(),
            MePool::now_epoch_secs() + 3600,
            5,
            0,
        );
        let mut reservation = pool
            .registry
            .try_reserve_writer_replacement(victim.id)
            .await
            .unwrap();
        let prepared = prepared_writer(&pool, 8002, 2, addr).await;
        pool.publish_prepared_replacement_writer(
            prepared,
            WriterRole::from_writer(&victim),
            WriterReplacementPurpose::IdleRefresh,
            &mut reservation,
        )
        .await
        .expect("a reserved active victim must remain replaceable during suppression");
        assert!(victim.draining.load(Ordering::Acquire));
        assert_eq!(
            pool.writer_replacement_open_reserved
                .load(Ordering::Acquire),
            1,
            "overlap is owned until the victim transport is destroyed"
        );
    }

    #[tokio::test]
    async fn replacement_commit_publishes_successor_before_draining_victim() {
        let pool = make_pool().await;
        let addr = endpoint(1);
        pool.update_proxy_maps(HashMap::from([(2, vec![(addr.ip(), addr.port())])]), None)
            .await;
        let victim = install_writer(&pool, 1001, 2, addr).await;
        let expected_role = WriterRole::from_writer(&victim);
        let mut reservation = pool
            .registry
            .try_reserve_writer_replacement(victim.id)
            .await
            .expect("idle victim must be reservable");
        let prepared = prepared_writer(&pool, 1002, 2, addr).await;

        pool.publish_prepared_replacement_writer(
            prepared,
            expected_role,
            WriterReplacementPurpose::IdleRefresh,
            &mut reservation,
        )
        .await
        .expect("replacement commit must succeed");

        let writers = pool.writers.read().await;
        assert_eq!(writers.len(), 2);
        assert_eq!(
            writers
                .iter()
                .filter(|writer| !writer.draining.load(Ordering::Acquire))
                .count(),
            1
        );
        assert!(victim.draining.load(Ordering::Acquire));
        assert!(writers.iter().any(|writer| writer.id == 1002));
        drop(writers);
        assert_eq!(pool.conn_count.load(Ordering::Acquire), 2);
        assert_eq!(pool.registry.writer_replacement_counts(), (0, 1));
    }

    #[tokio::test]
    async fn cancelled_replacement_waiting_for_publication_restores_all_reservations() {
        let pool = make_pool().await;
        let addr = endpoint(2);
        pool.update_proxy_maps(HashMap::from([(2, vec![(addr.ip(), addr.port())])]), None)
            .await;
        let victim = install_writer(&pool, 2001, 2, addr).await;
        let expected_role = WriterRole::from_writer(&victim);
        let mut reservation = pool
            .registry
            .try_reserve_writer_replacement(victim.id)
            .await
            .expect("idle victim must be reservable");
        let prepared = prepared_writer(&pool, 2002, 2, addr).await;
        let writers_guard = pool.writers.write().await;

        let result = tokio::time::timeout(
            Duration::from_millis(10),
            pool.publish_prepared_replacement_writer(
                prepared,
                expected_role,
                WriterReplacementPurpose::IdleRefresh,
                &mut reservation,
            ),
        )
        .await;

        assert!(result.is_err());
        drop(writers_guard);
        drop(reservation);
        assert_eq!(
            pool.writer_replacement_open_reserved
                .load(Ordering::Acquire),
            0
        );
        assert_eq!(pool.registry.writer_replacement_counts(), (0, 0));
        assert!(!victim.draining.load(Ordering::Acquire));
        assert!(
            !pool
                .writers
                .read()
                .await
                .iter()
                .any(|writer| writer.id == 2002)
        );
    }

    #[tokio::test]
    async fn floor_rebalance_commit_rejects_a_donor_without_surplus() {
        let pool = make_pool().await;
        let donor_addr = endpoint(3);
        let receiver_addr = endpoint(4);
        pool.update_proxy_maps(
            HashMap::from([
                (1, vec![(donor_addr.ip(), donor_addr.port())]),
                (2, vec![(receiver_addr.ip(), receiver_addr.port())]),
            ]),
            None,
        )
        .await;
        let victim = install_writer(&pool, 3001, 1, donor_addr).await;
        let expected_role = WriterRole::from_writer(&victim);
        let mut reservation = pool
            .registry
            .try_reserve_writer_replacement(victim.id)
            .await
            .expect("idle victim must be reservable");
        let prepared = prepared_writer(&pool, 3002, 2, receiver_addr).await;

        let result = pool
            .publish_prepared_replacement_writer(
                prepared,
                expected_role,
                WriterReplacementPurpose::FloorRebalance {
                    donor_floor: 1,
                    receiver_floor: 1,
                },
                &mut reservation,
            )
            .await;

        assert!(result.is_err());
        drop(reservation);
        assert!(!victim.draining.load(Ordering::Acquire));
        assert!(
            !pool
                .writers
                .read()
                .await
                .iter()
                .any(|writer| writer.id == 3002)
        );
        assert_eq!(pool.registry.writer_replacement_counts(), (0, 0));
    }
}
