use super::*;

const WRITER_REPLACEMENT_OPEN_LIMIT_MAX: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
/// Immutable identity of a writer lifecycle role at replacement reservation time.
pub(in crate::transport::middle_proxy) struct WriterRole {
    /// Telegram DC owning the writer.
    pub(in crate::transport::middle_proxy) dc: i32,
    /// Address family of the writer endpoint.
    pub(in crate::transport::middle_proxy) family: IpFamily,
    /// Pool generation owning the writer.
    pub(in crate::transport::middle_proxy) generation: u64,
    /// Lifecycle contour assigned to the writer.
    pub(in crate::transport::middle_proxy) contour: WriterContour,
}

impl WriterRole {
    /// Captures the current role of an installed writer.
    pub(in crate::transport::middle_proxy) fn from_writer(writer: &MeWriter) -> Self {
        Self {
            dc: writer.writer_dc,
            family: if writer.addr.is_ipv4() {
                IpFamily::V4
            } else {
                IpFamily::V6
            },
            generation: writer.generation,
            contour: WriterContour::from_u8(writer.contour.load(Ordering::Acquire)),
        }
    }

    /// Revalidates that an installed writer still has this exact role.
    pub(in crate::transport::middle_proxy) fn matches(self, writer: &MeWriter) -> bool {
        self == Self::from_writer(writer)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Capacity policy applied while opening a writer.
pub(in crate::transport::middle_proxy) enum WriterOpenIntent {
    /// Ordinary pool growth constrained by the configured contour cap.
    Normal,
    /// Required active coverage allowed to exceed an undersized configured cap temporarily.
    Coverage,
    /// Replacement-before-drain capacity owned by an existing victim reservation.
    Replacement,
}

/// RAII ownership of one bounded in-flight writer open.
pub(in crate::transport::middle_proxy) struct WriterOpenReservation {
    counter: Option<Arc<AtomicUsize>>,
}

impl Drop for WriterOpenReservation {
    fn drop(&mut self) {
        if let Some(counter) = &self.counter {
            counter.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

impl MePool {
    /// Computes reservation coverage across configured families, including suppressed ones.
    pub(in crate::transport::middle_proxy) async fn active_coverage_required_total(&self) -> usize {
        let mut required_total = 0usize;
        let endpoint_snapshot = self.endpoint_snapshot.load_full();

        // Suppression must not remove the capacity needed to recover active coverage.
        if self.decision.ipv4_me {
            for addrs in endpoint_snapshot.map_v4.values() {
                let mut endpoints = HashSet::<SocketAddr>::new();
                for (ip, port) in addrs.iter().copied() {
                    endpoints.insert(SocketAddr::new(ip, port));
                }
                required_total = required_total.saturating_add(
                    self.required_writers_for_dc_with_floor_mode(endpoints.len(), false),
                );
            }
        }

        if self.decision.ipv6_me {
            for addrs in endpoint_snapshot.map_v6.values() {
                let mut endpoints = HashSet::<SocketAddr>::new();
                for (ip, port) in addrs.iter().copied() {
                    endpoints.insert(SocketAddr::new(ip, port));
                }
                required_total = required_total.saturating_add(
                    self.required_writers_for_dc_with_floor_mode(endpoints.len(), false),
                );
            }
        }

        required_total
    }

    /// Reports whether one writer may be opened under the selected contour policy.
    pub(in crate::transport::middle_proxy) async fn can_open_writer_for_contour(
        &self,
        contour: WriterContour,
        intent: WriterOpenIntent,
        writer_dc: i32,
        target_addr: SocketAddr,
    ) -> bool {
        if intent == WriterOpenIntent::Replacement {
            return true;
        }
        let family = if target_addr.is_ipv4() {
            IpFamily::V4
        } else {
            IpFamily::V6
        };
        let endpoint_snapshot = self.endpoint_snapshot.load_full();
        let endpoints = endpoint_snapshot.endpoints_for_dc_family(writer_dc, family);
        if !endpoint_snapshot.contains_dc_endpoint(writer_dc, target_addr) {
            return false;
        }
        let (active_writers, warm_writers, _) = self.non_draining_writer_counts_by_contour().await;
        let live = match contour {
            WriterContour::Active => active_writers,
            WriterContour::Warm => warm_writers,
            WriterContour::Draining => return true,
        };
        let configured_cap = match contour {
            WriterContour::Active => self.adaptive_floor_active_cap_configured_total(),
            WriterContour::Warm => self.adaptive_floor_warm_cap_configured_total(),
            WriterContour::Draining => usize::MAX,
        };
        if live < configured_cap {
            return true;
        }
        if intent != WriterOpenIntent::Coverage {
            return false;
        }

        let endpoint_count = endpoints.len();
        if endpoint_count == 0 {
            return false;
        }
        let required = self.required_writers_for_dc_with_floor_mode(endpoint_count, false);
        let status = self.reinit.status.load();
        let generation = match contour {
            WriterContour::Active => status.active_generation,
            WriterContour::Warm => status.pending_hardswap_generation,
            WriterContour::Draining => 0,
        };
        let family_count = {
            let writers = self.writers.read().await;
            writers
                .iter()
                .filter(|writer| {
                    !writer.draining.load(Ordering::Relaxed)
                        && writer.writer_dc == writer_dc
                        && writer.generation == generation
                        && WriterContour::from_u8(writer.contour.load(Ordering::Relaxed)) == contour
                        && writer.addr.is_ipv4() == (family == IpFamily::V4)
                        && endpoint_snapshot.contains_dc_endpoint(writer_dc, writer.addr)
                })
                .count()
        };
        if family_count < required {
            return true;
        }

        false
    }

    /// Reserves bounded transient capacity for a writer open attempt.
    pub(in crate::transport::middle_proxy) async fn reserve_writer_open(
        &self,
        contour: WriterContour,
        intent: WriterOpenIntent,
        writer_dc: i32,
        target_addr: SocketAddr,
    ) -> Option<WriterOpenReservation> {
        let counter = match contour {
            WriterContour::Active => &self.writer_connect_active_reserved,
            WriterContour::Warm => &self.writer_connect_warm_reserved,
            WriterContour::Draining => {
                return Some(WriterOpenReservation { counter: None });
            }
        };

        if intent == WriterOpenIntent::Replacement {
            // Policy reload and replacement admission share the same linearization point.
            let _coordinator = self.reinit.coordinator.lock();
            let configured_cap = match contour {
                WriterContour::Active => self.adaptive_floor_active_cap_configured_total(),
                WriterContour::Warm => self.adaptive_floor_warm_cap_configured_total(),
                WriterContour::Draining => usize::MAX,
            };
            let effective_cap = match contour {
                WriterContour::Active => self
                    .floor_runtime
                    .me_adaptive_floor_active_cap_effective
                    .load(Ordering::Acquire) as usize,
                WriterContour::Warm => self
                    .floor_runtime
                    .me_adaptive_floor_warm_cap_effective
                    .load(Ordering::Acquire) as usize,
                WriterContour::Draining => usize::MAX,
            };
            let replacement_limit = configured_cap
                .max(effective_cap)
                .max(1)
                .min(WRITER_REPLACEMENT_OPEN_LIMIT_MAX);
            loop {
                let reserved = self
                    .writer_replacement_open_reserved
                    .load(Ordering::Acquire);
                if reserved >= replacement_limit {
                    return None;
                }
                if self
                    .writer_replacement_open_reserved
                    .compare_exchange_weak(
                        reserved,
                        reserved + 1,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
                {
                    return Some(WriterOpenReservation {
                        counter: Some(self.writer_replacement_open_reserved.clone()),
                    });
                }
            }
        }

        loop {
            if !self
                .can_open_writer_for_contour(contour, intent, writer_dc, target_addr)
                .await
            {
                return None;
            }
            let (active_writers, warm_writers, _) =
                self.non_draining_writer_counts_by_contour().await;
            let live = match contour {
                WriterContour::Active => active_writers,
                WriterContour::Warm => warm_writers,
                WriterContour::Draining => 0,
            };
            let mut limit = match contour {
                WriterContour::Active => self.adaptive_floor_active_cap_configured_total(),
                WriterContour::Warm => self.adaptive_floor_warm_cap_configured_total(),
                WriterContour::Draining => usize::MAX,
            };
            if intent == WriterOpenIntent::Coverage
                && matches!(contour, WriterContour::Active | WriterContour::Warm)
            {
                limit = limit
                    .max(self.active_coverage_required_total().await)
                    .saturating_add(
                        self.reconnect_runtime
                            .me_reconnect_max_concurrent_per_dc
                            .max(1) as usize,
                    );
            }

            let reserved = counter.load(Ordering::Acquire);
            if live.saturating_add(reserved) >= limit {
                return None;
            }
            if counter
                .compare_exchange_weak(reserved, reserved + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(WriterOpenReservation {
                    counter: Some(counter.clone()),
                });
            }
        }
    }

    /// Resolves a DC writer floor for static or adaptive-idle operation.
    pub(in crate::transport::middle_proxy) fn required_writers_for_dc_with_floor_mode(
        &self,
        endpoint_count: usize,
        reduce_for_idle: bool,
    ) -> usize {
        let base_required = self.required_writers_for_dc(endpoint_count);
        if !reduce_for_idle {
            return base_required;
        }
        if self.floor_mode() != MeFloorMode::Adaptive {
            return base_required;
        }
        let min_writers = if endpoint_count == 1 {
            (self
                .floor_runtime
                .me_adaptive_floor_min_writers_single_endpoint
                .load(Ordering::Relaxed) as usize)
                .max(1)
        } else {
            (self
                .floor_runtime
                .me_adaptive_floor_min_writers_multi_endpoint
                .load(Ordering::Relaxed) as usize)
                .max(1)
        };
        base_required.min(min_writers)
    }
}
