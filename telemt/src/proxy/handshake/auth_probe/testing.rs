use super::*;

/// Records one deterministic authentication failure against an isolated shared state.
pub(crate) fn auth_probe_record_failure_for_testing(
    shared: &ProxySharedState,
    peer_ip: IpAddr,
    now: Instant,
) {
    auth_probe_record_failure_in(shared, peer_ip, now);
}

/// Returns the normalized peer failure streak from an isolated shared state.
pub(crate) fn auth_probe_fail_streak_for_testing_in_shared(
    shared: &ProxySharedState,
    peer_ip: IpAddr,
) -> Option<u32> {
    let peer_ip = normalize_auth_probe_ip(peer_ip);
    shared
        .handshake
        .auth_probe
        .get(&peer_ip)
        .map(|entry| entry.fail_streak)
}

/// Clears probe entries, exact capacity accounting, and saturation state together.
pub(crate) fn clear_auth_probe_state_for_testing_in_shared(shared: &ProxySharedState) {
    let removed = shared.handshake.auth_probe.len();
    assert_eq!(shared.handshake.auth_probe_slots.used(), removed);
    shared.handshake.auth_probe.clear();
    shared.handshake.auth_probe_slots.release_many(removed);
    match shared.handshake.auth_probe_saturation.lock() {
        Ok(mut saturation) => {
            *saturation = None;
        }
        Err(poisoned) => {
            let mut saturation = poisoned.into_inner();
            *saturation = None;
            shared.handshake.auth_probe_saturation.clear_poison();
        }
    }
}

/// Inserts one fixture entry while preserving exact registry capacity accounting.
pub(crate) fn insert_auth_probe_state_for_testing_in_shared(
    shared: &ProxySharedState,
    peer_ip: IpAddr,
    state: AuthProbeState,
) {
    let peer_ip = normalize_auth_probe_ip(peer_ip);
    let slot = shared
        .handshake
        .auth_probe_slots
        .try_acquire()
        .expect("test auth-probe registry capacity must be available");
    match shared.handshake.auth_probe.entry(peer_ip) {
        Entry::Occupied(mut entry) => {
            entry.insert(state);
        }
        Entry::Vacant(entry) => {
            entry.insert(state);
            slot.commit();
        }
    }
}

/// Exposes the isolated probe registry to adversarial tests.
pub(crate) fn auth_probe_state_for_testing_in_shared(
    shared: &ProxySharedState,
) -> &DashMap<IpAddr, AuthProbeState> {
    &shared.handshake.auth_probe
}

/// Returns exact committed probe slots for capacity assertions.
pub(crate) fn auth_probe_slots_for_testing_in_shared(shared: &ProxySharedState) -> usize {
    shared.handshake.auth_probe_slots.used()
}

/// Exposes the isolated saturation state mutex to tests.
pub(crate) fn auth_probe_saturation_state_for_testing_in_shared(
    shared: &ProxySharedState,
) -> &Mutex<Option<AuthProbeSaturationState>> {
    &shared.handshake.auth_probe_saturation
}

/// Locks isolated saturation state while recovering poisoned test fixtures.
pub(crate) fn auth_probe_saturation_state_lock_for_testing_in_shared(
    shared: &ProxySharedState,
) -> std::sync::MutexGuard<'_, Option<AuthProbeSaturationState>> {
    shared
        .handshake
        .auth_probe_saturation
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Resets the isolated unknown-SNI warning rate limiter.
pub(crate) fn clear_unknown_sni_warn_state_for_testing_in_shared(shared: &ProxySharedState) {
    let mut guard = shared
        .handshake
        .unknown_sni_warn_next_allowed
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    *guard = None;
}

/// Evaluates unknown-SNI warning admission at a deterministic instant.
pub(crate) fn should_emit_unknown_sni_warn_for_testing_in_shared(
    shared: &ProxySharedState,
    now: Instant,
) -> bool {
    should_emit_unknown_sni_warn_in(shared, now)
}

/// Clears the isolated invalid-secret warning deduplication set.
pub(crate) fn clear_warned_secrets_for_testing_in_shared(shared: &ProxySharedState) {
    if let Ok(mut guard) = shared.handshake.invalid_secret_warned.lock() {
        guard.clear();
    }
}

/// Exposes the isolated invalid-secret warning set to tests.
pub(crate) fn warned_secrets_for_testing_in_shared(
    shared: &ProxySharedState,
) -> &Mutex<HashSet<(String, String)>> {
    &shared.handshake.invalid_secret_warned
}

/// Evaluates peer throttling against the current test clock.
pub(crate) fn auth_probe_is_throttled_for_testing_in_shared(
    shared: &ProxySharedState,
    peer_ip: IpAddr,
) -> bool {
    auth_probe_is_throttled_in(shared, peer_ip, Instant::now())
}

/// Evaluates global saturation throttling against the current test clock.
pub(crate) fn auth_probe_saturation_is_throttled_for_testing_in_shared(
    shared: &ProxySharedState,
) -> bool {
    auth_probe_saturation_is_throttled_in(shared, Instant::now())
}

/// Evaluates global saturation throttling at a deterministic instant.
pub(crate) fn auth_probe_saturation_is_throttled_at_for_testing_in_shared(
    shared: &ProxySharedState,
    now: Instant,
) -> bool {
    auth_probe_saturation_is_throttled_in(shared, now)
}

#[test]
fn parallel_distinct_failures_respect_exact_auth_probe_capacity() {
    const ATTEMPTS: usize = 10_000;

    let shared = ProxySharedState::new();
    std::thread::scope(|scope| {
        for worker in 0..16 {
            let shared = Arc::clone(&shared);
            scope.spawn(move || {
                for index in (worker..ATTEMPTS).step_by(16) {
                    let octets = (index as u32).to_be_bytes();
                    let peer_ip = IpAddr::V4(std::net::Ipv4Addr::new(
                        octets[1],
                        octets[2],
                        octets[3],
                        worker as u8,
                    ));
                    auth_probe_record_failure_in(shared.as_ref(), peer_ip, Instant::now());
                }
            });
        }
    });

    assert_eq!(
        shared.handshake.auth_probe.len(),
        AUTH_PROBE_TRACK_MAX_ENTRIES
    );
    assert_eq!(
        auth_probe_slots_for_testing_in_shared(shared.as_ref()),
        AUTH_PROBE_TRACK_MAX_ENTRIES
    );
}
