use super::*;
use std::time::{Duration, Instant};

fn poison_saturation_mutex(shared: &ProxySharedState) {
    let saturation = auth_probe_saturation_state_for_testing_in_shared(shared);
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = saturation
            .lock()
            .expect("saturation mutex must be lockable for poison setup");
        panic!("intentional poison for saturation mutex resilience test");
    }));
}

#[test]
fn auth_probe_saturation_note_recovers_after_mutex_poison() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());
    poison_saturation_mutex(shared.as_ref());

    let now = Instant::now();
    auth_probe_note_saturation_in(shared.as_ref(), now);

    assert!(
        auth_probe_saturation_is_throttled_at_for_testing_in_shared(shared.as_ref(), now),
        "poisoned saturation mutex must not disable saturation throttling"
    );
}

#[test]
fn auth_probe_saturation_check_recovers_after_mutex_poison() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());
    poison_saturation_mutex(shared.as_ref());

    {
        let mut guard = auth_probe_saturation_state_lock_for_testing_in_shared(shared.as_ref());
        *guard = Some(AuthProbeSaturationState {
            fail_streak: AUTH_PROBE_BACKOFF_START_FAILS,
            blocked_until: Instant::now() + Duration::from_millis(10),
            last_seen: Instant::now(),
        });
    }

    assert!(
        auth_probe_saturation_is_throttled_for_testing_in_shared(shared.as_ref()),
        "throttle check must recover poisoned saturation mutex and stay fail-closed"
    );
}

#[test]
fn clear_auth_probe_state_clears_saturation_even_if_poisoned() {
    let shared = ProxySharedState::new();
    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());
    poison_saturation_mutex(shared.as_ref());

    auth_probe_note_saturation_in(shared.as_ref(), Instant::now());
    assert!(auth_probe_saturation_is_throttled_for_testing_in_shared(
        shared.as_ref()
    ));

    clear_auth_probe_state_for_testing_in_shared(shared.as_ref());
    assert!(
        !auth_probe_saturation_is_throttled_for_testing_in_shared(shared.as_ref()),
        "clear helper must clear saturation state even after poison"
    );
}
