use super::*;
use std::sync::{Arc, Barrier};
use std::time::Duration;

#[test]
fn replay_checker_keeps_tls_and_handshake_domains_isolated_for_same_key() {
    let checker = ReplayChecker::new(128, Duration::from_millis(20));
    let key = b"same-key-domain-separation";

    assert!(
        !checker.check_and_add_handshake(key),
        "first handshake use should be fresh"
    );
    assert!(
        !checker.check_and_add_tls_digest(key),
        "same bytes in TLS domain should still be fresh"
    );

    assert!(
        checker.check_and_add_handshake(key),
        "second handshake use should be replay-hit"
    );
    assert!(
        checker.check_and_add_tls_digest(key),
        "second TLS use should be replay-hit independently"
    );
}

#[test]
fn replay_checker_tls_window_is_clamped_beyond_small_handshake_window() {
    let checker = ReplayChecker::new(128, Duration::from_millis(20));
    let handshake_key = b"short-window-handshake";
    let tls_key = b"short-window-tls";

    assert!(!checker.check_and_add_handshake(handshake_key));
    assert!(!checker.check_and_add_tls_digest(tls_key));

    std::thread::sleep(Duration::from_millis(80));

    assert!(
        !checker.check_and_add_handshake(handshake_key),
        "handshake key should expire under short configured window"
    );
    assert!(
        checker.check_and_add_tls_digest(tls_key),
        "TLS key should still be replay-hit because TLS window is clamped to a secure minimum"
    );
}

#[test]
fn replay_checker_compat_add_paths_do_not_cross_pollute_domains() {
    let checker = ReplayChecker::new(128, Duration::from_secs(1));
    let key = b"compat-domain-separation";

    checker.add_handshake(key);
    assert!(
        checker.check_and_add_handshake(key),
        "handshake add helper must populate handshake domain"
    );
    assert!(
        !checker.check_and_add_tls_digest(key),
        "handshake add helper must not pollute TLS domain"
    );

    checker.add_tls_digest(key);
    assert!(
        checker.check_and_add_tls_digest(key),
        "TLS add helper must populate TLS domain"
    );
}

#[test]
fn replay_checker_stats_reflect_dual_shard_domains() {
    let checker = ReplayChecker::new(128, Duration::from_secs(1));
    let stats = checker.stats();

    assert_eq!(
        stats.num_shards, 128,
        "stats should expose both shard domains (handshake + TLS)"
    );
}

#[test]
fn concurrent_tls_claim_allows_exactly_one_pending_handshake() {
    const WORKERS: usize = 16;

    let checker = Arc::new(ReplayChecker::new(128, Duration::from_secs(1)));
    let start = Arc::new(Barrier::new(WORKERS));
    let finish = Arc::new(Barrier::new(WORKERS));
    let mut handles = Vec::with_capacity(WORKERS);

    for _ in 0..WORKERS {
        let checker = Arc::clone(&checker);
        let start = Arc::clone(&start);
        let finish = Arc::clone(&finish);
        handles.push(std::thread::spawn(move || {
            start.wait();
            let claim = checker.claim_tls_digest(b"parallel-client-hello");
            finish.wait();
            claim.map(|claim| claim.commit()).unwrap_or(false)
        }));
    }

    let accepted = handles
        .into_iter()
        .map(|handle| handle.join().expect("TLS claim worker must not panic"))
        .filter(|accepted| *accepted)
        .count();
    assert_eq!(accepted, 1, "only one concurrent TLS claim may commit");
}
