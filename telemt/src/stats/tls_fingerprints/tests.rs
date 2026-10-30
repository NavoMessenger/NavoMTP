use super::*;

fn fp() -> TlsClientFingerprint {
    TlsClientFingerprint {
        ja3: "ja3".to_string(),
        ja3_raw: "771,4865,,,0".to_string(),
        ja4: "t13d010100_hash_hash".to_string(),
        ja4_raw: "raw".to_string(),
    }
}

#[test]
fn aggregates_ip_cidr_and_user_scopes() {
    let collector = TlsFingerprintCollector::default();
    let ip: IpAddr = "192.0.2.15".parse().expect("test IP parses");
    collector.record_observed(&fp(), ip, Duration::from_secs(60));
    collector.record_auth_success(&fp(), ip, "alice", Duration::from_secs(60));
    let snapshot = collector.snapshot(Duration::from_secs(60), 10);

    assert_eq!(snapshot.by_fingerprint[0].total, 1);
    assert_eq!(snapshot.by_fingerprint[0].auth_success, 1);
    assert_eq!(snapshot.by_ip[0].scope_key, "192.0.2.15");
    assert_eq!(snapshot.by_cidr[0].scope_key, "192.0.2.0/24");
    assert_eq!(snapshot.by_user[0].scope_key, "alice");
    assert_eq!(snapshot.by_user[0].total, 1);
}

#[test]
fn parallel_distinct_insertions_respect_exact_capacity() {
    const CAPACITY: usize = 127;
    const ATTEMPTS: usize = 10_000;

    let collector = std::sync::Arc::new(TlsFingerprintCollector::with_capacity(CAPACITY));
    std::thread::scope(|scope| {
        for worker in 0..16 {
            let collector = std::sync::Arc::clone(&collector);
            scope.spawn(move || {
                for index in (worker..ATTEMPTS).step_by(16) {
                    collector.record_scoped(
                        (TlsFingerprintScopeKind::Ip, format!("192.0.2.{index}")),
                        &fp(),
                        1,
                        true,
                        false,
                        false,
                    );
                }
            });
        }
    });

    assert_eq!(collector.entries.len(), CAPACITY);
    assert_eq!(collector.slots.used(), CAPACITY);
    assert_eq!(
        collector.dropped_total.load(Ordering::Relaxed),
        (ATTEMPTS - CAPACITY) as u64
    );
}
