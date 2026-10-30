use super::*;

#[test]
fn committed_and_pending_entries_share_one_shard_capacity() {
    let capacity = NonZeroUsize::new(2).unwrap();
    let mut shard = ReplayShard::new(capacity);
    let now = Instant::now();
    let window = Duration::from_secs(60);
    assert_eq!(
        shard.claim_owned(ReplayKey::from_slice(b"pending-a"), now, window, 1),
        ReplayClaimResult::Claimed
    );
    assert_eq!(
        shard.claim_owned(ReplayKey::from_slice(b"pending-b"), now, window, 2),
        ReplayClaimResult::Claimed
    );

    assert!(!shard.add_owned(ReplayKey::from_slice(b"committed"), now, window));

    assert_eq!(shard.len(), capacity.get());
    assert!(shard.pending.contains_key(b"pending-a".as_slice()));
    assert!(shard.pending.contains_key(b"pending-b".as_slice()));
}

#[test]
fn pending_capacity_rejection_is_not_reported_as_a_replay_hit() {
    let checker = ReplayChecker::new(64, Duration::from_secs(60));
    let first = checker
        .claim_tls_digest(b"same-shard-key")
        .expect("first claim must reserve the shard");
    let shard_idx = checker.get_shard_idx(b"same-shard-key");
    let rejected = (0..10_000u64)
        .map(u64::to_le_bytes)
        .find(|candidate| checker.get_shard_idx(candidate) == shard_idx)
        .expect("bounded search must find a second key in the selected shard");
    let before = checker.stats();

    assert!(checker.claim_tls_digest(&rejected).is_none());

    let after = checker.stats();
    assert_eq!(after.total_hits, before.total_hits);
    assert_eq!(
        after.total_capacity_rejections,
        before.total_capacity_rejections + 1
    );
    drop(first);
}
