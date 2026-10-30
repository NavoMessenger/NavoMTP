use super::super::*;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn test_ipv4(oct1: u8, oct2: u8, oct3: u8, oct4: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(oct1, oct2, oct3, oct4))
}

#[tokio::test]
async fn cancelled_cleanup_drain_restores_detached_batch() {
    let tracker = Arc::new(UserIpTracker::new());
    let user = "cancelled-cleanup-user";
    let ip = test_ipv4(10, 2, 1, 1);
    tracker.check_and_add(user, ip).await.unwrap();
    tracker.enqueue_cleanup(user.to_string(), ip);

    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let held_tracker = Arc::clone(&tracker);
    let held_user = user.to_string();
    let holder = tokio::spawn(async move {
        held_tracker
            .hold_user_shard_for_tests(&held_user, entered_tx, release_rx)
            .await;
    });
    entered_rx.await.unwrap();

    let shard_idx = UserIpTracker::shard_idx(user);
    let drain_tracker = Arc::clone(&tracker);
    let drain = tokio::spawn(async move {
        drain_tracker.drain_cleanup_shard(shard_idx).await;
    });
    tokio::time::timeout(Duration::from_secs(1), async {
        while tracker.cleanup_queue_physical_entries_for_tests() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cleanup batch must detach before waiting for the IP shard");

    drain.abort();
    assert!(drain.await.unwrap_err().is_cancelled());
    assert_eq!(tracker.cleanup_queue_len_for_tests(), 1);
    assert_eq!(tracker.cleanup_queue_physical_entries_for_tests(), 1);

    let _ = release_tx.send(());
    holder.await.unwrap();
    tracker.drain_cleanup_queue().await;
    assert_eq!(tracker.cleanup_queue_len_for_tests(), 0);
    assert_eq!(tracker.get_active_ip_count(user).await, 0);
}

#[test]
fn clear_all_serializes_queue_reset_with_concurrent_enqueue() {
    let tracker = Arc::new(UserIpTracker::new());
    let first_shard_user = (0u64..)
        .map(|index| format!("clear-race-{index}"))
        .find(|user| UserIpTracker::shard_idx(user) == 0)
        .unwrap();
    let last_shard = USER_IP_TRACKER_SHARDS - 1;
    let last_queue_guard = tracker.cleanup_shards[last_shard].queue.lock().unwrap();

    let clear_tracker = Arc::clone(&tracker);
    let clear = std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(clear_tracker.clear_all());
    });

    let wait_deadline = Instant::now() + Duration::from_secs(1);
    loop {
        match tracker.cleanup_shards[0].queue.try_lock() {
            Ok(queue) => drop(queue),
            Err(std::sync::TryLockError::WouldBlock) => break,
            Err(std::sync::TryLockError::Poisoned(_)) => panic!("cleanup queue lock poisoned"),
        }
        assert!(
            Instant::now() < wait_deadline,
            "clear_all did not reach queue reset"
        );
        std::thread::yield_now();
    }

    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (completed_tx, completed_rx) = std::sync::mpsc::channel();
    let enqueue_tracker = Arc::clone(&tracker);
    let enqueue = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        enqueue_tracker.enqueue_cleanup(first_shard_user, test_ipv4(10, 2, 2, 1));
        completed_tx.send(()).unwrap();
    });
    started_rx.recv().unwrap();
    assert!(
        completed_rx
            .recv_timeout(Duration::from_millis(50))
            .is_err()
    );

    drop(last_queue_guard);
    clear.join().unwrap();
    completed_rx.recv_timeout(Duration::from_secs(1)).unwrap();
    enqueue.join().unwrap();

    assert_eq!(tracker.cleanup_queue_len_for_tests(), 1);
    assert_eq!(tracker.cleanup_queue_physical_entries_for_tests(), 1);
}
