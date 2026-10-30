use super::*;
use crate::transport::middle_proxy::pool_writer_security_tests::make_pool;
use std::sync::atomic::AtomicUsize;

struct DestructionProbe {
    counter: Arc<AtomicUsize>,
    destroyed: Arc<AtomicBool>,
}

impl Drop for DestructionProbe {
    fn drop(&mut self) {
        assert!(
            self.counter.load(Ordering::Acquire) > 0,
            "transport must be destroyed before its overlap token"
        );
        self.destroyed.store(true, Ordering::Release);
    }
}

async fn transport(pool: &Arc<MePool>, destroyed: Arc<AtomicBool>) -> WriterTransport {
    let permit = pool
        .reserve_writer_open(
            WriterContour::Active,
            WriterOpenIntent::Replacement,
            2,
            "127.0.0.1:443".parse().unwrap(),
        )
        .await
        .unwrap();
    let probe = DestructionProbe {
        counter: pool.writer_replacement_open_reserved.clone(),
        destroyed,
    };
    WriterTransport::new(
        Box::pin(async move {
            let _probe = probe;
            std::future::pending::<()>().await;
        }),
        permit,
    )
}

#[tokio::test]
async fn unpolled_transport_and_aborted_task_release_after_destruction() {
    let pool = make_pool().await;
    for abort in [false, true] {
        let destroyed = Arc::new(AtomicBool::new(false));
        let task = transport(&pool, destroyed.clone()).await;
        if abort {
            let task = tokio::spawn(task);
            task.abort();
            let _ = task.await;
        } else {
            drop(task);
        }
        assert!(destroyed.load(Ordering::Acquire));
        assert_eq!(
            pool.writer_replacement_open_reserved
                .load(Ordering::Acquire),
            0
        );
    }
}

#[tokio::test]
async fn retiring_transport_owns_capacity_after_logical_removal() {
    let pool = make_pool().await;
    let destroyed = Arc::new(AtomicBool::new(false));
    let mut victim = transport(&pool, destroyed.clone()).await;
    drop(victim.opening.take());
    let lifetime = victim.lifetime.clone();
    let mut successor = transport(&pool, Arc::new(AtomicBool::new(false))).await;
    successor.future = Some(Box::pin(std::future::pending()));
    assert!(lifetime.commit(&mut successor.opening, || true));
    assert!(successor.opening.is_none());
    // Registry removal only drops its handle; the real transport retains the token.
    drop(lifetime);
    assert_eq!(
        pool.writer_replacement_open_reserved
            .load(Ordering::Acquire),
        1
    );
    drop(victim);
    assert!(destroyed.load(Ordering::Acquire));
    assert_eq!(
        pool.writer_replacement_open_reserved
            .load(Ordering::Acquire),
        0
    );
    // Successor is no longer overlap after its victim has physically gone.
    drop(successor);
}

#[tokio::test]
async fn failed_or_closed_handoff_keeps_the_prepared_token() {
    let pool = make_pool().await;
    let mut prepared = transport(&pool, Arc::new(AtomicBool::new(false))).await;
    let lifetime = ReplacementHandoff::new();
    assert!(!lifetime.commit(&mut prepared.opening, || false));
    assert!(prepared.opening.is_some());
    lifetime.close();
    assert!(!lifetime.commit(&mut prepared.opening, || true));
    assert!(prepared.opening.is_some());
    drop(prepared);
    assert_eq!(
        pool.writer_replacement_open_reserved
            .load(Ordering::Acquire),
        0
    );
}

#[tokio::test]
async fn overlap_limit_survives_commit_and_cap_shrink_until_teardown() {
    let pool = make_pool().await;
    pool.floor_runtime
        .me_adaptive_floor_cpu_cores_override
        .store(1, Ordering::Relaxed);
    pool.floor_runtime
        .me_adaptive_floor_max_active_writers_per_core
        .store(1, Ordering::Relaxed);
    pool.floor_runtime
        .me_adaptive_floor_max_active_writers_global
        .store(1, Ordering::Relaxed);
    pool.set_adaptive_floor_runtime_caps(pool.floor_authority(), 1, 2, 1, 1, 1, 0, 0);
    let mut victim = transport(&pool, Arc::new(AtomicBool::new(false))).await;
    drop(victim.opening.take());
    let mut successor = transport(&pool, Arc::new(AtomicBool::new(false))).await;
    successor.future = Some(Box::pin(std::future::pending()));
    assert!(victim.lifetime.commit(&mut successor.opening, || true));
    let second = transport(&pool, Arc::new(AtomicBool::new(false))).await;
    pool.set_adaptive_floor_runtime_caps(pool.floor_authority(), 1, 1, 1, 1, 1, 1, 0);
    let addr = "127.0.0.1:443".parse().unwrap();
    assert!(
        pool.reserve_writer_open(
            WriterContour::Active,
            WriterOpenIntent::Replacement,
            2,
            addr
        )
        .await
        .is_none()
    );
    drop(second);
    assert!(
        pool.reserve_writer_open(
            WriterContour::Active,
            WriterOpenIntent::Replacement,
            2,
            addr
        )
        .await
        .is_none()
    );
    drop(victim);
    assert!(
        pool.reserve_writer_open(
            WriterContour::Active,
            WriterOpenIntent::Replacement,
            2,
            addr
        )
        .await
        .is_some()
    );
    drop(successor);
    assert_eq!(
        pool.writer_replacement_open_reserved
            .load(Ordering::Acquire),
        0
    );
}

#[tokio::test]
async fn panicking_transport_releases_capacity_after_unwinding_its_resources() {
    let pool = make_pool().await;
    let permit = pool
        .reserve_writer_open(
            WriterContour::Active,
            WriterOpenIntent::Replacement,
            2,
            "127.0.0.1:443".parse().unwrap(),
        )
        .await
        .unwrap();
    let destroyed = Arc::new(AtomicBool::new(false));
    let probe = DestructionProbe {
        counter: pool.writer_replacement_open_reserved.clone(),
        destroyed: destroyed.clone(),
    };
    let task = WriterTransport::new(
        Box::pin(async move {
            let _probe = probe;
            panic!("injected transport panic");
        }),
        permit,
    );
    assert!(tokio::spawn(task).await.unwrap_err().is_panic());
    assert!(destroyed.load(Ordering::Acquire));
    assert_eq!(
        pool.writer_replacement_open_reserved
            .load(Ordering::Acquire),
        0
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn racing_commit_and_close_release_each_token_exactly_once() {
    let pool = make_pool().await;
    for _ in 0..128 {
        let permit = pool
            .reserve_writer_open(
                WriterContour::Active,
                WriterOpenIntent::Replacement,
                2,
                "127.0.0.1:443".parse().unwrap(),
            )
            .await
            .unwrap();
        let lifetime = ReplacementHandoff::new();
        let closing = lifetime.clone();
        let close = tokio::spawn(async move {
            tokio::task::yield_now().await;
            closing.close();
        });
        let commit = tokio::spawn(async move {
            let mut permit = Some(permit);
            lifetime.commit(&mut permit, || true);
            drop(permit);
        });
        close.await.unwrap();
        commit.await.unwrap();
        assert_eq!(
            pool.writer_replacement_open_reserved
                .load(Ordering::Acquire),
            0
        );
    }
}
