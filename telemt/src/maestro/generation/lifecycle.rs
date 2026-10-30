use super::*;

/// Cancels tasks if runtime preparation exits before ownership reaches a generation.
#[must_use = "runtime preparation guards must be disarmed after ownership transfer"]
pub(crate) struct RuntimeTaskScopePreparationGuard {
    scope: RuntimeTaskScope,
    armed: bool,
}

impl RuntimeTaskScopePreparationGuard {
    /// Arms cancellation for a newly created, not-yet-published task scope.
    pub(crate) fn new(scope: RuntimeTaskScope) -> Self {
        Self { scope, armed: true }
    }

    /// Confirms that a runtime generation now owns the task scope.
    pub(crate) fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for RuntimeTaskScopePreparationGuard {
    fn drop(&mut self) {
        if self.armed {
            self.scope.begin_stop();
        }
    }
}

pub(super) struct SessionDrainCancellationGuard<'a> {
    generation: &'a RuntimeGeneration,
    armed: bool,
}

impl<'a> SessionDrainCancellationGuard<'a> {
    pub(super) fn new(generation: &'a RuntimeGeneration) -> Self {
        Self {
            generation,
            armed: true,
        }
    }

    pub(super) fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for SessionDrainCancellationGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.generation.begin_stop_sessions();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NotifyOnDrop(Arc<Notify>);

    impl Drop for NotifyOnDrop {
        fn drop(&mut self) {
            self.0.notify_one();
        }
    }

    #[tokio::test]
    async fn preparation_guard_drop_cancels_scope_and_rejects_late_spawn() {
        let scope = RuntimeTaskScope::new();
        let guard = RuntimeTaskScopePreparationGuard::new(scope.clone());
        drop(guard);

        assert!(scope.cancellation_token().is_cancelled());
        let ran = Arc::new(AtomicUsize::new(0));
        let ran_task = Arc::clone(&ran);
        scope.spawn(async move {
            ran_task.fetch_add(1, Ordering::AcqRel);
        });
        tokio::task::yield_now().await;
        assert_eq!(ran.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn preparation_guard_disarm_transfers_ownership() {
        let scope = RuntimeTaskScope::new();
        RuntimeTaskScopePreparationGuard::new(scope.clone()).disarm();

        assert!(!scope.cancellation_token().is_cancelled());
        scope.stop().await;
    }

    #[tokio::test]
    async fn aborted_scope_stop_still_cancels_children() {
        let scope = RuntimeTaskScope::new();
        let registration = scope.admission.try_register().unwrap();
        let started = Arc::new(Notify::new());
        let dropped = Arc::new(Notify::new());
        let started_task = Arc::clone(&started);
        let dropped_task = Arc::clone(&dropped);
        scope.spawn(async move {
            let _drop_signal = NotifyOnDrop(dropped_task);
            started_task.notify_one();
            std::future::pending::<()>().await;
        });
        started.notified().await;

        let stop_scope = scope.clone();
        let stop = tokio::spawn(async move {
            stop_scope.stop().await;
        });
        scope.cancellation_token().cancelled().await;
        stop.abort();
        assert!(stop.await.unwrap_err().is_cancelled());
        drop(registration);

        tokio::time::timeout(Duration::from_secs(1), dropped.notified())
            .await
            .expect("scope cancellation must drop the tracked child");
        assert!(scope.admission.try_register().is_none());
    }

    #[tokio::test]
    async fn aborted_graceful_drain_forces_session_cancellation() {
        let generation = test_runtime_generation(1, ProxyConfig::default());
        let registration = generation.session_admission.try_register().unwrap();
        let started = Arc::new(Notify::new());
        let dropped = Arc::new(Notify::new());
        let started_task = Arc::clone(&started);
        let dropped_task = Arc::clone(&dropped);
        assert!(generation.spawn_session(async move {
            let _drop_signal = NotifyOnDrop(dropped_task);
            started_task.notify_one();
            std::future::pending::<()>().await;
        }));
        started.notified().await;

        let drain_generation = Arc::clone(&generation);
        let drain = tokio::spawn(async move {
            drain_generation
                .drain_sessions(Duration::from_secs(60))
                .await
        });
        while generation.session_admission.state.load(Ordering::Acquire) & SESSION_ADMISSION_CLOSED
            == 0
        {
            tokio::task::yield_now().await;
        }
        drain.abort();
        assert!(drain.await.unwrap_err().is_cancelled());
        assert!(generation.session_cancel.is_cancelled());
        drop(registration);

        tokio::time::timeout(Duration::from_secs(1), dropped.notified())
            .await
            .expect("aborted graceful drain must cancel existing sessions");
    }
}
