use std::sync::Arc;
use std::task::Waker;

use tokio::sync::{Notify, OwnedSemaphorePermit};

use super::{DownBatch, SessionState, StreamState, WebSession};

enum DeferredSessionEffect {
    Wake(Waker),
    DropWaker(Waker),
    Notify(Arc<Notify>),
}

enum RetainedSessionResource {
    Batch(DownBatch),
    StagingPermit(OwnedSemaphorePermit),
    Stream(StreamState),
}

struct DeferredItems<T> {
    first: Option<T>,
    second: Option<T>,
    spill: Vec<T>,
}

impl<T> DeferredItems<T> {
    fn new() -> Self {
        Self {
            first: None,
            second: None,
            spill: Vec::new(),
        }
    }

    fn push(&mut self, value: T) {
        if self.first.is_none() {
            self.first = Some(value);
        } else if self.second.is_none() {
            self.second = Some(value);
        } else {
            self.spill.push(value);
        }
    }

    fn into_iter(self) -> impl Iterator<Item = T> {
        [self.first, self.second]
            .into_iter()
            .flatten()
            .chain(self.spill)
    }

    #[cfg(test)]
    fn spilled(&self) -> bool {
        !self.spill.is_empty()
    }
}

/// Wake-capable work detached from one session-state transaction.
#[must_use = "deferred session effects must be finished after releasing SessionState"]
pub(super) struct DeferredSessionEffects {
    retained: DeferredItems<RetainedSessionResource>,
    callbacks: DeferredItems<DeferredSessionEffect>,
}

impl DeferredSessionEffects {
    /// Creates an empty callback and retained-resource accumulator.
    pub(super) fn new() -> Self {
        Self {
            retained: DeferredItems::new(),
            callbacks: DeferredItems::new(),
        }
    }

    /// Defers one consuming wake until the session-state guard is gone.
    pub(super) fn wake(&mut self, waker: Waker) {
        self.callbacks.push(DeferredSessionEffect::Wake(waker));
    }

    /// Defers one RawWaker drop without delivering a readiness signal.
    pub(super) fn drop_waker(&mut self, waker: Waker) {
        self.callbacks.push(DeferredSessionEffect::DropWaker(waker));
    }

    /// Defers one exact notification without coalescing sibling effects.
    pub(super) fn notify(&mut self, notify: Arc<Notify>) {
        self.callbacks.push(DeferredSessionEffect::Notify(notify));
    }

    /// Retains a detached response batch until its lease can drop safely.
    pub(super) fn retain_batch(&mut self, batch: DownBatch) {
        self.retained.push(RetainedSessionResource::Batch(batch));
    }

    /// Retains transient semaphore capacity until state publication completes.
    pub(super) fn retain_staging_permit(&mut self, permit: OwnedSemaphorePermit) {
        self.retained
            .push(RetainedSessionResource::StagingPermit(permit));
    }

    /// Retains replaced stream-owned wakers for a post-unlock drop.
    pub(super) fn retain_stream(&mut self, stream: StreamState) {
        self.retained.push(RetainedSessionResource::Stream(stream));
    }

    /// Drops retained ownership first, then dispatches callbacks in FIFO order.
    pub(super) fn finish(self) {
        for retained in self.retained.into_iter() {
            match retained {
                RetainedSessionResource::Batch(batch) => drop(batch),
                RetainedSessionResource::StagingPermit(permit) => drop(permit),
                RetainedSessionResource::Stream(stream) => drop(stream),
            }
        }
        for callback in self.callbacks.into_iter() {
            match callback {
                DeferredSessionEffect::Wake(waker) => waker.wake(),
                DeferredSessionEffect::DropWaker(waker) => drop(waker),
                DeferredSessionEffect::Notify(notify) => notify.notify_waiters(),
            }
        }
    }

    #[cfg(test)]
    /// Reports whether callback storage crossed the allocation-free inline bound.
    pub(super) fn callbacks_spilled(&self) -> bool {
        self.callbacks.spilled()
    }
}

impl WebSession {
    /// Executes one session-state transaction and dispatches callbacks after unlock.
    pub(super) fn with_state_effects<R>(
        &self,
        apply: impl FnOnce(&mut SessionState, &mut DeferredSessionEffects) -> R,
    ) -> R {
        let mut effects = DeferredSessionEffects::new();
        let result = {
            let mut state = self.state.lock();
            apply(&mut state, &mut effects)
        };
        effects.finish();
        result
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Wake, Waker};

    use tokio::sync::Semaphore;

    use super::*;

    struct OrderedWake {
        id: usize,
        next: Arc<AtomicUsize>,
    }

    impl Wake for OrderedWake {
        fn wake(self: Arc<Self>) {
            assert_eq!(self.next.fetch_add(1, Ordering::AcqRel), self.id);
        }
    }

    struct PermitOrderWake {
        semaphore: Arc<Semaphore>,
        observed_release: Arc<AtomicUsize>,
    }

    impl Wake for PermitOrderWake {
        fn wake(self: Arc<Self>) {
            self.observed_release
                .store(self.semaphore.available_permits(), Ordering::Release);
        }
    }

    #[test]
    fn two_callbacks_stay_inline_and_the_third_spills_in_fifo_order() {
        let next = Arc::new(AtomicUsize::new(0));
        let mut effects = DeferredSessionEffects::new();
        for id in 0..2 {
            effects.wake(Waker::from(Arc::new(OrderedWake {
                id,
                next: Arc::clone(&next),
            })));
        }
        assert!(!effects.callbacks_spilled());
        effects.wake(Waker::from(Arc::new(OrderedWake {
            id: 2,
            next: Arc::clone(&next),
        })));
        assert!(effects.callbacks_spilled());

        effects.finish();

        assert_eq!(next.load(Ordering::Acquire), 3);
    }

    #[test]
    fn retained_resources_drop_before_callbacks_run() {
        let semaphore = Arc::new(Semaphore::new(1));
        let permit = Arc::clone(&semaphore).try_acquire_owned().unwrap();
        let observed_release = Arc::new(AtomicUsize::new(0));
        let mut effects = DeferredSessionEffects::new();
        effects.retain_staging_permit(permit);
        effects.wake(Waker::from(Arc::new(PermitOrderWake {
            semaphore,
            observed_release: Arc::clone(&observed_release),
        })));

        effects.finish();

        assert_eq!(observed_release.load(Ordering::Acquire), 1);
    }
}
