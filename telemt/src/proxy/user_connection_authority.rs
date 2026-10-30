use std::sync::Arc;

use dashmap::DashMap;
use dashmap::mapref::entry::Entry;

/// Process-wide per-user connection admission shared by runtime generations.
#[derive(Default)]
pub(crate) struct UserConnectionAuthority {
    active: DashMap<String, u64>,
}

/// Owns one exact connection slot until the authenticated connection exits.
#[must_use = "connection permits must be retained for the connection lifetime"]
pub(crate) struct UserConnectionPermit {
    authority: Arc<UserConnectionAuthority>,
    user: String,
}

impl UserConnectionAuthority {
    /// Acquires a slot without consulting optional telemetry state.
    pub(crate) fn try_acquire(
        self: &Arc<Self>,
        user: &str,
        limit: Option<u64>,
    ) -> Option<UserConnectionPermit> {
        match self.active.entry(user.to_string()) {
            Entry::Occupied(mut entry) => {
                if limit.is_some_and(|max| *entry.get() >= max) {
                    return None;
                }
                let next = entry.get().checked_add(1)?;
                *entry.get_mut() = next;
            }
            Entry::Vacant(entry) => {
                if limit == Some(0) {
                    return None;
                }
                entry.insert(1);
            }
        }
        Some(UserConnectionPermit {
            authority: Arc::clone(self),
            user: user.to_string(),
        })
    }

    /// Returns the authoritative active connection count for one username.
    pub(crate) fn active(&self, user: &str) -> u64 {
        self.active.get(user).map(|entry| *entry).unwrap_or(0)
    }

    #[cfg(test)]
    fn tracked_users(&self) -> usize {
        self.active.len()
    }
}

impl Drop for UserConnectionPermit {
    fn drop(&mut self) {
        let Entry::Occupied(mut entry) = self.authority.active.entry(self.user.clone()) else {
            debug_assert!(false, "connection permit owner entry disappeared");
            return;
        };
        debug_assert!(*entry.get() > 0, "connection permit counter underflow");
        if *entry.get() <= 1 {
            entry.remove();
        } else {
            *entry.get_mut() -= 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Barrier;

    #[test]
    fn permit_drop_releases_and_removes_zero_entry() {
        let authority = Arc::new(UserConnectionAuthority::default());
        let permit = authority.try_acquire("alice", Some(1)).unwrap();
        assert_eq!(authority.active("alice"), 1);
        assert!(authority.try_acquire("alice", Some(1)).is_none());

        drop(permit);

        assert_eq!(authority.active("alice"), 0);
        assert_eq!(authority.tracked_users(), 0);
    }

    #[test]
    fn concurrent_acquire_never_exceeds_limit() {
        const CONTENDERS: usize = 64;
        const LIMIT: u64 = 7;

        let authority = Arc::new(UserConnectionAuthority::default());
        let barrier = Arc::new(Barrier::new(CONTENDERS + 1));
        let (permit_tx, permit_rx) = std::sync::mpsc::channel();
        let mut threads = Vec::with_capacity(CONTENDERS);
        for _ in 0..CONTENDERS {
            let authority = Arc::clone(&authority);
            let barrier = Arc::clone(&barrier);
            let permit_tx = permit_tx.clone();
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                permit_tx
                    .send(authority.try_acquire("alice", Some(LIMIT)))
                    .unwrap();
            }));
        }
        drop(permit_tx);
        barrier.wait();
        for thread in threads {
            thread.join().unwrap();
        }
        let permits = permit_rx.into_iter().flatten().collect::<Vec<_>>();

        assert_eq!(permits.len() as u64, LIMIT);
        assert_eq!(authority.active("alice"), LIMIT);
        drop(permits);
        assert_eq!(authority.active("alice"), 0);
    }
}
