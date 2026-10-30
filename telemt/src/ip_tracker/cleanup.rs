use super::*;

struct DetachedCleanupBatch<'a> {
    tracker: &'a UserIpTracker,
    shard_idx: usize,
    entries: CleanupBatch,
}

impl DetachedCleanupBatch<'_> {
    fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn entries(&self) -> impl Iterator<Item = (&(String, UserIncarnation, IpAddr), &usize)> {
        self.entries.iter()
    }

    fn commit(mut self) {
        let committed = self.entries.len();
        self.entries.clear();
        UserIpTracker::decrement_counter(&self.tracker.cleanup_queue_len, committed);
    }
}

impl Drop for DetachedCleanupBatch<'_> {
    fn drop(&mut self) {
        if self.entries.is_empty() {
            return;
        }

        let cleanup_shard = &self.tracker.cleanup_shards[self.shard_idx];
        let mut duplicate_entries = 0usize;
        let mut restore = |queue: &mut CleanupQueue| {
            for ((user, incarnation, ip), count) in self.entries.drain() {
                let queued = queue
                    .entry(user)
                    .or_default()
                    .entry(incarnation)
                    .or_default()
                    .entry(ip)
                    .or_insert(0);
                if *queued != 0 {
                    duplicate_entries = duplicate_entries.saturating_add(1);
                }
                *queued = queued.saturating_add(count);
            }
        };
        match cleanup_shard.queue.lock() {
            Ok(mut queue) => restore(&mut queue),
            Err(poisoned) => {
                let mut queue = poisoned.into_inner();
                restore(&mut queue);
                cleanup_shard.queue.clear_poison();
                tracing::warn!(
                    "UserIpTracker cleanup_queue lock poisoned while restoring a cancelled cleanup batch"
                );
            }
        }
        UserIpTracker::decrement_counter(&self.tracker.cleanup_queue_len, duplicate_entries);
    }
}

impl UserIpTracker {
    /// Queues a deferred active IP cleanup for a later async drain.
    pub fn enqueue_cleanup(&self, user: String, ip: IpAddr) {
        self.enqueue_cleanup_for_incarnation(user, 0, ip);
    }

    /// Queues cleanup for the exact user incarnation that owns the reservation.
    pub(crate) fn enqueue_cleanup_for_incarnation(
        &self,
        user: String,
        incarnation: UserIncarnation,
        ip: IpAddr,
    ) {
        self.observe_cleanup_poison_for_tests();
        let shard_idx = Self::shard_idx(&user);
        let cleanup_shard = &self.cleanup_shards[shard_idx];
        match cleanup_shard.queue.lock() {
            Ok(mut queue) => {
                let count = queue
                    .entry(user)
                    .or_default()
                    .entry(incarnation)
                    .or_default()
                    .entry(ip)
                    .or_insert(0);
                if *count == 0 {
                    self.cleanup_queue_len.fetch_add(1, Ordering::Relaxed);
                }
                *count = count.saturating_add(1);
                self.cleanup_deferred_releases
                    .fetch_add(1, Ordering::Relaxed);
            }
            Err(poisoned) => {
                let mut queue = poisoned.into_inner();
                let count = queue
                    .entry(user.clone())
                    .or_default()
                    .entry(incarnation)
                    .or_default()
                    .entry(ip)
                    .or_insert(0);
                if *count == 0 {
                    self.cleanup_queue_len.fetch_add(1, Ordering::Relaxed);
                }
                *count = count.saturating_add(1);
                self.cleanup_deferred_releases
                    .fetch_add(1, Ordering::Relaxed);
                cleanup_shard.queue.clear_poison();
                tracing::warn!(
                    "UserIpTracker cleanup_queue lock poisoned; recovered and enqueued IP cleanup for {} ({})",
                    user,
                    ip
                );
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn cleanup_queue_len_for_tests(&self) -> usize {
        self.cleanup_queue_len.load(Ordering::Relaxed) as usize
    }

    #[cfg(test)]
    pub(crate) fn cleanup_queue_physical_entries_for_tests(&self) -> usize {
        self.cleanup_shards
            .iter()
            .map(|cleanup_shard| {
                let count = |queue: &CleanupQueue| {
                    queue
                        .values()
                        .flat_map(HashMap::values)
                        .map(HashMap::len)
                        .sum::<usize>()
                };
                match cleanup_shard.queue.lock() {
                    Ok(queue) => count(&queue),
                    Err(poisoned) => count(&poisoned.into_inner()),
                }
            })
            .sum()
    }

    #[cfg(test)]
    pub(crate) fn cleanup_queue_mutex_for_tests(
        &self,
    ) -> Arc<Mutex<HashMap<(String, IpAddr), usize>>> {
        Arc::clone(&self.cleanup_queue_poison_probe)
    }

    pub(crate) async fn drain_cleanup_queue(&self) {
        if self.cleanup_queue_len.load(Ordering::Relaxed) == 0 {
            return;
        }
        for shard_idx in 0..USER_IP_TRACKER_SHARDS {
            self.drain_cleanup_shard(shard_idx).await;
        }
    }

    pub(super) async fn drain_cleanup_for_user(&self, user: &str) {
        if self.cleanup_queue_len.load(Ordering::Relaxed) == 0 {
            return;
        }
        let shard_idx = Self::shard_idx(user);
        let _drain_guard = self.cleanup_drain_locks[shard_idx].lock().await;
        let cleanup_shard = &self.cleanup_shards[shard_idx];
        let to_remove = match cleanup_shard.queue.lock() {
            Ok(mut queue) => detach_user_cleanup(self, shard_idx, &mut queue, user),
            Err(poisoned) => {
                let mut queue = poisoned.into_inner();
                let drained = detach_user_cleanup(self, shard_idx, &mut queue, user);
                cleanup_shard.queue.clear_poison();
                drained
            }
        };
        if to_remove.is_empty() {
            return;
        }
        let mut shard = self.shards[shard_idx].write().await;
        let mut removed_active_entries = 0usize;
        for ((queued_user, incarnation, ip), pending_count) in to_remove.entries() {
            if shard.incarnations.get(queued_user).copied() != Some(*incarnation) {
                continue;
            }
            removed_active_entries = removed_active_entries.saturating_add(
                Self::apply_active_cleanup(&mut shard.active_ips, queued_user, *ip, *pending_count),
            );
        }
        Self::decrement_counter(&self.active_entry_count, removed_active_entries);
        drop(shard);
        to_remove.commit();
    }

    pub(super) async fn drain_cleanup_shard(&self, shard_idx: usize) {
        let Ok(_drain_guard) = self.cleanup_drain_locks[shard_idx].try_lock() else {
            return;
        };

        let cleanup_shard = &self.cleanup_shards[shard_idx];
        let to_remove = {
            match cleanup_shard.queue.lock() {
                Ok(mut queue) => {
                    if queue.is_empty() {
                        return;
                    }
                    let mut drained = HashMap::with_capacity(CLEANUP_DRAIN_BATCH_LIMIT);
                    for _ in 0..CLEANUP_DRAIN_BATCH_LIMIT {
                        let Some((user, incarnation, ip, count)) =
                            Self::pop_one_cleanup(&mut queue)
                        else {
                            break;
                        };
                        drained.insert((user, incarnation, ip), count);
                    }
                    DetachedCleanupBatch {
                        tracker: self,
                        shard_idx,
                        entries: drained,
                    }
                }
                Err(poisoned) => {
                    let mut queue = poisoned.into_inner();
                    if queue.is_empty() {
                        cleanup_shard.queue.clear_poison();
                        return;
                    }
                    let mut drained = HashMap::with_capacity(CLEANUP_DRAIN_BATCH_LIMIT);
                    for _ in 0..CLEANUP_DRAIN_BATCH_LIMIT {
                        let Some((user, incarnation, ip, count)) =
                            Self::pop_one_cleanup(&mut queue)
                        else {
                            break;
                        };
                        drained.insert((user, incarnation, ip), count);
                    }
                    cleanup_shard.queue.clear_poison();
                    DetachedCleanupBatch {
                        tracker: self,
                        shard_idx,
                        entries: drained,
                    }
                }
            }
        };
        if to_remove.is_empty() {
            return;
        }

        let mut shard = self.shards[shard_idx].write().await;
        let mut removed_active_entries = 0usize;
        for ((user, incarnation, ip), pending_count) in to_remove.entries() {
            if shard.incarnations.get(user).copied() != Some(*incarnation) {
                continue;
            }
            removed_active_entries = removed_active_entries.saturating_add(
                Self::apply_active_cleanup(&mut shard.active_ips, user, *ip, *pending_count),
            );
        }
        Self::decrement_counter(&self.active_entry_count, removed_active_entries);
        drop(shard);
        to_remove.commit();
    }
}

fn detach_user_cleanup<'a>(
    tracker: &'a UserIpTracker,
    shard_idx: usize,
    queue: &mut CleanupQueue,
    user: &str,
) -> DetachedCleanupBatch<'a> {
    let mut entries = CleanupBatch::new();
    if let Some(incarnations) = queue.remove(user) {
        for (incarnation, ips) in incarnations {
            for (ip, count) in ips {
                entries.insert((user.to_string(), incarnation, ip), count);
            }
        }
    }
    DetachedCleanupBatch {
        tracker,
        shard_idx,
        entries,
    }
}
