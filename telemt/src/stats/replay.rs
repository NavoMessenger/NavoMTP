use std::borrow::Borrow;
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, VecDeque};
use std::hash::{Hash, Hasher};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use lru::LruCache;
use parking_lot::Mutex;
use tracing::debug;

const REPLAY_INLINE_KEY_CAP: usize = 48;

#[derive(Clone)]
enum ReplayKey {
    Inline {
        len: u8,
        bytes: [u8; REPLAY_INLINE_KEY_CAP],
    },
    Heap(Arc<[u8]>),
}

impl ReplayKey {
    fn from_slice(key: &[u8]) -> Self {
        if key.len() <= REPLAY_INLINE_KEY_CAP {
            let mut bytes = [0u8; REPLAY_INLINE_KEY_CAP];
            bytes[..key.len()].copy_from_slice(key);
            return Self::Inline {
                len: key.len() as u8,
                bytes,
            };
        }

        Self::Heap(Arc::from(key))
    }

    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Inline { len, bytes } => &bytes[..*len as usize],
            Self::Heap(bytes) => bytes.as_ref(),
        }
    }
}

impl Borrow<[u8]> for ReplayKey {
    fn borrow(&self) -> &[u8] {
        self.as_slice()
    }
}

impl PartialEq for ReplayKey {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for ReplayKey {}

impl Hash for ReplayKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_slice().hash(state);
    }
}

pub struct ReplayChecker {
    handshake_shards: Vec<Mutex<ReplayShard>>,
    tls_shards: Vec<Mutex<ReplayShard>>,
    shard_mask: usize,
    window: Duration,
    tls_window: Duration,
    checks: AtomicU64,
    hits: AtomicU64,
    additions: AtomicU64,
    capacity_rejections: AtomicU64,
    cleanups: AtomicU64,
    next_claim_token: AtomicU64,
}

struct ReplayEntry {
    seq: u64,
}

struct ReplayShard {
    cache: LruCache<ReplayKey, ReplayEntry>,
    pending: HashMap<ReplayKey, u64>,
    queue: VecDeque<(Instant, ReplayKey, u64)>,
    seq_counter: u64,
    capacity: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReplayClaimResult {
    Claimed,
    Duplicate,
    Capacity,
}

impl ReplayShard {
    fn new(cap: NonZeroUsize) -> Self {
        Self {
            cache: LruCache::new(cap),
            pending: HashMap::new(),
            queue: VecDeque::with_capacity(cap.get()),
            seq_counter: 0,
            capacity: cap.get(),
        }
    }

    fn next_seq(&mut self) -> u64 {
        self.seq_counter += 1;
        self.seq_counter
    }

    fn cleanup(&mut self, now: Instant, window: Duration) {
        if window.is_zero() {
            self.cache.clear();
            self.queue.clear();
            return;
        }
        let cutoff = now.checked_sub(window).unwrap_or(now);

        while let Some((ts, _, _)) = self.queue.front() {
            if *ts >= cutoff {
                break;
            }
            self.evict_queue_front();
        }
    }

    fn evict_queue_front(&mut self) {
        let Some((_, key, queue_seq)) = self.queue.pop_front() else {
            return;
        };

        if let Some(entry) = self.cache.peek(key.as_slice())
            && entry.seq == queue_seq
        {
            self.cache.pop(key.as_slice());
        }
    }

    fn check(&mut self, key: &[u8], now: Instant, window: Duration) -> bool {
        if window.is_zero() {
            return false;
        }
        self.cleanup(now, window);
        self.cache.get(key).is_some() || self.pending.contains_key(key)
    }

    fn add_owned(&mut self, key: ReplayKey, now: Instant, window: Duration) -> bool {
        if window.is_zero() {
            return true;
        }
        self.cleanup(now, window);
        if self.cache.peek(key.as_slice()).is_some() || self.pending.contains_key(key.as_slice()) {
            return true;
        }
        while self.cache.len().saturating_add(self.pending.len()) >= self.capacity {
            if self.queue.is_empty() {
                return false;
            }
            self.evict_queue_front();
        }

        let seq = self.next_seq();
        self.cache.put(key.clone(), ReplayEntry { seq });
        self.queue.push_back((now, key, seq));
        true
    }

    fn claim_owned(
        &mut self,
        key: ReplayKey,
        now: Instant,
        window: Duration,
        token: u64,
    ) -> ReplayClaimResult {
        if window.is_zero() {
            return ReplayClaimResult::Claimed;
        }
        self.cleanup(now, window);
        if self.cache.peek(key.as_slice()).is_some() || self.pending.contains_key(key.as_slice()) {
            return ReplayClaimResult::Duplicate;
        }
        while self.cache.len().saturating_add(self.pending.len()) >= self.capacity {
            if self.queue.is_empty() {
                return ReplayClaimResult::Capacity;
            }
            self.evict_queue_front();
        }
        self.pending.insert(key, token);
        ReplayClaimResult::Claimed
    }

    fn remove_pending(&mut self, key: &[u8], token: u64) -> bool {
        if self.pending.get(key).copied() != Some(token) {
            return false;
        }
        self.pending.remove(key);
        true
    }

    fn len(&self) -> usize {
        self.cache.len().saturating_add(self.pending.len())
    }
}

/// Exclusive in-flight ownership of one TLS replay digest.
#[must_use = "the claim must be committed after all TLS policy checks"]
pub(crate) struct TlsReplayClaim<'a> {
    checker: &'a ReplayChecker,
    shard_idx: usize,
    key: Option<ReplayKey>,
    token: u64,
    reserved: bool,
}

impl TlsReplayClaim<'_> {
    /// Commits the claimed digest into the replay window.
    pub(crate) fn commit(mut self) -> bool {
        if !self.reserved {
            return true;
        }
        let Some(key) = self.key.take() else {
            return false;
        };
        let mut shard = self.checker.tls_shards[self.shard_idx].lock();
        if !shard.remove_pending(key.as_slice(), self.token) {
            return false;
        }
        if !shard.add_owned(key, Instant::now(), self.checker.tls_window) {
            self.checker
                .capacity_rejections
                .fetch_add(1, Ordering::Relaxed);
            return false;
        }
        self.checker.additions.fetch_add(1, Ordering::Relaxed);
        self.reserved = false;
        true
    }
}

impl Drop for TlsReplayClaim<'_> {
    fn drop(&mut self) {
        if !self.reserved {
            return;
        }
        if let Some(key) = self.key.as_ref() {
            self.checker.tls_shards[self.shard_idx]
                .lock()
                .remove_pending(key.as_slice(), self.token);
        }
    }
}

impl ReplayChecker {
    pub fn new(total_capacity: usize, window: Duration) -> Self {
        const MIN_TLS_REPLAY_WINDOW: Duration = Duration::from_secs(120);
        let num_shards = 64;
        let shard_capacity = (total_capacity / num_shards).max(1);
        let cap = NonZeroUsize::new(shard_capacity).unwrap();

        let mut handshake_shards = Vec::with_capacity(num_shards);
        let mut tls_shards = Vec::with_capacity(num_shards);
        for _ in 0..num_shards {
            handshake_shards.push(Mutex::new(ReplayShard::new(cap)));
            tls_shards.push(Mutex::new(ReplayShard::new(cap)));
        }

        Self {
            handshake_shards,
            tls_shards,
            shard_mask: num_shards - 1,
            window,
            tls_window: window.max(MIN_TLS_REPLAY_WINDOW),
            checks: AtomicU64::new(0),
            hits: AtomicU64::new(0),
            additions: AtomicU64::new(0),
            capacity_rejections: AtomicU64::new(0),
            cleanups: AtomicU64::new(0),
            next_claim_token: AtomicU64::new(1),
        }
    }

    fn reserve_claim_token(&self) -> Option<u64> {
        let mut current = self.next_claim_token.load(Ordering::Relaxed);
        loop {
            if current == u64::MAX {
                return None;
            }
            match self.next_claim_token.compare_exchange_weak(
                current,
                current + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Some(current),
                Err(actual) => current = actual,
            }
        }
    }

    fn get_shard_idx(&self, key: &[u8]) -> usize {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        (hasher.finish() as usize) & self.shard_mask
    }

    fn check_and_add_internal(
        &self,
        data: &[u8],
        shards: &[Mutex<ReplayShard>],
        window: Duration,
    ) -> bool {
        self.checks.fetch_add(1, Ordering::Relaxed);
        let idx = self.get_shard_idx(data);
        let owned_key = ReplayKey::from_slice(data);
        let mut shard = shards[idx].lock();
        let now = Instant::now();
        let found = shard.check(data, now, window);
        if found {
            self.hits.fetch_add(1, Ordering::Relaxed);
            return true;
        }
        if shard.add_owned(owned_key, now, window) {
            self.additions.fetch_add(1, Ordering::Relaxed);
            false
        } else {
            self.capacity_rejections.fetch_add(1, Ordering::Relaxed);
            true
        }
    }

    fn check_only_internal(
        &self,
        data: &[u8],
        shards: &[Mutex<ReplayShard>],
        window: Duration,
    ) -> bool {
        self.checks.fetch_add(1, Ordering::Relaxed);
        let idx = self.get_shard_idx(data);
        let mut shard = shards[idx].lock();
        let found = shard.check(data, Instant::now(), window);
        if found {
            self.hits.fetch_add(1, Ordering::Relaxed);
        }
        found
    }

    fn add_only(&self, data: &[u8], shards: &[Mutex<ReplayShard>], window: Duration) {
        let idx = self.get_shard_idx(data);
        let owned_key = ReplayKey::from_slice(data);
        let mut shard = shards[idx].lock();
        if shard.add_owned(owned_key, Instant::now(), window) {
            self.additions.fetch_add(1, Ordering::Relaxed);
        } else {
            self.capacity_rejections.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn check_and_add_handshake(&self, data: &[u8]) -> bool {
        self.check_and_add_internal(data, &self.handshake_shards, self.window)
    }

    pub fn check_and_add_tls_digest(&self, data: &[u8]) -> bool {
        self.check_and_add_internal(data, &self.tls_shards, self.tls_window)
    }

    /// Claims one TLS digest until the policy-valid handshake commits or aborts.
    pub(crate) fn claim_tls_digest(&self, data: &[u8]) -> Option<TlsReplayClaim<'_>> {
        self.checks.fetch_add(1, Ordering::Relaxed);
        let shard_idx = self.get_shard_idx(data);
        let key = ReplayKey::from_slice(data);
        if self.tls_window.is_zero() {
            return Some(TlsReplayClaim {
                checker: self,
                shard_idx,
                key: None,
                token: 0,
                reserved: false,
            });
        }
        let token = self.reserve_claim_token()?;
        let mut shard = self.tls_shards[shard_idx].lock();
        match shard.claim_owned(key.clone(), Instant::now(), self.tls_window, token) {
            ReplayClaimResult::Claimed => {}
            ReplayClaimResult::Duplicate => {
                self.hits.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            ReplayClaimResult::Capacity => {
                self.capacity_rejections.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        }
        drop(shard);
        Some(TlsReplayClaim {
            checker: self,
            shard_idx,
            key: Some(key),
            token,
            reserved: true,
        })
    }

    pub fn check_handshake(&self, data: &[u8]) -> bool {
        self.check_and_add_handshake(data)
    }

    pub fn add_handshake(&self, data: &[u8]) {
        self.add_only(data, &self.handshake_shards, self.window)
    }

    pub fn check_tls_digest(&self, data: &[u8]) -> bool {
        self.check_only_internal(data, &self.tls_shards, self.tls_window)
    }

    pub fn add_tls_digest(&self, data: &[u8]) {
        self.add_only(data, &self.tls_shards, self.tls_window)
    }

    pub fn stats(&self) -> ReplayStats {
        let mut total_entries = 0;
        let mut total_queue_len = 0;
        for shard in &self.handshake_shards {
            let s = shard.lock();
            total_entries += s.len();
            total_queue_len += s.queue.len();
        }
        for shard in &self.tls_shards {
            let s = shard.lock();
            total_entries += s.len();
            total_queue_len += s.queue.len();
        }

        ReplayStats {
            total_entries,
            total_queue_len,
            total_checks: self.checks.load(Ordering::Relaxed),
            total_hits: self.hits.load(Ordering::Relaxed),
            total_additions: self.additions.load(Ordering::Relaxed),
            total_capacity_rejections: self.capacity_rejections.load(Ordering::Relaxed),
            total_cleanups: self.cleanups.load(Ordering::Relaxed),
            num_shards: self.handshake_shards.len() + self.tls_shards.len(),
            window_secs: self.window.as_secs(),
        }
    }

    pub async fn run_periodic_cleanup(&self) {
        let interval = if self.window.as_secs() > 60 {
            Duration::from_secs(30)
        } else {
            Duration::from_secs((self.window.as_secs().max(1) / 2).max(1))
        };

        loop {
            tokio::time::sleep(interval).await;

            let now = Instant::now();
            let mut cleaned = 0usize;

            for shard_mutex in &self.handshake_shards {
                let mut shard = shard_mutex.lock();
                let before = shard.len();
                shard.cleanup(now, self.window);
                let after = shard.len();
                cleaned += before.saturating_sub(after);
            }
            for shard_mutex in &self.tls_shards {
                let mut shard = shard_mutex.lock();
                let before = shard.len();
                shard.cleanup(now, self.tls_window);
                let after = shard.len();
                cleaned += before.saturating_sub(after);
            }

            self.cleanups.fetch_add(1, Ordering::Relaxed);

            if cleaned > 0 {
                debug!(cleaned = cleaned, "Replay checker: periodic cleanup");
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReplayStats {
    pub total_entries: usize,
    pub total_queue_len: usize,
    pub total_checks: u64,
    pub total_hits: u64,
    pub total_additions: u64,
    /// Claims rejected because committed and pending entries exhausted a shard.
    pub total_capacity_rejections: u64,
    pub total_cleanups: u64,
    pub num_shards: usize,
    pub window_secs: u64,
}

impl ReplayStats {
    pub fn hit_rate(&self) -> f64 {
        if self.total_checks == 0 {
            0.0
        } else {
            (self.total_hits as f64 / self.total_checks as f64) * 100.0
        }
    }

    pub fn ghost_ratio(&self) -> f64 {
        if self.total_entries == 0 {
            0.0
        } else {
            self.total_queue_len as f64 / self.total_entries as f64
        }
    }
}

#[cfg(test)]
#[path = "replay/tests.rs"]
mod capacity_tests;
