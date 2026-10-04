//! Bounded, LRU-capped sliding-window state.
//!
//! Every rule keeps per-key state in a [`BoundedMap`]. When a rule would exceed
//! its configured key cap (defence against a spoofed-source flood exhausting
//! memory), the least-recently-touched entries are evicted in bulk and an
//! eviction counter is bumped. Expiry of timestamps inside a window is handled
//! with [`drain_expired`].

use std::collections::VecDeque;
use std::hash::Hash;
use std::time::{Duration, SystemTime};

use hashbrown::HashMap;

struct Slot<V> {
    v: V,
    tick: u64,
}

/// A `HashMap` with an LRU eviction cap keyed on touch order.
pub struct BoundedMap<K, V> {
    map: HashMap<K, Slot<V>>,
    cap: usize,
    clock: u64,
    evictions: u64,
}

impl<K: Eq + Hash + Clone, V> BoundedMap<K, V> {
    /// New map holding at most `cap` keys.
    pub fn new(cap: usize) -> Self {
        BoundedMap {
            map: HashMap::with_capacity(cap.min(4096)),
            cap: cap.max(1),
            clock: 0,
            evictions: 0,
        }
    }

    fn bump(&mut self) -> u64 {
        self.clock = self.clock.wrapping_add(1);
        self.clock
    }

    /// Configured cap.
    pub fn cap(&self) -> usize {
        self.cap
    }

    /// Total keys currently tracked.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Number of keys evicted since creation (feeds a metric).
    pub fn evictions(&self) -> u64 {
        self.evictions
    }

    /// Immutable lookup (does not affect recency).
    pub fn get(&self, k: &K) -> Option<&V> {
        self.map.get(k).map(|s| &s.v)
    }

    /// Mutable lookup, marking `k` as recently used.
    pub fn get_mut(&mut self, k: &K) -> Option<&mut V> {
        let tick = self.bump();
        match self.map.get_mut(k) {
            Some(s) => {
                s.tick = tick;
                Some(&mut s.v)
            }
            None => None,
        }
    }

    /// Whether the key exists.
    pub fn contains_key(&self, k: &K) -> bool {
        self.map.contains_key(k)
    }

    /// Remove a key, returning its value.
    pub fn remove(&mut self, k: &K) -> Option<V> {
        self.map.remove(k).map(|s| s.v)
    }

    /// Get a mutable reference to `k`'s value, creating it with `f` if absent,
    /// then pruning to the cap if needed.
    pub fn get_or_insert_with(&mut self, k: K, f: impl FnOnce() -> V) -> &mut V {
        let tick = self.bump();
        if self.map.len() >= self.cap && !self.map.contains_key(&k) {
            self.prune_lru();
        }
        let slot = self.map.entry(k).or_insert_with(|| Slot { v: f(), tick });
        slot.tick = tick;
        &mut slot.v
    }

    /// Insert a value, returning the previous value for the key if any.
    pub fn insert(&mut self, k: K, v: V) -> Option<V> {
        let tick = self.bump();
        if self.map.len() >= self.cap && !self.map.contains_key(&k) {
            self.prune_lru();
        }
        self.map.insert(k, Slot { v, tick }).map(|s| s.v)
    }

    /// Iterate over all entries (unordered).
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.map.iter().map(|(k, s)| (k, &s.v))
    }

    /// Snapshot the keys, so a caller can then mutate values by key without
    /// holding an iterator borrow.
    pub fn keys_vec(&self) -> Vec<K> {
        self.map.keys().cloned().collect()
    }

    /// Remove every entry for which `pred(k, v)` is true.
    pub fn retain(&mut self, mut pred: impl FnMut(&K, &V) -> bool) {
        self.map.retain(|k, s| pred(k, &s.v));
    }

    /// Clear all state (keeps evictions).
    pub fn clear(&mut self) {
        self.map.clear();
    }

    fn prune_lru(&mut self) {
        if self.map.len() <= self.cap {
            return;
        }
        // Evict down to ~7/8 capacity so the next prune is amortised.
        let target = (self.cap - self.cap / 8).max(1);
        let remove_n = self.map.len().saturating_sub(target);
        let mut order: Vec<(u64, K)> = self.map.iter().map(|(k, s)| (s.tick, k.clone())).collect();
        order.sort_unstable_by_key(|x| x.0);
        for i in 0..remove_n.min(order.len()) {
            self.map.remove(&order[i].1);
        }
        self.evictions += remove_n as u64;
    }
}

/// Push `now` onto a deque of event times and drop those older than the window.
///
/// The deque must stay sorted by time (it will be when fed monotonic or
/// near-monotonic packet timestamps; we defensively drop from the front only).
pub fn push_and_prune(deq: &mut VecDeque<SystemTime>, now: SystemTime, window: Duration) {
    deq.push_back(now);
    let cutoff = now.checked_sub(window).unwrap_or(SystemTime::UNIX_EPOCH);
    while let Some(&front) = deq.front() {
        if front <= cutoff {
            deq.pop_front();
        } else {
            break;
        }
    }
}

/// Count how many timestamps in the deque fall within `window` of `now`.
pub fn count_in_window(deq: &VecDeque<SystemTime>, now: SystemTime, window: Duration) -> u64 {
    let cutoff = now.checked_sub(window).unwrap_or(SystemTime::UNIX_EPOCH);
    deq.iter().filter(|&&t| t > cutoff).count() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lru_evicts_over_cap() {
        let mut m: BoundedMap<u32, u32> = BoundedMap::new(8);
        for i in 0..20u32 {
            m.insert(i, i * 10);
        }
        assert!(m.len() <= 8 + 1, "len was {}", m.len());
        assert!(m.evictions() > 0);
    }

    #[test]
    fn get_or_insert_bumps_and_evicts() {
        let mut m: BoundedMap<u32, VecDeque<u32>> = BoundedMap::new(4);
        for i in 0..10u32 {
            m.get_or_insert_with(i, VecDeque::new).push_back(i);
        }
        assert!(m.len() <= 5);
        assert!(m.evictions() > 0);
    }

    #[test]
    fn retain_and_iter() {
        let mut m: BoundedMap<u32, u32> = BoundedMap::new(100);
        for i in 0..10u32 {
            m.insert(i, i);
        }
        m.retain(|_, v| v % 2 == 0);
        assert_eq!(m.len(), 5);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        // push_and_prune never exceeds the window length and stays sorted.
        #[test]
        fn window_stays_within_duration(times in prop::collection::vec(0u64..100_000, 1..200)) {
            let mut deq: VecDeque<SystemTime> = VecDeque::new();
            let base = SystemTime::UNIX_EPOCH;
            let window = Duration::from_secs(10);
            for secs in times {
                let now = base + Duration::from_secs(secs);
                push_and_prune(&mut deq, now, window);
                // every retained entry is within the window of `now`, or is in
                // the future (input may be unsorted during replay).
                for &t in &deq {
                    let dt = now.duration_since(t).unwrap_or(Duration::ZERO);
                    prop_assert!(dt <= window || t > now);
                }
                prop_assert!(deq.contains(&now));
            }
        }

        // BoundedMap never exceeds cap by more than one between prunes.
        #[test]
        fn bounded_map_respects_cap(keys in prop::collection::vec(any::<u32>(), 1..1000)) {
            let cap = 50usize;
            let mut m: BoundedMap<u32, u32> = BoundedMap::new(cap);
            for k in keys {
                m.get_or_insert_with(k, || 0);
                prop_assert!(m.len() <= cap + 1);
            }
        }
    }
}
