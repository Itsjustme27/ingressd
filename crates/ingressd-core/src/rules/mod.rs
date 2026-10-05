//! Detection rule framework: the [`Detector`] trait, shared primitives, and the
//! registry that assembles enabled rules from [`crate::config::RulesConfig`].

use std::collections::{HashSet, VecDeque};
use std::time::{Duration, SystemTime};

use crate::state::BoundedMap;
use crate::types::{AlertDraft, PacketEvent, RuleId};

pub mod detectors;

pub use detectors::build_detectors;

/// A single stateful detection rule.
///
/// Rules own their bounded per-peer state and apply their own per-(rule,peer)
/// cooldown, so the engine does not need to know anything rule-specific.
pub trait Detector: Send {
    /// Which rule this is.
    fn id(&self) -> RuleId;

    /// Consume one event; append any alerts that fire to `out`.
    fn on_event(&mut self, ev: &PacketEvent, out: &mut Vec<AlertDraft>);

    /// Inject the set of locally-listening TCP ports (for `new-listener-probe`).
    fn set_listening_ports(&mut self, _ports: &HashSet<u16>) {}

    /// Approximate number of tracked keys, summed into a gauge metric.
    fn tracked_keys(&self) -> usize {
        0
    }
}

/// Per-key emission cooldown backed by a [`BoundedMap`].
pub struct Cooldown<K: Eq + std::hash::Hash + Clone> {
    map: BoundedMap<K, SystemTime>,
    dur: Duration,
}

impl<K: Eq + std::hash::Hash + Clone> Cooldown<K> {
    /// A cooldown that remembers at most `cap` keys.
    pub fn new(cap: usize, dur: Duration) -> Self {
        Cooldown {
            map: BoundedMap::new(cap),
            dur,
        }
    }

    /// True if an alert for `key` may be emitted now; records the emission.
    pub fn allow(&mut self, key: &K, now: SystemTime) -> bool {
        if let Some(&last) = self.map.get(key) {
            if now
                .duration_since(last)
                .map(|d| d < self.dur)
                .unwrap_or(false)
            {
                return false;
            }
        }
        self.map.insert(key.clone(), now);
        true
    }

    /// Number of keys remembered.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

/// Append a timestamp, drop entries older than `window`, return the count kept.
pub fn bump_window(deq: &mut VecDeque<SystemTime>, now: SystemTime, window: Duration) -> u64 {
    deq.push_back(now);
    let cutoff = now.checked_sub(window).unwrap_or(SystemTime::UNIX_EPOCH);
    while let Some(&front) = deq.front() {
        if front <= cutoff {
            deq.pop_front();
        } else {
            break;
        }
    }
    deq.len() as u64
}

/// Whole seconds between two times, saturating at 0.
pub fn delta_secs(a: SystemTime, b: SystemTime) -> f64 {
    b.duration_since(a)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// Shannon entropy in bits per character.
pub fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut freq = [0usize; 256];
    for &b in s.as_bytes() {
        freq[b as usize] += 1;
    }
    let n = s.len() as f64;
    let mut h = 0.0f64;
    for &c in &freq {
        if c > 0 {
            let p = c as f64 / n;
            h -= p * p.log2();
        }
    }
    h
}

/// The registrable base domain: the last two labels, or the whole name if short.
pub fn base_domain(qname: &str) -> String {
    let parts: Vec<&str> = qname.split('.').collect();
    if parts.len() >= 2 {
        format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
    } else {
        qname.to_string()
    }
}

/// Length of the longest single DNS label.
pub fn longest_label(qname: &str) -> usize {
    qname.split('.').map(|l| l.len()).max().unwrap_or(0)
}

/// Build the detector list from configuration, wiring the shared intel source.
///
/// Each rule is independently capped at `cfg.max_tracked_keys` (a stricter bound
/// than a shared pool, which keeps one noisy rule from starving the others).
pub fn new_bounded<K: Eq + std::hash::Hash + Clone, V>(cap: usize) -> BoundedMap<K, V> {
    BoundedMap::new(cap)
}

/// Helper used by detectors to make an alert draft with the rule id attached.
pub fn draft(
    ev: &PacketEvent,
    rule: RuleId,
    severity: crate::types::Severity,
    detail: String,
    count: u64,
    window_s: u64,
) -> AlertDraft {
    AlertDraft::from_event(ev, severity, detail, count, window_s, rule)
}
