//! Runtime counters and a hand-rolled Prometheus text exposition.
//!
//! Hand-rolled (no `prometheus` crate) so the exact metric names from the design
//! spec are stable and the hot path uses only lock-free atomics. Alert counting
//! uses a mutexed map because alerts are rare compared to packets.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use crate::types::RuleId;

/// All process-wide counters. Cheap to clone via `Arc`.
#[derive(Debug, Default)]
pub struct Counters {
    packets: AtomicU64,
    bytes: AtomicU64,
    parse_errors: AtomicU64,
    drops: AtomicU64,
    skipped_nonpublic: AtomicU64,
    tracked_keys: AtomicU64,
    channel_depth: AtomicU64,
    evictions: AtomicU64,
    feed_age_s: AtomicU64,
    custom_signatures: AtomicU64,
    alerts_total: AtomicU64,
    alerts_by_rule: Mutex<HashMap<&'static str, u64>>,
}

impl Counters {
    /// New zeroed counters.
    pub fn new() -> Self {
        Self::default()
    }

    /// Count decoded packets.
    pub fn inc_packets(&self, n: u64) {
        self.packets.fetch_add(n, Ordering::Relaxed);
    }
    /// Count wire bytes.
    pub fn add_bytes(&self, n: u64) {
        self.bytes.fetch_add(n, Ordering::Relaxed);
    }
    /// Count malformed/undecodable frames.
    pub fn inc_parse_errors(&self, n: u64) {
        self.parse_errors.fetch_add(n, Ordering::Relaxed);
    }
    /// Count events dropped at a full channel.
    pub fn inc_drops(&self, n: u64) {
        self.drops.fetch_add(n, Ordering::Relaxed);
    }
    /// Count peers skipped as non-public.
    pub fn inc_skipped_nonpublic(&self, n: u64) {
        self.skipped_nonpublic.fetch_add(n, Ordering::Relaxed);
    }
    /// Count LRU evictions.
    pub fn inc_evictions(&self, n: u64) {
        self.evictions.fetch_add(n, Ordering::Relaxed);
    }
    /// Set the tracked-key gauge.
    pub fn set_tracked_keys(&self, n: u64) {
        self.tracked_keys.store(n, Ordering::Relaxed);
    }
    /// Set the channel-depth gauge.
    pub fn set_channel_depth(&self, n: u64) {
        self.channel_depth.store(n, Ordering::Relaxed);
    }
    /// Set the seconds since the last successful intel refresh.
    pub fn set_feed_age(&self, secs: u64) {
        self.feed_age_s.store(secs, Ordering::Relaxed);
    }
    /// Set the number of active custom/Snort signatures.
    pub fn set_custom_signatures(&self, n: u64) {
        self.custom_signatures.store(n, Ordering::Relaxed);
    }
    /// Custom-signature gauge value.
    pub fn custom_signatures(&self) -> u64 {
        self.custom_signatures.load(Ordering::Relaxed)
    }
    /// Record a single alert for a rule.
    pub fn record_alert(&self, rule: RuleId) {
        self.alerts_total.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut m) = self.alerts_by_rule.lock() {
            *m.entry(rule.as_str()).or_insert(0) += 1;
        }
    }

    // Snapshot getters (used by tests).
    /// Packets decoded so far.
    pub fn packets(&self) -> u64 {
        self.packets.load(Ordering::Relaxed)
    }
    /// Parse errors so far.
    pub fn parse_errors(&self) -> u64 {
        self.parse_errors.load(Ordering::Relaxed)
    }
    /// Drops so far.
    pub fn drops(&self) -> u64 {
        self.drops.load(Ordering::Relaxed)
    }
    /// Wire bytes so far.
    pub fn bytes(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }
    /// Skipped non-public peers so far.
    pub fn skipped_nonpublic(&self) -> u64 {
        self.skipped_nonpublic.load(Ordering::Relaxed)
    }
    /// LRU evictions so far.
    pub fn evictions(&self) -> u64 {
        self.evictions.load(Ordering::Relaxed)
    }
    /// Tracked-key gauge.
    pub fn tracked_keys(&self) -> u64 {
        self.tracked_keys.load(Ordering::Relaxed)
    }
    /// Channel-depth gauge.
    pub fn channel_depth(&self) -> u64 {
        self.channel_depth.load(Ordering::Relaxed)
    }
    /// Feed-age gauge (seconds since last intel refresh).
    pub fn feed_age(&self) -> u64 {
        self.feed_age_s.load(Ordering::Relaxed)
    }
    /// Alerts so far.
    pub fn alerts_total(&self) -> u64 {
        self.alerts_total.load(Ordering::Relaxed)
    }
    /// Alerts for one rule.
    pub fn alerts_for(&self, rule: RuleId) -> u64 {
        self.alerts_by_rule
            .lock()
            .map(|m| m.get(rule.as_str()).copied().unwrap_or(0))
            .unwrap_or(0)
    }

    /// Render the Prometheus text format.
    pub fn prometheus_text(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(1024);
        let counters = [
            ("ingressd_packets_total", "counter", self.packets.load(Ordering::Relaxed), "Packets decoded"),
            ("ingressd_bytes_total", "counter", self.bytes.load(Ordering::Relaxed), "Wire bytes decoded"),
            ("ingressd_parse_errors_total", "counter", self.parse_errors.load(Ordering::Relaxed), "Malformed frames"),
            ("ingressd_drops_total", "counter", self.drops.load(Ordering::Relaxed), "Events dropped at full channel"),
            (
                "ingressd_skipped_nonpublic_total",
                "counter",
                self.skipped_nonpublic.load(Ordering::Relaxed),
                "Peers skipped as non-public",
            ),
            ("ingressd_evictions_total", "counter", self.evictions.load(Ordering::Relaxed), "LRU key evictions"),
            ("ingressd_alerts_total", "counter", self.alerts_total.load(Ordering::Relaxed), "Alerts emitted"),
            ("ingressd_tracked_keys", "gauge", self.tracked_keys.load(Ordering::Relaxed), "Tracked window keys"),
            ("ingressd_channel_depth", "gauge", self.channel_depth.load(Ordering::Relaxed), "Capture channel depth"),
            (
                "ingressd_intel_feed_age_seconds",
                "gauge",
                self.feed_age_s.load(Ordering::Relaxed),
                "Seconds since last intel refresh",
            ),
            (
                "ingressd_custom_signatures_total",
                "gauge",
                self.custom_signatures.load(Ordering::Relaxed),
                "Active custom/Snort signatures",
            ),
        ];
        for (name, ty, val, help) in counters {
            let _ = writeln!(s, "# HELP {name} {help}");
            let _ = writeln!(s, "# TYPE {name} {ty}");
            let _ = writeln!(s, "{name} {val}");
        }
        let _ = writeln!(s, "# HELP ingressd_alerts_by_rule Alerts emitted per rule");
        let _ = writeln!(s, "# TYPE ingressd_alerts_by_rule counter");
        if let Ok(m) = self.alerts_by_rule.lock() {
            for rule in RuleId::ALL {
                let v = m.get(rule.as_str()).copied().unwrap_or(0);
                let _ = writeln!(s, "ingressd_alerts_by_rule{{rule=\"{}\"}} {v}", rule.as_str());
            }
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prometheus_output_has_all_series() {
        let c = Counters::new();
        c.inc_packets(10);
        c.add_bytes(100);
        c.record_alert(RuleId::PortScan);
        let text = c.prometheus_text();
        assert!(text.contains("ingressd_packets_total 10"));
        assert!(text.contains("ingressd_alerts_by_rule{rule=\"port-scan\"} 1"));
        assert!(text.contains("ingressd_bytes_total 100"));
    }
}
