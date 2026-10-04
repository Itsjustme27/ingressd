//! The detection engine: owns the enabled detectors, enforces the allowlist,
//! enriches alerts with GeoIP/ASN, and updates counters.
//!
//! The engine expects incoming [`PacketEvent`]s to already be public-scoped and
//! direction-tagged — that is the capture layer's responsibility
//! (`ingressd-capture`). This separation keeps the engine portable and easy to
//! drive from unit and end-to-end tests.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use ipnet::IpNet;

use crate::config::RulesConfig;
use crate::intel::{GeoArc, GeoSource, IntelArc};
use crate::metrics::Counters;
use crate::rules::{build_detectors, Detector};
use crate::types::{Alert, AlertDraft, PacketEvent};

/// Runs all enabled detection rules over a stream of events.
pub struct Engine {
    detectors: Vec<Box<dyn Detector>>,
    allowlist: Vec<IpNet>,
    geo: GeoArc,
    counters: Arc<Counters>,
    sensor: String,
}

impl Engine {
    /// Build an engine from rule configuration plus the intel/geo/counters wiring.
    ///
    /// `sensor` is stamped on every alert (hostname / instance id) so SIEM
    /// consumers can attribute events to a specific endpoint.
    pub fn new(
        cfg: &RulesConfig,
        intel: IntelArc,
        geo: GeoArc,
        counters: Arc<Counters>,
        allowlist: Vec<IpNet>,
        sensor: String,
    ) -> Engine {
        Engine {
            detectors: build_detectors(cfg, intel),
            allowlist,
            geo,
            counters,
            sensor,
        }
    }

    /// Whether `ip` is allowlisted (never alerted on, never blocked).
    pub fn is_allowlisted(&self, ip: IpAddr) -> bool {
        self.allowlist.iter().any(|net| net.contains(ip))
    }

    /// Provide the current set of locally-listening TCP ports.
    pub fn set_listening_ports(&mut self, ports: &HashSet<u16>) {
        for d in &mut self.detectors {
            d.set_listening_ports(ports);
        }
    }

    /// Process one event and return any alerts that fired.
    pub fn process(&mut self, ev: &PacketEvent) -> Vec<Alert> {
        if self.is_allowlisted(ev.peer_ip) {
            return Vec::new();
        }

        let mut drafts: Vec<AlertDraft> = Vec::new();
        for d in &mut self.detectors {
            d.on_event(ev, &mut drafts);
        }

        if drafts.is_empty() {
            self.update_gauges();
            return Vec::new();
        }

        let mut alerts = Vec::with_capacity(drafts.len());
        for dr in drafts {
            let (asn, cc) = match &self.geo {
                Some(g) => GeoSource::lookup(&**g, dr.peer_ip),
                None => (None, None),
            };
            let mut alert = dr.finish(asn, cc);
            alert.sensor = self.sensor.clone();
            self.counters.record_alert(alert.rule);
            alerts.push(alert);
        }
        self.update_gauges();
        alerts
    }

    /// Number of active detectors and their rule keys (for startup logging).
    pub fn active_rules(&self) -> Vec<&'static str> {
        self.detectors.iter().map(|d| d.id().as_str()).collect()
    }

    fn update_gauges(&self) {
        let mut sum = 0usize;
        for d in &self.detectors {
            sum += d.tracked_keys();
        }
        self.counters.set_tracked_keys(sum as u64);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intel::NullIntel;
    use crate::types::{Direction, Proto, TcpFlags};
    use std::time::{Duration, SystemTime};

    fn counters() -> Arc<Counters> {
        Arc::new(Counters::new())
    }

    fn syn(peer: &str, local: &str, dport: u16, ts: SystemTime) -> PacketEvent {
        let peer: IpAddr = peer.parse().unwrap();
        let local: IpAddr = local.parse().unwrap();
        PacketEvent {
            ts,
            direction: Direction::Inbound,
            local_ip: local,
            peer_ip: peer,
            src_ip: peer,
            dst_ip: local,
            proto: Proto::Tcp,
            src_port: Some(40000),
            dst_port: Some(dport),
            tcp_flags: Some(TcpFlags::from_bits(0x02)),
            icmp: None,
            dns: None,
            payload_len: 0,
            payload: Vec::new(),
            ip_total_len: 40,
            fragmented: false,
            first_fragment: false,
        }
    }

    #[test]
    fn allowlisted_peer_never_alerts() {
        let cfg = RulesConfig::default();
        let mut eng = Engine::new(
            &cfg,
            Arc::new(NullIntel),
            None,
            counters(),
            vec!["203.0.113.0/24".parse().unwrap()],
            "test-sensor".into(),
        );
        let base = SystemTime::now();
        let mut fired = 0;
        for p in 0..cfg.port_scan.min_targets as u16 {
            fired += eng
                .process(&syn("203.0.113.9", "198.51.100.5", 100 + p, base))
                .len();
        }
        assert_eq!(fired, 0, "allowlisted peer must not alert");
    }

    #[test]
    fn engine_emits_scan_and_counts_it() {
        let cfg = RulesConfig::default();
        let c = counters();
        let mut eng = Engine::new(
            &cfg,
            Arc::new(NullIntel),
            None,
            Arc::clone(&c),
            Vec::new(),
            "test-sensor".into(),
        );
        let base = SystemTime::now();
        let mut total = 0;
        for p in 0..cfg.port_scan.min_targets as u16 + 5 {
            total += eng
                .process(&syn("203.0.113.77", "198.51.100.5", 1000 + p, base))
                .len();
        }
        assert!(total >= 1);
        assert_eq!(c.alerts_for(RuleIdKey::PortScan), 1);
    }

    // tiny alias so we don't import RuleId at module top in tests twice
    type RuleIdKey = crate::types::RuleId;

    #[test]
    fn cooldown_suppresses_within_window() {
        let mut cfg = RulesConfig::default();
        cfg.port_scan.min_targets = 2;
        cfg.port_scan.window_s = 300;
        cfg.port_scan.cooldown_s = 3600;
        let mut eng = Engine::new(
            &cfg,
            Arc::new(NullIntel),
            None,
            counters(),
            Vec::new(),
            "test-sensor".into(),
        );
        let base = SystemTime::now();
        let a = eng
            .process(&syn("198.51.100.9", "203.0.113.5", 1, base))
            .len();
        let b = eng
            .process(&syn("198.51.100.9", "203.0.113.5", 2, base))
            .len();
        let _ = a;
        assert_eq!(b, 1, "first crossing should alert");
        // A second crossing right away is within cooldown -> suppressed.
        let c = eng
            .process(&syn(
                "198.51.100.9",
                "203.0.113.5",
                3,
                base + Duration::from_secs(1),
            ))
            .len();
        assert_eq!(c, 0, "cooldown should suppress the second alert");
    }
}
