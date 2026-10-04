//! End-to-end replay test: generate the shared pcap scenario (one burst per rule
//! plus a benign flow), write it with the crate's pcap writer, read it back with
//! the reader, push every frame through the real decode -> scope -> engine
//! pipeline, and assert:
//!   * every detection rule fires at least once, and
//!   * the benign peer produces zero alerts (no false positives on the benign flow).

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

use ingressd_capture::{frame_to_event, HostHandle};
use ingressd_core::config::RulesConfig;
use ingressd_core::gen;
use ingressd_core::intel::{IntelHit, IntelArc, ThreatIntelSource};
use ingressd_core::metrics::Counters;
use ingressd_core::pcap::{read_all, PcapWriter};
use ingressd_core::scope::HostAddrs;
use ingressd_core::types::RuleId;
use ingressd_core::Engine;

/// A tiny fixed threat-intel source for the `threat-intel-hit` rule.
struct FixedIntel {
    bad: HashSet<IpAddr>,
}
impl ThreatIntelSource for FixedIntel {
    fn lookup(&self, ip: IpAddr) -> Option<IntelHit> {
        self.bad.get(&ip).map(|_| IntelHit { source: Some("test".to_string()) })
    }
    fn len(&self) -> usize {
        self.bad.len()
    }
}

/// Thresholds tuned so a compact scenario trips each rule exactly.
fn tuned_config() -> RulesConfig {
    let mut c = RulesConfig::default();
    c.port_scan.min_targets = 5;
    c.port_scan.cooldown_s = 1;
    c.invalid_tcp_flags.threshold = 3;
    c.invalid_tcp_flags.cooldown_s = 1;
    c.brute_force.threshold = 4;
    c.brute_force.cooldown_s = 1;
    c.syn_flood.threshold = 20;
    c.syn_flood.cooldown_s = 1;
    c.udp_flood.threshold = 10;
    c.udp_flood.cooldown_s = 1;
    c.icmp_flood.threshold = 10;
    c.icmp_flood.cooldown_s = 1;
    c.reflection.threshold = 3;
    c.reflection.min_response_bytes = 500;
    c.reflection.cooldown_s = 1;
    c.dns_tunnel.subdomain_threshold = 6;
    c.dns_tunnel.cooldown_s = 1;
    c.icmp_tunnel.max_payload = 500;
    c.icmp_tunnel.threshold = 3;
    c.icmp_tunnel.cooldown_s = 1;
    c.beaconing.min_samples = 4;
    c.beaconing.cooldown_s = 1;
    c.new_listener.min_sources = 3;
    c.new_listener.cooldown_s = 1;
    c.suspicious_port.cooldown_s = 1;
    c.threat_intel.cooldown_s = 1;
    c.validate().expect("tuned config must validate");
    c
}

#[test]
fn e2e_replay_detects_all_rules_and_no_benign_fp() {
    let frames = gen::attack_scenario();
    assert!(!frames.is_empty());

    // Write a real pcap, then read it back (round-trips the writer + reader too).
    let path = std::env::temp_dir().join(format!("ingressd-e2e-{}.pcap", std::process::id()));
    {
        let mut w = PcapWriter::new(std::fs::File::create(&path).expect("create pcap")).expect("pcap writer");
        for (ts, f) in &frames {
            w.write_packet(*ts, f).expect("write packet");
        }
    }
    let read = read_all(std::io::BufReader::new(std::fs::File::open(&path).expect("open pcap"))).expect("read pcap");
    let _ = std::fs::remove_file(&path);
    assert_eq!(read.len(), frames.len(), "pcap round-trip must preserve packet count");

    // Host + engine wiring.
    let mut ha = HostAddrs::new();
    ha.set([IpAddr::V4(gen::HOST)]);
    let host: HostHandle = Arc::new(RwLock::new(ha));
    let counters = Arc::new(Counters::new());
    let mut bad = HashSet::new();
    bad.insert(IpAddr::V4(gen::attacker(10)));
    let intel: IntelArc = Arc::new(FixedIntel { bad });
    let cfg = tuned_config();
    let mut engine = Engine::new(&cfg, intel, None, Arc::clone(&counters), Vec::new());
    let listening: HashSet<u16> = [22u16, 80].into_iter().collect();
    engine.set_listening_ports(&listening);

    // Replay through the full pipeline.
    let mut fired: HashMap<RuleId, u32> = HashMap::new();
    let mut benign_alerts = 0;
    for (ts, frame) in &read {
        if let Some(ev) = frame_to_event(frame, *ts, &host, &counters) {
            let is_benign = ev.peer_ip == IpAddr::V4(gen::BENIGN);
            for alert in engine.process(&ev) {
                *fired.entry(alert.rule).or_default() += 1;
                if is_benign {
                    benign_alerts += 1;
                }
            }
        }
    }

    let expected = [
        RuleId::PortScan,
        RuleId::InvalidTcpFlags,
        RuleId::BruteForce,
        RuleId::SynFlood,
        RuleId::UdpFlood,
        RuleId::IcmpFlood,
        RuleId::ReflectionAmplification,
        RuleId::DnsTunnel,
        RuleId::IcmpTunnel,
        RuleId::Beaconing,
        RuleId::ThreatIntelHit,
        RuleId::SuspiciousPort,
        RuleId::NewListenerProbe,
    ];
    for r in expected {
        assert!(fired.contains_key(&r), "rule {r} did not fire; fired = {fired:?}");
    }
    assert_eq!(benign_alerts, 0, "benign peer produced false positives");
    assert!(counters.packets() >= frames.len() as u64);
    assert!(counters.alerts_total() >= 13);
}
