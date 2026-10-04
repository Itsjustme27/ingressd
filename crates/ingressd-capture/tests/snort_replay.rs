//! End-to-end test for Snort integration: a content-based Snort rule is parsed,
//! converted to an engine signature, and enforced on real frames — firing on the
//! malicious payload (case-insensitively) and NOT on benign traffic.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ingressd_capture::frame_to_event;
use ingressd_core::config::RulesConfig;
use ingressd_core::gen;
use ingressd_core::intel::NullIntel;
use ingressd_core::metrics::Counters;
use ingressd_core::scope::HostAddrs;
use ingressd_core::snort;
use ingressd_core::types::RuleId;
use ingressd_core::Engine;

const ATTACKER: Ipv4Addr = Ipv4Addr::new(45, 45, 45, 45);
const BENIGN: Ipv4Addr = Ipv4Addr::new(60, 60, 60, 60);

const RULE: &str = "alert tcp $EXTERNAL_NET any -> $HOME_NET 80 ( msg:\"EVIL beacon\"; flow:to_server,established; content:\"EVILBEACON\"; nocase; classtype:trojan-activity; sid:9000002; rev:1; )";

#[test]
fn snort_content_rule_enforces_and_spares_benign() {
    // 1. Parse + convert the Snort rule to a native signature.
    let vars = snort::VarMap::new();
    let parsed = snort::parse_str(RULE, &vars);
    assert_eq!(parsed.len(), 1, "rule should parse");
    let sig = parsed[0]
        .to_signature()
        .expect("rule should be enforceable");
    assert_eq!(sig.direction.as_deref(), Some("in"));
    assert_eq!(sig.ports, vec![80]);
    assert!(sig.nocase);

    let mut cfg = RulesConfig::default();
    cfg.signature = vec![sig];

    // 2. Build the engine with that one custom rule.
    let mut ha = HostAddrs::new();
    ha.set([IpAddr::V4(gen::HOST)]);
    let host = Arc::new(RwLock::new(ha));
    let counters = Arc::new(Counters::new());
    let mut engine = Engine::new(
        &cfg,
        Arc::new(NullIntel),
        None,
        Arc::clone(&counters),
        Vec::new(),
        "snort-test".into(),
    );

    let base = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let mut fired: HashSet<RuleId> = HashSet::new();
    let mut benign_hits = 0;

    let mut feed = |ts: SystemTime, frame: Vec<u8>| {
        if let Some(ev) = frame_to_event(&frame, ts, &host, &counters) {
            let is_benign = ev.peer_ip == IpAddr::V4(BENIGN);
            for a in engine.process(&ev) {
                fired.insert(a.rule);
                if is_benign {
                    benign_hits += 1;
                }
            }
        }
    };

    // 3. Malicious inbound on :80 with the (mixed-case) content -> must fire.
    feed(
        base,
        gen::tcp_payload(
            ATTACKER,
            gen::HOST,
            51000,
            80,
            gen::TCP_ACK,
            b"GET /c2 HTTP/1.1\r\nX-EvIlBeAcOn: yes\r\n",
        ),
    );
    // 4. Benign inbound on :80 without the content -> must NOT fire.
    feed(
        base + Duration::from_secs(1),
        gen::tcp_payload(
            BENIGN,
            gen::HOST,
            51001,
            80,
            gen::TCP_ACK,
            b"GET /index.html HTTP/1.1\r\n",
        ),
    );

    assert!(
        fired.contains(&RuleId::CustomSignature),
        "snort content rule did not fire: {fired:?}"
    );
    assert_eq!(
        benign_hits, 0,
        "benign traffic must not trigger the snort rule"
    );
    assert_eq!(
        counters.alerts_for(RuleId::CustomSignature),
        1,
        "exactly one custom alert"
    );
}
