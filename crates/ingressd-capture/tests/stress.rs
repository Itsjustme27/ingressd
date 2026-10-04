//! Load & robustness test: replay the scenario many times, assert no panics, no
//! false positives on the benign flow, bounded memory (tracked keys capped), and
//! alert determinism under volume. This is a cheap proxy for line-rate safety;
//! the real 1 Gbit/s check is `deploy/`+`scripts/stress_test.sh` with tcpreplay.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

use ingressd_capture::frame_to_event;
use ingressd_core::config::RulesConfig;
use ingressd_core::gen;
use ingressd_core::intel::NullIntel;
use ingressd_core::metrics::Counters;
use ingressd_core::scope::HostAddrs;
use ingressd_core::Engine;

#[test]
fn stress_replay_is_bounded_and_benign_clean() {
    let frames = gen::attack_scenario();
    let mut ha = HostAddrs::new();
    ha.set([IpAddr::V4(gen::HOST)]);
    let host: Arc<RwLock<HostAddrs>> = Arc::new(RwLock::new(ha));
    let counters = Arc::new(Counters::new());

    // Small per-rule key cap to force LRU eviction under the flood volume.
    let mut cfg = RulesConfig::default();
    cfg.max_tracked_keys = 64;
    let mut engine = Engine::new(
        &cfg,
        Arc::new(NullIntel),
        None,
        Arc::clone(&counters),
        Vec::new(),
        "stress".into(),
    );

    // Replay the scenario 200x with advancing time so windows churn.
    let mut fired_by_rule: HashMap<&str, u32> = HashMap::new();
    let benign: IpAddr = IpAddr::V4(gen::BENIGN);
    let mut benign_hits = 0u32;
    let base = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);

    for round in 0..200u64 {
        let t = base + std::time::Duration::from_secs(round * 30);
        for (ts, frame) in &frames {
            // Shift each frame's timestamp forward by the round offset.
            let shifted = *ts + std::time::Duration::from_secs(round * 30);
            let _ = t;
            if let Some(ev) = frame_to_event(frame, shifted, &host, &counters) {
                let is_benign = ev.peer_ip == benign;
                for a in engine.process(&ev) {
                    *fired_by_rule.entry(a.rule.as_str()).or_default() += 1;
                    if is_benign {
                        benign_hits += 1;
                    }
                }
            }
        }
    }

    // 1. No false positives on the benign peer, ever.
    assert_eq!(benign_hits, 0, "benign peer alerted under load");

    // 2. Memory guard: per-rule key caps are honored (tracked_keys stays bounded).
    //    14 rules * (cap + cooldown map) => a few hundred at most, not frames*rules.
    let tracked = counters.tracked_keys();
    assert!(
        tracked <= 14 * (cfg.max_tracked_keys as u64) * 2,
        "tracked_keys unbounded: {tracked}"
    );

    // 3. Evictions actually happened (proves the LRU cap is exercised).
    assert!(
        counters.evictions() > 0,
        "expected LRU evictions at cap {}",
        cfg.max_tracked_keys
    );

    // 4. Core rules still fired across the run (determinism under volume).
    for r in ["port-scan", "brute-force", "syn-flood", "suspicious-port"] {
        assert!(
            fired_by_rule.contains_key(r),
            "{r} never fired: {fired_by_rule:?}"
        );
    }
}
