//! Concrete detection rules. Every rule owns bounded per-peer state and applies
//! its own per-(rule,peer) cooldown before emitting an [`AlertDraft`].

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, SystemTime};

use crate::config::{
    BeaconingCfg, BruteForceCfg, CountCfg, DnsTunnelCfg, IcmpTunnelCfg, NewListenerCfg,
    PortListCfg, PortScanCfg, RateCfg, ReflectionCfg, RulesConfig, SignatureCfg, SimpleCfg,
    SynFloodCfg,
};
use crate::intel::IntelArc;
use crate::state::BoundedMap;
use crate::types::{AlertDraft, Direction, PacketEvent, Proto, RuleId, Severity, TcpFlags};

use ipnet::IpNet;

use super::{bump_window, draft, longest_label, shannon_entropy, Cooldown, Detector};

// ------------------------------- helpers -------------------------------

fn cutoff_of(now: SystemTime, win: Duration) -> SystemTime {
    now.checked_sub(win).unwrap_or(SystemTime::UNIX_EPOCH)
}

fn prune_only(deq: &mut VecDeque<SystemTime>, now: SystemTime, win: Duration) {
    let cutoff = cutoff_of(now, win);
    while let Some(&front) = deq.front() {
        if front <= cutoff {
            deq.pop_front();
        } else {
            break;
        }
    }
}

fn combo_name(f: &TcpFlags) -> &'static str {
    if f.is_null() {
        "NULL"
    } else if f.is_xmas() {
        "XMAS"
    } else if f.is_syn_fin() {
        "SYN+FIN"
    } else if f.is_syn_rst() {
        "SYN+RST"
    } else if f.is_fin_only() {
        "FIN-only"
    } else {
        "invalid"
    }
}

fn join_ports(set: &HashSet<u16>) -> String {
    let mut v: Vec<u16> = set.iter().copied().collect();
    v.sort_unstable();
    let head: Vec<String> = v.iter().take(10).map(|p| p.to_string()).collect();
    let mut s = head.join(",");
    if v.len() > 10 {
        s.push_str(&format!(",+{}", v.len() - 10));
    }
    s
}

/// Substring search over a byte slice.
fn contains(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || hay.len() < needle.len() {
        return false;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

/// Snort-style content match honoring `offset` (start) and `depth` (window size)
/// relative to the payload, with optional ASCII case-folding.
fn content_match(
    payload: &[u8],
    needle: &[u8],
    nocase: bool,
    offset: Option<usize>,
    depth: Option<usize>,
) -> bool {
    if needle.is_empty() {
        return false;
    }
    let start = offset.unwrap_or(0).min(payload.len());
    let end = match depth {
        Some(d) => start.saturating_add(d).min(payload.len()),
        None => payload.len(),
    };
    if end <= start {
        return false;
    }
    let hay = &payload[start..end];
    if nocase {
        contains(&hay.to_ascii_lowercase(), &needle.to_ascii_lowercase())
    } else {
        contains(hay, needle)
    }
}

// ============================ 1. port-scan ============================

pub struct PortScanDetector {
    min: usize,
    win: Duration,
    win_s: u64,
    sev: Severity,
    state: BoundedMap<IpAddr, HashMap<(IpAddr, u16), SystemTime>>,
    cooldown: Cooldown<IpAddr>,
}

impl PortScanDetector {
    pub fn new(cfg: &PortScanCfg, cap: usize) -> Self {
        PortScanDetector {
            min: cfg.min_targets,
            win: Duration::from_secs(cfg.window_s),
            win_s: cfg.window_s,
            sev: cfg.severity,
            state: BoundedMap::new(cap),
            cooldown: Cooldown::new(cap, Duration::from_secs(cfg.cooldown_s)),
        }
    }
}

impl Detector for PortScanDetector {
    fn id(&self) -> RuleId {
        RuleId::PortScan
    }
    fn on_event(&mut self, ev: &PacketEvent, out: &mut Vec<AlertDraft>) {
        if !(ev.inbound() && ev.is_new_tcp_connection()) {
            return;
        }
        let Some(dport) = ev.dst_port else { return };
        let peer = ev.peer_ip;
        let now = ev.ts;
        let (min, win, sev, win_s) = (self.min, self.win, self.sev, self.win_s);
        let cutoff = cutoff_of(now, win);

        let m = self.state.get_or_insert_with(peer, HashMap::new);
        m.insert((ev.dst_ip, dport), now);
        m.retain(|_, t| *t > cutoff);
        let distinct = m.len();

        if distinct >= min {
            let uniq_ips: HashSet<IpAddr> = m.keys().map(|(ip, _)| *ip).collect();
            let uniq_ports: HashSet<u16> = m.keys().map(|(_, p)| *p).collect();
            let kind = if uniq_ips.len() >= min && uniq_ports.len() >= min {
                "horizontal+vertical"
            } else if uniq_ips.len() >= min {
                "horizontal"
            } else {
                "vertical"
            };
            if self.cooldown.allow(&peer, now) {
                let detail = format!(
                    "{kind} scan: {distinct} targets across {} hosts / {} ports in {win_s}s",
                    uniq_ips.len(),
                    uniq_ports.len()
                );
                out.push(draft(
                    ev,
                    RuleId::PortScan,
                    sev,
                    detail,
                    distinct as u64,
                    win_s,
                ));
            }
            m.clear();
        }
    }
    fn tracked_keys(&self) -> usize {
        self.state.len() + self.cooldown.len()
    }
}

// ======================= 2. invalid-tcp-flags =========================

pub struct InvalidFlagsDetector {
    threshold: usize,
    win: Duration,
    win_s: u64,
    sev: Severity,
    state: BoundedMap<IpAddr, VecDeque<SystemTime>>,
    cooldown: Cooldown<IpAddr>,
}

impl InvalidFlagsDetector {
    pub fn new(cfg: &CountCfg, cap: usize) -> Self {
        InvalidFlagsDetector {
            threshold: cfg.threshold,
            win: Duration::from_secs(cfg.window_s),
            win_s: cfg.window_s,
            sev: cfg.severity,
            state: BoundedMap::new(cap),
            cooldown: Cooldown::new(cap, Duration::from_secs(cfg.cooldown_s)),
        }
    }
}

impl Detector for InvalidFlagsDetector {
    fn id(&self) -> RuleId {
        RuleId::InvalidTcpFlags
    }
    fn on_event(&mut self, ev: &PacketEvent, out: &mut Vec<AlertDraft>) {
        let Some(flags) = &ev.tcp_flags else { return };
        if !flags.is_invalid_combo() {
            return;
        }
        let name = combo_name(flags);
        let peer = ev.peer_ip;
        let now = ev.ts;
        let (thr, win, sev, win_s) = (self.threshold, self.win, self.sev, self.win_s);
        let deq = self.state.get_or_insert_with(peer, VecDeque::new);
        let count = bump_window(deq, now, win);
        if count >= thr as u64 && self.cooldown.allow(&peer, now) {
            let detail = format!("invalid TCP flags ({name}): {count} packets in {win_s}s");
            out.push(draft(
                ev,
                RuleId::InvalidTcpFlags,
                sev,
                detail,
                count,
                win_s,
            ));
        }
    }
    fn tracked_keys(&self) -> usize {
        self.state.len() + self.cooldown.len()
    }
}

// =========================== 3. brute-force ===========================

pub struct BruteForceDetector {
    threshold: usize,
    win: Duration,
    win_s: u64,
    sev: Severity,
    ports: HashSet<u16>,
    state: BoundedMap<IpAddr, (VecDeque<SystemTime>, HashSet<u16>)>,
    cooldown: Cooldown<IpAddr>,
}

impl BruteForceDetector {
    pub fn new(cfg: &BruteForceCfg, cap: usize) -> Self {
        BruteForceDetector {
            threshold: cfg.threshold,
            win: Duration::from_secs(cfg.window_s),
            win_s: cfg.window_s,
            sev: cfg.severity,
            ports: cfg.ports.iter().copied().collect(),
            state: BoundedMap::new(cap),
            cooldown: Cooldown::new(cap, Duration::from_secs(cfg.cooldown_s)),
        }
    }
}

impl Detector for BruteForceDetector {
    fn id(&self) -> RuleId {
        RuleId::BruteForce
    }
    fn on_event(&mut self, ev: &PacketEvent, out: &mut Vec<AlertDraft>) {
        if !(ev.inbound() && ev.is_new_tcp_connection()) {
            return;
        }
        let Some(dport) = ev.dst_port else { return };
        if !self.ports.contains(&dport) {
            return;
        }
        let peer = ev.peer_ip;
        let now = ev.ts;
        let (thr, win, sev, win_s) = (self.threshold, self.win, self.sev, self.win_s);
        let entry = self
            .state
            .get_or_insert_with(peer, || (VecDeque::new(), HashSet::new()));
        let count = bump_window(&mut entry.0, now, win);
        entry.1.insert(dport);
        if count >= thr as u64 && self.cooldown.allow(&peer, now) {
            let detail = format!(
                "brute force: {count} new connections to auth ports [{}] in {win_s}s",
                join_ports(&entry.1)
            );
            out.push(draft(ev, RuleId::BruteForce, sev, detail, count, win_s));
            entry.0.clear();
            entry.1.clear();
        }
    }
    fn tracked_keys(&self) -> usize {
        self.state.len() + self.cooldown.len()
    }
}

// ============================ 4. syn-flood ============================

pub struct SynFloodDetector {
    threshold: usize,
    win: Duration,
    win_s: u64,
    sev: Severity,
    max_ratio: f64,
    state: BoundedMap<(IpAddr, u16), (VecDeque<SystemTime>, VecDeque<SystemTime>)>,
    cooldown: Cooldown<(IpAddr, u16)>,
}

impl SynFloodDetector {
    pub fn new(cfg: &SynFloodCfg, cap: usize) -> Self {
        SynFloodDetector {
            threshold: cfg.threshold,
            win: Duration::from_secs(cfg.window_s),
            win_s: cfg.window_s,
            sev: cfg.severity,
            max_ratio: cfg.max_completion_ratio,
            state: BoundedMap::new(cap),
            cooldown: Cooldown::new(cap, Duration::from_secs(cfg.cooldown_s)),
        }
    }
}

impl Detector for SynFloodDetector {
    fn id(&self) -> RuleId {
        RuleId::SynFlood
    }
    fn on_event(&mut self, ev: &PacketEvent, out: &mut Vec<AlertDraft>) {
        let now = ev.ts;
        let win = self.win;
        // Count our SYN-ACK replies (completions) toward the target endpoint.
        if ev.direction == crate::types::Direction::Outbound
            && ev.proto == Proto::Tcp
            && ev.tcp_flags.map(|f| f.syn && f.ack).unwrap_or(false)
        {
            if let (Some(lip), Some(lport)) = (ev.src_ip, ev.src_port) {
                let key = (lip, lport);
                let entry = self
                    .state
                    .get_or_insert_with(key, || (VecDeque::new(), VecDeque::new()));
                bump_window(&mut entry.1, now, win);
            }
            return;
        }
        // Otherwise: inbound SYN toward a local endpoint.
        if !(ev.inbound() && ev.is_new_tcp_connection()) {
            return;
        }
        let Some(dport) = ev.dst_port else { return };
        let key = (ev.dst_ip, dport);
        let (thr, sev, win_s, max_ratio) = (self.threshold, self.sev, self.win_s, self.max_ratio);
        let entry = self
            .state
            .get_or_insert_with(key, || (VecDeque::new(), VecDeque::new()));
        let syns = bump_window(&mut entry.0, now, win);
        prune_only(&mut entry.1, now, win);
        let synacks = entry.1.len() as u64;
        if syns >= thr as u64 {
            let ratio = if syns > 0 {
                synacks as f64 / syns as f64
            } else {
                1.0
            };
            if ratio < max_ratio && self.cooldown.allow(&key, now) {
                let detail = format!(
                    "SYN flood on {}:{dport}: {syns} SYNs, {} SYN-ACKs, completion ratio {ratio:.2} in {win_s}s",
                    ev.dst_ip, synacks
                );
                out.push(draft(ev, RuleId::SynFlood, sev, detail, syns, win_s));
            }
        }
    }
    fn tracked_keys(&self) -> usize {
        self.state.len() + self.cooldown.len()
    }
}

// ==================== 5/6. udp-flood & icmp-flood =====================

#[derive(Clone, Copy, PartialEq, Eq)]
enum FloodKind {
    Udp,
    Icmp,
}

pub struct TargetRateDetector {
    kind: FloodKind,
    threshold: usize,
    win: Duration,
    win_s: u64,
    sev: Severity,
    state: BoundedMap<(IpAddr, u16), VecDeque<SystemTime>>,
    cooldown: Cooldown<(IpAddr, u16)>,
}

impl TargetRateDetector {
    pub fn new(kind: RuleId, cfg: &RateCfg, cap: usize) -> Self {
        TargetRateDetector {
            kind: if kind == RuleId::UdpFlood {
                FloodKind::Udp
            } else {
                FloodKind::Icmp
            },
            threshold: cfg.threshold,
            win: Duration::from_secs(cfg.window_s),
            win_s: cfg.window_s,
            sev: cfg.severity,
            state: BoundedMap::new(cap),
            cooldown: Cooldown::new(cap, Duration::from_secs(cfg.cooldown_s)),
        }
    }
}

impl Detector for TargetRateDetector {
    fn id(&self) -> RuleId {
        match self.kind {
            FloodKind::Udp => RuleId::UdpFlood,
            FloodKind::Icmp => RuleId::IcmpFlood,
        }
    }
    fn on_event(&mut self, ev: &PacketEvent, out: &mut Vec<AlertDraft>) {
        if !ev.inbound() {
            return;
        }
        let key = match self.kind {
            FloodKind::Udp if ev.proto == Proto::Udp => (ev.dst_ip, ev.dst_port.unwrap_or(0)),
            FloodKind::Icmp if ev.proto == Proto::Icmp => (ev.dst_ip, 0),
            _ => return,
        };
        let now = ev.ts;
        let (thr, win, sev, win_s) = (self.threshold, self.win, self.sev, self.win_s);
        let count = {
            let deq = self.state.get_or_insert_with(key, VecDeque::new);
            bump_window(deq, now, win)
        };
        if count >= thr as u64 && self.cooldown.allow(&key, now) {
            let name = match self.kind {
                FloodKind::Udp => "UDP",
                FloodKind::Icmp => "ICMP",
            };
            let detail = format!("{name} flood on {}: {count} pkts in {win_s}s", key.0);
            out.push(draft(ev, self.id(), sev, detail, count, win_s));
        }
    }
    fn tracked_keys(&self) -> usize {
        self.state.len() + self.cooldown.len()
    }
}

// ==================== 7. reflection-amplification =====================

pub struct ReflectionDetector {
    ports: HashSet<u16>,
    min_bytes: usize,
    threshold: usize,
    win: Duration,
    win_s: u64,
    sev: Severity,
    requests: BoundedMap<(IpAddr, u16), SystemTime>,
    unsolicited: BoundedMap<IpAddr, VecDeque<SystemTime>>,
    cooldown: Cooldown<IpAddr>,
}

impl ReflectionDetector {
    pub fn new(cfg: &ReflectionCfg, cap: usize) -> Self {
        ReflectionDetector {
            ports: cfg.ports.iter().copied().collect(),
            min_bytes: cfg.min_response_bytes,
            threshold: cfg.threshold,
            win: Duration::from_secs(cfg.window_s),
            win_s: cfg.window_s,
            sev: cfg.severity,
            requests: BoundedMap::new(cap),
            unsolicited: BoundedMap::new(cap),
            cooldown: Cooldown::new(cap, Duration::from_secs(cfg.cooldown_s)),
        }
    }
}

impl Detector for ReflectionDetector {
    fn id(&self) -> RuleId {
        RuleId::ReflectionAmplification
    }
    fn on_event(&mut self, ev: &PacketEvent, out: &mut Vec<AlertDraft>) {
        if ev.proto != Proto::Udp {
            return;
        }
        let now = ev.ts;
        match ev.direction {
            crate::types::Direction::Outbound => {
                // We sent a UDP request to a reflector service: remember it so a
                // later reply from that peer:port is considered solicited.
                if let Some(dport) = ev.dst_port {
                    if self.ports.contains(&dport) {
                        self.requests.insert((ev.peer_ip, dport), now);
                    }
                }
            }
            crate::types::Direction::Inbound => {
                let Some(sport) = ev.src_port else { return };
                if !self.ports.contains(&sport) {
                    return;
                }
                // Was there a recent matching outbound request to peer:sport?
                let solicited = self
                    .requests
                    .get(&(ev.peer_ip, sport))
                    .map(|t| {
                        now.duration_since(*t)
                            .map(|d| d <= self.win)
                            .unwrap_or(false)
                    })
                    .unwrap_or(false);
                if solicited || ev.payload_len < self.min_bytes {
                    return;
                }
                let peer = ev.peer_ip;
                let (thr, win, sev, win_s) = (self.threshold, self.win, self.sev, self.win_s);
                let count = {
                    let deq = self.unsolicited.get_or_insert_with(peer, VecDeque::new);
                    bump_window(deq, now, win)
                };
                if count >= thr as u64 && self.cooldown.allow(&peer, now) {
                    let detail = format!(
                        "reflection/amplification: {count} unsolicited {sport}-source responses >= {}B in {win_s}s",
                        self.min_bytes
                    );
                    out.push(draft(
                        ev,
                        RuleId::ReflectionAmplification,
                        sev,
                        detail,
                        count,
                        win_s,
                    ));
                }
            }
        }
    }
    fn tracked_keys(&self) -> usize {
        self.requests.len() + self.unsolicited.len() + self.cooldown.len()
    }
}

// ============================ 8. dns-tunnel ===========================

#[derive(Default)]
struct DnsState {
    susp: VecDeque<SystemTime>,
    txt: VecDeque<SystemTime>,
    qnames: HashSet<String>,
}

pub struct DnsTunnelDetector {
    entropy: f64,
    qlen: usize,
    llabel: usize,
    subthr: usize,
    txtthr: usize,
    win: Duration,
    win_s: u64,
    sev: Severity,
    state: BoundedMap<IpAddr, DnsState>,
    cooldown: Cooldown<IpAddr>,
}

impl DnsTunnelDetector {
    pub fn new(cfg: &DnsTunnelCfg, cap: usize) -> Self {
        DnsTunnelDetector {
            entropy: cfg.entropy_threshold,
            qlen: cfg.qname_len_threshold,
            llabel: cfg.label_len_threshold,
            subthr: cfg.subdomain_threshold,
            txtthr: cfg.txt_threshold,
            win: Duration::from_secs(cfg.window_s),
            win_s: cfg.window_s,
            sev: cfg.severity,
            state: BoundedMap::new(cap),
            cooldown: Cooldown::new(cap, Duration::from_secs(cfg.cooldown_s)),
        }
    }
}

impl Detector for DnsTunnelDetector {
    fn id(&self) -> RuleId {
        RuleId::DnsTunnel
    }
    fn on_event(&mut self, ev: &PacketEvent, out: &mut Vec<AlertDraft>) {
        let Some(q) = &ev.dns else { return };
        if q.is_response {
            return;
        }
        let peer = ev.peer_ip;
        let now = ev.ts;
        let (ent_thr, qlen_thr, ll_thr, subthr, txtthr, win, sev, win_s) = (
            self.entropy,
            self.qlen,
            self.llabel,
            self.subthr,
            self.txtthr,
            self.win,
            self.sev,
            self.win_s,
        );

        let ent = shannon_entropy(&q.qname);
        let is_susp =
            ent >= ent_thr || q.qname.len() >= qlen_thr || longest_label(&q.qname) >= ll_thr;
        let is_txt = q.qtype == 16 || q.qtype == 10; // TXT / NULL
        let qname = q.qname.clone();

        let reason = {
            let st = self.state.get_or_insert_with(peer, DnsState::default);
            if is_susp {
                bump_window(&mut st.susp, now, win);
            }
            if is_txt {
                bump_window(&mut st.txt, now, win);
            }
            st.qnames.insert(qname);
            let susp = st.susp.len();
            let txt = st.txt.len();
            let uniq = st.qnames.len();

            if uniq >= subthr {
                // Bound memory regardless of whether the cooldown lets us alert.
                st.qnames.clear();
            }
            let reason = if txt >= txtthr {
                Some(format!("high TXT/NULL volume: {txt} queries"))
            } else if uniq >= subthr {
                Some(format!("many unique subdomains: {uniq}"))
            } else if susp >= 5 {
                Some(format!(
                    "{susp} high-entropy/long qnames (last entropy {ent:.1})"
                ))
            } else {
                None
            };
            reason
        };

        if let Some(reason) = reason {
            if self.cooldown.allow(&peer, now) {
                let detail = format!("possible DNS tunnel: {reason} in {win_s}s");
                out.push(draft(ev, RuleId::DnsTunnel, sev, detail, 0, win_s));
            }
        }
    }
    fn tracked_keys(&self) -> usize {
        self.state.len() + self.cooldown.len()
    }
}

// =========================== 9. icmp-tunnel ===========================

pub struct IcmpTunnelDetector {
    max_payload: usize,
    threshold: usize,
    win: Duration,
    win_s: u64,
    sev: Severity,
    state: BoundedMap<IpAddr, VecDeque<SystemTime>>,
    cooldown: Cooldown<IpAddr>,
}

impl IcmpTunnelDetector {
    pub fn new(cfg: &IcmpTunnelCfg, cap: usize) -> Self {
        IcmpTunnelDetector {
            max_payload: cfg.max_payload,
            threshold: cfg.threshold,
            win: Duration::from_secs(cfg.window_s),
            win_s: cfg.window_s,
            sev: cfg.severity,
            state: BoundedMap::new(cap),
            cooldown: Cooldown::new(cap, Duration::from_secs(cfg.cooldown_s)),
        }
    }
}

impl Detector for IcmpTunnelDetector {
    fn id(&self) -> RuleId {
        RuleId::IcmpTunnel
    }
    fn on_event(&mut self, ev: &PacketEvent, out: &mut Vec<AlertDraft>) {
        let Some(icmp) = &ev.icmp else { return };
        if !(ev.proto == Proto::Icmp && icmp.echo && icmp.payload_len >= self.max_payload) {
            return;
        }
        let peer = ev.peer_ip;
        let now = ev.ts;
        let (thr, win, sev, win_s, maxlen) = (
            self.threshold,
            self.win,
            self.sev,
            self.win_s,
            self.max_payload,
        );
        let count = {
            let deq = self.state.get_or_insert_with(peer, VecDeque::new);
            bump_window(deq, now, win)
        };
        if count >= thr as u64 && self.cooldown.allow(&peer, now) {
            let detail = format!(
                "possible ICMP tunnel: {count} oversized echo payloads >= {maxlen}B in {win_s}s"
            );
            out.push(draft(ev, RuleId::IcmpTunnel, sev, detail, count, win_s));
        }
    }
    fn tracked_keys(&self) -> usize {
        self.state.len() + self.cooldown.len()
    }
}

// ============================ 10. beaconing ===========================

pub struct BeaconingDetector {
    min_samples: usize,
    max_cv: f64,
    win: Duration,
    win_s: u64,
    sev: Severity,
    max_samples: usize,
    state: BoundedMap<IpAddr, VecDeque<SystemTime>>,
    cooldown: Cooldown<IpAddr>,
}

impl BeaconingDetector {
    pub fn new(cfg: &BeaconingCfg, cap: usize) -> Self {
        BeaconingDetector {
            min_samples: cfg.min_samples,
            max_cv: cfg.max_jitter_cv,
            win: Duration::from_secs(cfg.window_s),
            win_s: cfg.window_s,
            sev: cfg.severity,
            max_samples: cfg.max_samples,
            state: BoundedMap::new(cap),
            cooldown: Cooldown::new(cap, Duration::from_secs(cfg.cooldown_s)),
        }
    }
}

/// Population coefficient of variation of intervals between consecutive times.
/// Returns `None` when there are too few samples or the mean is non-positive.
fn cv_of(deq: &VecDeque<SystemTime>) -> Option<(f64, f64)> {
    if deq.len() < 3 {
        return None;
    }
    let mut intervals = Vec::with_capacity(deq.len() - 1);
    let mut prev: Option<SystemTime> = None;
    for &t in deq {
        if let Some(p) = prev {
            let d = t
                .checked_duration_since(p)
                .map(|d| d.as_secs_f64())
                .unwrap_or(0.0);
            intervals.push(d);
        }
        prev = Some(t);
    }
    let n = intervals.len() as f64;
    let mean = intervals.iter().sum::<f64>() / n;
    if mean <= 0.0 {
        return None;
    }
    let var = intervals.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
    let sd = var.sqrt();
    Some((sd / mean, mean))
}

impl Detector for BeaconingDetector {
    fn id(&self) -> RuleId {
        RuleId::Beaconing
    }
    fn on_event(&mut self, ev: &PacketEvent, out: &mut Vec<AlertDraft>) {
        if !(ev.direction == crate::types::Direction::Outbound && ev.is_new_tcp_connection()) {
            return;
        }
        let peer = ev.peer_ip;
        let now = ev.ts;
        let (min_samples, max_cv, win, sev, win_s, max_samples) = (
            self.min_samples,
            self.max_cv,
            self.win,
            self.sev,
            self.win_s,
            self.max_samples,
        );

        let result = {
            let deq = self.state.get_or_insert_with(peer, VecDeque::new);
            deq.push_back(now);
            while deq.len() > max_samples {
                deq.pop_front();
            }
            prune_only(deq, now, win);
            if deq.len() >= min_samples {
                cv_of(deq).and_then(|(cv, mean)| {
                    if cv <= max_cv {
                        Some((cv, mean, deq.len()))
                    } else {
                        None
                    }
                })
            } else {
                None
            }
        };

        if let Some((cv, mean, n)) = result {
            if self.cooldown.allow(&peer, now) {
                let detail = format!(
                    "beaconing to {peer}: {n} connections, mean interval {mean:.1}s, jitter CV {cv:.3} (<= {max_cv})"
                );
                out.push(draft(ev, RuleId::Beaconing, sev, detail, n as u64, win_s));
                if let Some(deq) = self.state.get_mut(&peer) {
                    deq.clear();
                }
            }
        }
    }
    fn tracked_keys(&self) -> usize {
        self.state.len() + self.cooldown.len()
    }
}

// ========================= 11. threat-intel-hit =======================

pub struct ThreatIntelDetector {
    intel: IntelArc,
    sev: Severity,
    cooldown: Cooldown<IpAddr>,
}

impl ThreatIntelDetector {
    pub fn new(cfg: &SimpleCfg, cap: usize, intel: IntelArc) -> Self {
        ThreatIntelDetector {
            intel,
            sev: cfg.severity,
            cooldown: Cooldown::new(cap, Duration::from_secs(cfg.cooldown_s)),
        }
    }
}

impl Detector for ThreatIntelDetector {
    fn id(&self) -> RuleId {
        RuleId::ThreatIntelHit
    }
    fn on_event(&mut self, ev: &PacketEvent, out: &mut Vec<AlertDraft>) {
        let peer = ev.peer_ip;
        if let Some(hit) = crate::intel::ThreatIntelSource::lookup(&*self.intel, peer) {
            if self.cooldown.allow(&peer, ev.ts) {
                let src = hit.source.unwrap_or_else(|| "blocklist".to_string());
                let detail = format!("peer {peer} matches threat feed '{src}'");
                out.push(draft(ev, RuleId::ThreatIntelHit, self.sev, detail, 1, 0));
            }
        }
    }
    fn tracked_keys(&self) -> usize {
        self.cooldown.len()
    }
}

// ========================= 12. suspicious-port ========================

pub struct SuspiciousPortDetector {
    ports: HashSet<u16>,
    sev: Severity,
    cooldown: Cooldown<IpAddr>,
}

impl SuspiciousPortDetector {
    pub fn new(cfg: &PortListCfg, cap: usize) -> Self {
        SuspiciousPortDetector {
            ports: cfg.ports.iter().copied().collect(),
            sev: cfg.severity,
            cooldown: Cooldown::new(cap, Duration::from_secs(cfg.cooldown_s)),
        }
    }
}

impl Detector for SuspiciousPortDetector {
    fn id(&self) -> RuleId {
        RuleId::SuspiciousPort
    }
    fn on_event(&mut self, ev: &PacketEvent, out: &mut Vec<AlertDraft>) {
        let hit = ev
            .src_port
            .filter(|p| self.ports.contains(p))
            .or_else(|| ev.dst_port.filter(|p| self.ports.contains(p)));
        if let Some(port) = hit {
            let peer = ev.peer_ip;
            if self.cooldown.allow(&peer, ev.ts) {
                let detail = format!("traffic on suspicious/backdoor port {port}");
                out.push(draft(ev, RuleId::SuspiciousPort, self.sev, detail, 1, 0));
            }
        }
    }
    fn tracked_keys(&self) -> usize {
        self.cooldown.len()
    }
}

// ======================= 13. new-listener-probe =======================

pub struct NewListenerDetector {
    min_sources: usize,
    win: Duration,
    win_s: u64,
    sev: Severity,
    listening: HashSet<u16>,
    state: BoundedMap<u16, HashMap<IpAddr, SystemTime>>,
    cooldown: Cooldown<u16>,
}

impl NewListenerDetector {
    pub fn new(cfg: &NewListenerCfg, cap: usize) -> Self {
        NewListenerDetector {
            min_sources: cfg.min_sources,
            win: Duration::from_secs(cfg.window_s),
            win_s: cfg.window_s,
            sev: cfg.severity,
            listening: HashSet::new(),
            state: BoundedMap::new(cap),
            cooldown: Cooldown::new(cap, Duration::from_secs(cfg.cooldown_s)),
        }
    }
}

impl Detector for NewListenerDetector {
    fn id(&self) -> RuleId {
        RuleId::NewListenerProbe
    }
    fn on_event(&mut self, ev: &PacketEvent, out: &mut Vec<AlertDraft>) {
        // Only meaningful once we know what is listening; an unknown listener set
        // would flag every port, so skip.
        if self.listening.is_empty() {
            return;
        }
        if !(ev.inbound() && ev.is_new_tcp_connection()) {
            return;
        }
        let Some(dport) = ev.dst_port else { return };
        if self.listening.contains(&dport) {
            return; // it is a real service, not a probe of nothing
        }
        let now = ev.ts;
        let (min, win, sev, win_s) = (self.min_sources, self.win, self.sev, self.win_s);
        let cutoff = cutoff_of(now, win);
        let count = {
            let m = self.state.get_or_insert_with(dport, HashMap::new);
            m.insert(ev.peer_ip, now);
            m.retain(|_, t| *t > cutoff);
            m.len()
        };
        if count >= min && self.cooldown.allow(&dport, now) {
            let detail =
                format!("{count} distinct sources probing un-listened port {dport} in {win_s}s");
            out.push(draft(
                ev,
                RuleId::NewListenerProbe,
                sev,
                detail,
                count as u64,
                win_s,
            ));
            if let Some(m) = self.state.get_mut(&dport) {
                m.clear();
            }
        }
    }
    fn set_listening_ports(&mut self, ports: &HashSet<u16>) {
        self.listening = ports.clone();
    }
    fn tracked_keys(&self) -> usize {
        self.state.len() + self.cooldown.len()
    }
}

// ======================= 14. custom-signature ======================

/// One compiled signature with parsed protocol/direction/port/CIDR constraints.
struct CompiledSig {
    name: String,
    proto: Option<Proto>,
    dir: Option<Direction>,
    ports: Vec<u16>,
    nets: Vec<IpNet>,
    severity: Severity,
    content: Option<Vec<u8>>,
    nocase: bool,
    depth: Option<usize>,
    offset: Option<usize>,
    label: String,
}

/// User-defined detection signatures. A signature alerts when a packet matches
/// every constraint it declares; each is independently cooldown-limited per
/// (peer, name).
pub struct CustomSignatureDetector {
    sigs: Vec<CompiledSig>,
    cooldown: Cooldown<(IpAddr, String)>,
    suppress_after: Option<u64>,
    emitted: BoundedMap<(IpAddr, String), u64>,
}

fn parse_proto(s: &str) -> Option<Proto> {
    match s {
        "tcp" => Some(Proto::Tcp),
        "udp" => Some(Proto::Udp),
        "icmp" => Some(Proto::Icmp),
        _ => None,
    }
}

fn parse_dir(s: &str) -> Option<Direction> {
    match s {
        "in" => Some(Direction::Inbound),
        "out" => Some(Direction::Outbound),
        _ => None,
    }
}

impl CustomSignatureDetector {
    pub fn new(cfg: &SimpleCfg, sigs: &[SignatureCfg], cap: usize) -> Self {
        let mut compiled = Vec::new();
        for s in sigs {
            if !s.enabled || s.name.trim().is_empty() {
                continue;
            }
            compiled.push(CompiledSig {
                name: s.name.clone(),
                proto: s.protocol.as_deref().and_then(parse_proto),
                dir: s.direction.as_deref().and_then(parse_dir),
                ports: s.ports.clone(),
                nets: s
                    .peer_cidr
                    .iter()
                    .filter_map(|c| c.parse::<IpNet>().ok())
                    .collect(),
                severity: s.severity.unwrap_or(cfg.severity),
                content: s.content.as_deref().map(crate::snort::decode_content),
                nocase: s.nocase,
                depth: s.depth,
                offset: s.offset,
                label: match (&s.msg, s.sid) {
                    (Some(m), Some(id)) => format!("sid {id}: {m}"),
                    (Some(m), None) => m.clone(),
                    (None, Some(id)) => format!("sid {id}"),
                    (None, None) => s.name.clone(),
                },
            });
        }
        CustomSignatureDetector {
            sigs: compiled,
            cooldown: Cooldown::new(cap, Duration::from_secs(cfg.cooldown_s)),
            suppress_after: cfg.suppress_after,
            emitted: BoundedMap::new(cap),
        }
    }

    pub fn sigs_count(&self) -> usize {
        self.sigs.len()
    }
}

impl Detector for CustomSignatureDetector {
    fn id(&self) -> RuleId {
        RuleId::CustomSignature
    }
    fn on_event(&mut self, ev: &PacketEvent, out: &mut Vec<AlertDraft>) {
        for s in self.sigs.iter() {
            if let Some(p) = &s.proto {
                if &ev.proto != p {
                    continue;
                }
            }
            if let Some(d) = &s.dir {
                if &ev.direction != d {
                    continue;
                }
            }
            if !s.ports.is_empty() {
                let hit = ev.src_port.is_some_and(|p| s.ports.contains(&p))
                    || ev.dst_port.is_some_and(|p| s.ports.contains(&p));
                if !hit {
                    continue;
                }
            }
            if !s.nets.is_empty() && !s.nets.iter().any(|n| n.contains(ev.peer_ip)) {
                continue;
            }
            if let Some(needle) = &s.content {
                if !content_match(&ev.payload, needle, s.nocase, s.offset, s.depth) {
                    continue;
                }
            }
            let key = (ev.peer_ip, s.name.clone());
            // Feedback suppression: stop re-alerting a persistently-fired key.
            let already = *self.emitted.get(&key).unwrap_or(&0);
            if let Some(n) = self.suppress_after {
                if already >= n {
                    continue;
                }
            }
            if self.cooldown.allow(&key, ev.ts) {
                self.emitted.insert(key, already + 1);
                let detail = format!(
                    "signature '{}' [{}] matched {} {} from {}",
                    s.name, s.label, ev.proto, ev.direction, ev.peer_ip
                );
                out.push(draft(ev, RuleId::CustomSignature, s.severity, detail, 1, 0));
            }
        }
    }
    fn tracked_keys(&self) -> usize {
        self.cooldown.len()
    }
}

// ============================ registry ================================

/// Assemble the enabled detectors described by `cfg`.
pub fn build_detectors(cfg: &RulesConfig, intel: IntelArc) -> Vec<Box<dyn Detector>> {
    let cap = cfg.max_tracked_keys;
    let mut v: Vec<Box<dyn Detector>> = Vec::new();
    if cfg.port_scan.enabled {
        v.push(Box::new(PortScanDetector::new(&cfg.port_scan, cap)));
    }
    if cfg.invalid_tcp_flags.enabled {
        v.push(Box::new(InvalidFlagsDetector::new(
            &cfg.invalid_tcp_flags,
            cap,
        )));
    }
    if cfg.brute_force.enabled {
        v.push(Box::new(BruteForceDetector::new(&cfg.brute_force, cap)));
    }
    if cfg.syn_flood.enabled {
        v.push(Box::new(SynFloodDetector::new(&cfg.syn_flood, cap)));
    }
    if cfg.udp_flood.enabled {
        v.push(Box::new(TargetRateDetector::new(
            RuleId::UdpFlood,
            &cfg.udp_flood,
            cap,
        )));
    }
    if cfg.icmp_flood.enabled {
        v.push(Box::new(TargetRateDetector::new(
            RuleId::IcmpFlood,
            &cfg.icmp_flood,
            cap,
        )));
    }
    if cfg.reflection.enabled {
        v.push(Box::new(ReflectionDetector::new(&cfg.reflection, cap)));
    }
    if cfg.dns_tunnel.enabled {
        v.push(Box::new(DnsTunnelDetector::new(&cfg.dns_tunnel, cap)));
    }
    if cfg.icmp_tunnel.enabled {
        v.push(Box::new(IcmpTunnelDetector::new(&cfg.icmp_tunnel, cap)));
    }
    if cfg.beaconing.enabled {
        v.push(Box::new(BeaconingDetector::new(&cfg.beaconing, cap)));
    }
    if cfg.threat_intel.enabled {
        v.push(Box::new(ThreatIntelDetector::new(
            &cfg.threat_intel,
            cap,
            intel,
        )));
    }
    if cfg.suspicious_port.enabled {
        v.push(Box::new(SuspiciousPortDetector::new(
            &cfg.suspicious_port,
            cap,
        )));
    }
    if cfg.new_listener.enabled {
        v.push(Box::new(NewListenerDetector::new(&cfg.new_listener, cap)));
    }
    if cfg.custom_signature.enabled && !cfg.signature.is_empty() {
        let d = CustomSignatureDetector::new(&cfg.custom_signature, &cfg.signature, cap);
        if d.sigs_count() > 0 {
            v.push(Box::new(d));
        }
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Direction;

    fn ev_syn(peer: IpAddr, local: IpAddr, dport: u16, ts: SystemTime) -> PacketEvent {
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
    fn port_scan_fires_after_threshold() {
        let cfg = PortScanCfg {
            min_targets: 5,
            window_s: 60,
            cooldown_s: 300,
            severity: Severity::Medium,
            enabled: true,
        };
        let mut d = PortScanDetector::new(&cfg, 1000);
        let peer: IpAddr = "203.0.113.9".parse().unwrap();
        let local: IpAddr = "198.51.100.5".parse().unwrap();
        let base = SystemTime::now();
        let mut out = Vec::new();
        for p in 0..5u16 {
            d.on_event(&ev_syn(peer, local, 100 + p, base), &mut out);
        }
        assert_eq!(
            out.len(),
            1,
            "expected exactly one scan alert, got {}",
            out.len()
        );
        assert_eq!(out[0].rule, RuleId::PortScan);
    }

    #[test]
    fn port_scan_below_threshold_silent() {
        let cfg = PortScanCfg {
            min_targets: 5,
            window_s: 60,
            cooldown_s: 300,
            severity: Severity::Medium,
            enabled: true,
        };
        let mut d = PortScanDetector::new(&cfg, 1000);
        let peer: IpAddr = "203.0.113.9".parse().unwrap();
        let local: IpAddr = "198.51.100.5".parse().unwrap();
        let base = SystemTime::now();
        let mut out = Vec::new();
        for p in 0..4u16 {
            d.on_event(&ev_syn(peer, local, 100 + p, base), &mut out);
        }
        assert!(out.is_empty());
    }

    #[test]
    fn cv_detects_regular_intervals() {
        let base = SystemTime::now();
        let mut deq = VecDeque::new();
        for i in 0..10u64 {
            deq.push_back(base + Duration::from_secs(i * 60));
        }
        let (cv, mean) = cv_of(&deq).unwrap();
        assert!((mean - 60.0).abs() < 1e-6);
        assert!(cv < 0.001);
    }

    fn base_ev(peer: IpAddr, local: IpAddr) -> PacketEvent {
        PacketEvent {
            ts: SystemTime::now(),
            direction: Direction::Inbound,
            local_ip: local,
            peer_ip: peer,
            src_ip: peer,
            dst_ip: local,
            proto: Proto::Tcp,
            src_port: Some(40000),
            dst_port: Some(443),
            tcp_flags: Some(TcpFlags::from_bits(0x10)),
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
    fn invalid_flags_fire_in_burst() {
        let cfg = CountCfg {
            enabled: true,
            threshold: 3,
            window_s: 60,
            cooldown_s: 300,
            severity: Severity::Medium,
        };
        let mut d = InvalidFlagsDetector::new(&cfg, 1000);
        let peer: IpAddr = "203.0.113.5".parse().unwrap();
        let local: IpAddr = "198.51.100.5".parse().unwrap();
        let mut out = Vec::new();
        for _ in 0..3 {
            let mut ev = base_ev(peer, local);
            ev.tcp_flags = Some(TcpFlags::from_bits(0x00)); // NULL
            d.on_event(&ev, &mut out);
        }
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule, RuleId::InvalidTcpFlags);
    }

    #[test]
    fn brute_force_counts_auth_syns() {
        let cfg = BruteForceCfg {
            enabled: true,
            threshold: 3,
            window_s: 60,
            cooldown_s: 300,
            severity: Severity::High,
            ports: vec![22],
        };
        let mut d = BruteForceDetector::new(&cfg, 1000);
        let peer: IpAddr = "203.0.113.9".parse().unwrap();
        let local: IpAddr = "198.51.100.5".parse().unwrap();
        let mut out = Vec::new();
        for _ in 0..3 {
            d.on_event(&ev_syn(peer, local, 22, SystemTime::now()), &mut out);
        }
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].rule, RuleId::BruteForce);
    }

    #[test]
    fn suspicious_port_fires_once_per_cooldown() {
        let cfg = PortListCfg {
            enabled: true,
            ports: vec![4444],
            cooldown_s: 3600,
            severity: Severity::Low,
        };
        let mut d = SuspiciousPortDetector::new(&cfg, 1000);
        let peer: IpAddr = "203.0.113.20".parse().unwrap();
        let local: IpAddr = "198.51.100.5".parse().unwrap();
        let mut out = Vec::new();
        let mut ev = base_ev(peer, local);
        ev.dst_port = Some(4444);
        d.on_event(&ev, &mut out);
        d.on_event(&ev, &mut out);
        assert_eq!(out.len(), 1, "cooldown should suppress the second");
        assert_eq!(out[0].rule, RuleId::SuspiciousPort);
    }

    #[test]
    fn dns_tunnel_trips_on_unique_subdomains() {
        let cfg = DnsTunnelCfg {
            enabled: true,
            entropy_threshold: 4.0,
            qname_len_threshold: 200,
            label_len_threshold: 200,
            subdomain_threshold: 4,
            txt_threshold: 100,
            window_s: 120,
            cooldown_s: 300,
            severity: Severity::Medium,
        };
        let mut d = DnsTunnelDetector::new(&cfg, 1000);
        let peer: IpAddr = "203.0.113.30".parse().unwrap();
        let local: IpAddr = "198.51.100.5".parse().unwrap();
        let mut out = Vec::new();
        for n in [
            "a.example.org",
            "b.example.org",
            "c.example.org",
            "d.example.org",
        ] {
            let mut ev = base_ev(peer, local);
            ev.proto = Proto::Udp;
            ev.tcp_flags = None;
            ev.dns = Some(crate::types::DnsQuery {
                qname: n.to_string(),
                qtype: 1,
                qclass: 1,
                is_response: false,
            });
            d.on_event(&ev, &mut out);
        }
        assert!(
            out.iter().any(|a| a.rule == RuleId::DnsTunnel),
            "expected a dns-tunnel alert, got {out:?}"
        );
    }

    #[test]
    fn custom_signature_matches_declared_constraints() {
        let cfg = SimpleCfg {
            enabled: true,
            cooldown_s: 3600,
            severity: Severity::Medium,
            suppress_after: None,
        };
        let sigs = vec![SignatureCfg {
            name: "test-4444".to_string(),
            enabled: true,
            protocol: Some("tcp".to_string()),
            direction: Some("in".to_string()),
            ports: vec![4444],
            peer_cidr: vec![],
            severity: None,
            content: None,
            nocase: false,
            depth: None,
            offset: None,
            msg: None,
            sid: None,
        }];
        let mut d = CustomSignatureDetector::new(&cfg, &sigs, 1000);
        assert_eq!(d.sigs_count(), 1);
        let peer: IpAddr = "203.0.113.40".parse().unwrap();
        let local: IpAddr = "198.51.100.5".parse().unwrap();

        let mut hit = base_ev(peer, local);
        hit.dst_port = Some(4444);
        let mut out = Vec::new();
        d.on_event(&hit, &mut out);
        assert_eq!(out.len(), 1, "signature should match tcp/in/4444");
        assert_eq!(out[0].rule, RuleId::CustomSignature);

        // A different port must not match the signature.
        let mut miss = base_ev(peer, local);
        miss.dst_port = Some(123);
        let mut out2 = Vec::new();
        d.on_event(&miss, &mut out2);
        assert!(out2.is_empty(), "signature must not match port 123");
    }
}
