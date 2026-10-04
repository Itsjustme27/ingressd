//! Core data types shared across the crate: decoded events, alerts, enums.

use std::fmt;
use std::net::IpAddr;
use std::time::SystemTime;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Direction of the packet relative to *this* host.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    /// Peer -> host.
    Inbound,
    /// Host -> peer.
    Outbound,
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Direction::Inbound => f.write_str("inbound"),
            Direction::Outbound => f.write_str("outbound"),
        }
    }
}

/// Transport protocol, coarse-grained for rule logic.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Proto {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
    /// ICMP (v4 or v6).
    Icmp,
    /// Anything else, carrying the IP protocol number.
    Other(u8),
}

impl Proto {
    /// Map an IP `protocol` number to a [`Proto`].
    pub fn from_ip_protocol(n: u8) -> Proto {
        match n {
            6 => Proto::Tcp,
            17 => Proto::Udp,
            1 | 58 => Proto::Icmp,
            other => Proto::Other(other),
        }
    }

    /// The IP protocol number this maps back to.
    pub fn ip_protocol(self) -> u8 {
        match self {
            Proto::Tcp => 6,
            Proto::Udp => 17,
            Proto::Icmp => 1,
            Proto::Other(n) => n,
        }
    }
}

impl fmt::Display for Proto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Proto::Tcp => f.write_str("tcp"),
            Proto::Udp => f.write_str("udp"),
            Proto::Icmp => f.write_str("icmp"),
            Proto::Other(n) => write!(f, "ip/{n}"),
        }
    }
}

/// TCP control flags of a header, decoded to booleans.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct TcpFlags {
    /// FIN.
    pub fin: bool,
    /// SYN.
    pub syn: bool,
    /// RST.
    pub rst: bool,
    /// PSH.
    pub psh: bool,
    /// ACK.
    pub ack: bool,
    /// URG.
    pub urg: bool,
    /// ECE.
    pub ece: bool,
    /// CWR.
    pub cwr: bool,
}

impl TcpFlags {
    /// Decode from the 8-bit TCP flags field (bits 0..=7 as in the header).
    pub fn from_bits(bits: u8) -> TcpFlags {
        TcpFlags {
            fin: bits & 0x01 != 0,
            syn: bits & 0x02 != 0,
            rst: bits & 0x04 != 0,
            psh: bits & 0x08 != 0,
            ack: bits & 0x10 != 0,
            urg: bits & 0x20 != 0,
            ece: bits & 0x40 != 0,
            cwr: bits & 0x80 != 0,
        }
    }

    /// True when no control flags are set (a NULL scan packet).
    pub fn is_null(&self) -> bool {
        !(self.fin || self.syn || self.rst || self.psh || self.ack || self.urg || self.ece || self.cwr)
    }

    /// SYN with no ACK: a connection attempt (used by most scan/flood rules).
    pub fn is_syn_only(&self) -> bool {
        self.syn && !self.ack && !self.rst && !self.fin
    }

    /// SYN+FIN, an invalid combination often used by stealth scanners (nmap `-sN`/`-sN`).
    pub fn is_syn_fin(&self) -> bool {
        self.syn && self.fin
    }

    /// SYN+RST, invalid.
    pub fn is_syn_rst(&self) -> bool {
        self.syn && self.rst
    }

    /// FIN with neither SYN nor ACK: a bare FIN probe.
    pub fn is_fin_only(&self) -> bool {
        self.fin && !self.syn && !self.ack && !self.rst
    }

    /// XMAS: FIN+PSH+URG set with no SYN/ACK/RST.
    pub fn is_xmas(&self) -> bool {
        self.fin && self.psh && self.urg && !self.syn && !self.ack && !self.rst
    }

    /// True if this packet uses any of the well-known invalid flag combinations.
    pub fn is_invalid_combo(&self) -> bool {
        self.is_null() || self.is_xmas() || self.is_fin_only() || self.is_syn_fin() || self.is_syn_rst()
    }
}

/// ICMP information relevant to tunneling/flood detection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct IcmpInfo {
    /// ICMP type (v4 type, or v6 type).
    pub kind: u8,
    /// ICMP code.
    pub code: u8,
    /// True when the message is an echo request or reply.
    pub echo: bool,
    /// Length of the data payload after the 8-byte ICMP header.
    pub payload_len: usize,
}

/// A parsed DNS question record (the first question in a query).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsQuery {
    /// Fully-qualified qname, ASCII, trailing dot removed.
    pub qname: String,
    /// QTYPE (1=A, 16=TXT, 10=NULL, 28=AAAA, ...).
    pub qtype: u16,
    /// QCLASS.
    pub qclass: u16,
    /// True if this looks like a response rather than a query.
    pub is_response: bool,
}

/// An owned, decoded network event — the unit handed from capture to the engine.
///
/// All fields are plain data (no borrowed slices) so the event is `Send + 'static`
/// and can cross a bounded channel.
#[derive(Clone, Debug)]
pub struct PacketEvent {
    /// Wall-clock time of the packet (pcap timestamp when replaying).
    pub ts: SystemTime,
    /// Inbound or outbound relative to this host.
    pub direction: Direction,
    /// This host's address in the conversation.
    pub local_ip: IpAddr,
    /// The public peer address.
    pub peer_ip: IpAddr,
    /// Source address (wire order).
    pub src_ip: IpAddr,
    /// Destination address (wire order).
    pub dst_ip: IpAddr,
    /// Transport protocol.
    pub proto: Proto,
    /// Source port, when transport has ports.
    pub src_port: Option<u16>,
    /// Destination port, when transport has ports.
    pub dst_port: Option<u16>,
    /// TCP flags, present for TCP.
    pub tcp_flags: Option<TcpFlags>,
    /// ICMP info, present for ICMP.
    pub icmp: Option<IcmpInfo>,
    /// Parsed DNS question, present for a well-formed DNS query on any port.
    pub dns: Option<DnsQuery>,
    /// Transport payload length (bytes after the L4 header).
    pub payload_len: usize,
    /// A bounded snapshot of the transport payload (up to `MAX_PAYLOAD_SNAP`
    /// bytes) for content/signature matching. Empty for flow-log inputs.
    pub payload: Vec<u8>,
    /// Total IP packet length (wire bytes of the IP datagram).
    pub ip_total_len: u16,
    /// Whether the IP datagram is a fragment.
    pub fragmented: bool,
    /// Whether this is the first fragment (carries the L4 header).
    pub first_fragment: bool,
}

impl Default for PacketEvent {
    fn default() -> Self {
        PacketEvent {
            ts: SystemTime::now(),
            direction: Direction::Inbound,
            local_ip: IpAddr::from([0, 0, 0, 0]),
            peer_ip: IpAddr::from([0, 0, 0, 0]),
            src_ip: IpAddr::from([0, 0, 0, 0]),
            dst_ip: IpAddr::from([0, 0, 0, 0]),
            proto: Proto::Other(0),
            src_port: None,
            dst_port: None,
            tcp_flags: None,
            icmp: None,
            dns: None,
            payload_len: 0,
            payload: Vec::new(),
            ip_total_len: 0,
            fragmented: false,
            first_fragment: false,
        }
    }
}

/// Max transport-payload bytes snapshotted per event for content matching.
/// Bounds channel memory (50k events * this cap) and covers the `depth`/`offset`
/// windows of typical Snort signatures.
pub const MAX_PAYLOAD_SNAP: usize = 512;

impl PacketEvent {
    /// True when the packet is inbound from the peer toward this host.
    pub fn inbound(&self) -> bool {
        self.direction == Direction::Inbound
    }

    /// True for a TCP SYN-only packet (a new connection attempt).
    pub fn is_new_tcp_connection(&self) -> bool {
        self.proto == Proto::Tcp && self.tcp_flags.is_some_and(|f| f.is_syn_only())
    }
}

/// Alert severity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Low.
    Low,
    /// Medium.
    Medium,
    /// High.
    High,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
        })
    }
}

/// The set of detection rules. Also the stable key used in config and metrics.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum RuleId {
    /// Port scanning (horizontal / vertical).
    #[serde(rename = "port-scan")]
    PortScan,
    /// Invalid TCP flag combinations.
    #[serde(rename = "invalid-tcp-flags")]
    InvalidTcpFlags,
    /// Brute force against auth services.
    #[serde(rename = "brute-force")]
    BruteForce,
    /// TCP SYN flood.
    #[serde(rename = "syn-flood")]
    SynFlood,
    /// UDP flood.
    #[serde(rename = "udp-flood")]
    UdpFlood,
    /// ICMP flood.
    #[serde(rename = "icmp-flood")]
    IcmpFlood,
    /// UDP reflection / amplification.
    #[serde(rename = "reflection-amplification")]
    ReflectionAmplification,
    /// DNS tunneling.
    #[serde(rename = "dns-tunnel")]
    DnsTunnel,
    /// ICMP tunneling.
    #[serde(rename = "icmp-tunnel")]
    IcmpTunnel,
    /// Periodic C2 beaconing.
    #[serde(rename = "beaconing")]
    Beaconing,
    /// Peer matches a threat-intel blocklist.
    #[serde(rename = "threat-intel-hit")]
    ThreatIntelHit,
    /// Traffic on a known backdoor / C2 port.
    #[serde(rename = "suspicious-port")]
    SuspiciousPort,
    /// Inbound probes to a port with no listener.
    #[serde(rename = "new-listener-probe")]
    NewListenerProbe,
    /// A user-defined detection signature from `[rules.signature]`.
    #[serde(rename = "custom-signature")]
    CustomSignature,
}

impl RuleId {
    /// All rule ids, in a stable order (used for config defaults and metrics).
    pub const ALL: [RuleId; 14] = [
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
        RuleId::CustomSignature,
    ];

    /// Stable string key (config section name, metrics label).
    pub fn as_str(&self) -> &'static str {
        match self {
            RuleId::PortScan => "port-scan",
            RuleId::InvalidTcpFlags => "invalid-tcp-flags",
            RuleId::BruteForce => "brute-force",
            RuleId::SynFlood => "syn-flood",
            RuleId::UdpFlood => "udp-flood",
            RuleId::IcmpFlood => "icmp-flood",
            RuleId::ReflectionAmplification => "reflection-amplification",
            RuleId::DnsTunnel => "dns-tunnel",
            RuleId::IcmpTunnel => "icmp-tunnel",
            RuleId::Beaconing => "beaconing",
            RuleId::ThreatIntelHit => "threat-intel-hit",
            RuleId::SuspiciousPort => "suspicious-port",
            RuleId::NewListenerProbe => "new-listener-probe",
            RuleId::CustomSignature => "custom-signature",
        }
    }

    /// MITRE ATT&CK technique id for the rule.
    pub fn mitre(&self) -> &'static str {
        match self {
            RuleId::PortScan => "T1046",
            RuleId::InvalidTcpFlags => "T1046",
            RuleId::BruteForce => "T1110",
            RuleId::SynFlood => "T1498.001",
            RuleId::UdpFlood | RuleId::IcmpFlood => "T1498",
            RuleId::ReflectionAmplification => "T1498.002",
            RuleId::DnsTunnel => "T1071.004",
            RuleId::IcmpTunnel => "T1095",
            RuleId::Beaconing => "T1071",
            RuleId::ThreatIntelHit => "T1071",
            RuleId::SuspiciousPort => "T1571",
            RuleId::NewListenerProbe => "T1595",
            RuleId::CustomSignature => "T1071",
        }
    }

    /// MITRE ATT&CK tactic id for the rule's technique.
    pub fn tactic(&self) -> &'static str {
        match self {
            RuleId::PortScan | RuleId::InvalidTcpFlags => "TA0007",        // Discovery
            RuleId::BruteForce => "TA0006",                                 // Credential Access
            RuleId::SynFlood | RuleId::UdpFlood | RuleId::IcmpFlood | RuleId::ReflectionAmplification => "TA0040", // Impact
            RuleId::DnsTunnel | RuleId::Beaconing | RuleId::ThreatIntelHit | RuleId::SuspiciousPort | RuleId::IcmpTunnel => "TA0011", // Command and Control
            RuleId::NewListenerProbe => "TA0043",                           // Reconnaissance
            RuleId::CustomSignature => "TA0011",                            // Command and Control (default)
        }
    }

    /// Human-readable MITRE tactic name.
    pub fn tactic_name(&self) -> &'static str {
        match self.tactic() {
            "TA0007" => "Discovery",
            "TA0006" => "Credential Access",
            "TA0040" => "Impact",
            "TA0011" => "Command and Control",
            "TA0043" => "Reconnaissance",
            _ => "Unknown",
        }
    }

    /// Rule-specific tags (SIEM correlation keys).
    pub fn tags(&self) -> &'static [&'static str] {
        match self {
            RuleId::PortScan => &["recon", "scan", "discovery"],
            RuleId::InvalidTcpFlags => &["recon", "scan", "evasion"],
            RuleId::BruteForce => &["credential-access", "brute-force"],
            RuleId::SynFlood => &["dos", "flood", "availability"],
            RuleId::UdpFlood => &["dos", "flood", "availability"],
            RuleId::IcmpFlood => &["dos", "flood", "availability"],
            RuleId::ReflectionAmplification => &["dos", "amplification", "availability"],
            RuleId::DnsTunnel => &["exfiltration", "c2", "dns"],
            RuleId::IcmpTunnel => &["tunneling", "c2", "icmp"],
            RuleId::Beaconing => &["c2", "beaconing"],
            RuleId::ThreatIntelHit => &["threat-intel", "known-bad"],
            RuleId::SuspiciousPort => &["c2", "backdoor"],
            RuleId::NewListenerProbe => &["recon", "fingerprinting"],
            RuleId::CustomSignature => &["custom", "signature"],
        }
    }

    /// Base impact weight (0..=70) used by [`compute_risk_score`]; independent
    /// of the configured severity so tuning severity still shifts the score.
    pub fn base_weight(&self) -> u8 {
        match self {
            RuleId::ThreatIntelHit => 55,
            RuleId::ReflectionAmplification | RuleId::SynFlood => 50,
            RuleId::DnsTunnel | RuleId::IcmpTunnel | RuleId::Beaconing => 45,
            RuleId::BruteForce => 40,
            RuleId::UdpFlood | RuleId::IcmpFlood => 38,
            RuleId::SuspiciousPort => 30,
            RuleId::PortScan | RuleId::InvalidTcpFlags => 25,
            RuleId::NewListenerProbe => 18,
            RuleId::CustomSignature => 35,
        }
    }
}

impl fmt::Display for RuleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for RuleId {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        RuleId::ALL
            .iter()
            .copied()
            .find(|r| r.as_str() == s)
            .ok_or_else(|| format!("unknown rule id: {s}"))
    }
}

/// The port fields of an alert.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertPorts {
    /// Source port, if known.
    pub src: Option<u16>,
    /// Destination port, if known.
    pub dst: Option<u16>,
}

/// A detection alert, serialized as one JSON Lines record.
///
/// Field names match the output contract in the design spec.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Alert {
    /// Unique id for this alert instance (referenced by enforcement logs).
    pub id: String,
    /// RFC 3339 UTC timestamp.
    pub time: DateTime<Utc>,
    /// Rule that fired.
    pub rule: RuleId,
    /// Severity.
    pub severity: Severity,
    /// Direction relative to this host.
    pub direction: Direction,
    /// The public peer IP.
    pub peer_ip: IpAddr,
    /// Peer ASN when GeoIP/ASN enrichment is available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_asn: Option<u32>,
    /// Peer country code when GeoIP enrichment is available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_country: Option<String>,
    /// This host's address in the conversation.
    pub local_ip: IpAddr,
    /// Transport protocol.
    pub proto: Proto,
    /// Relevant ports.
    pub ports: AlertPorts,
    /// Human-readable detail string.
    pub detail: String,
    /// MITRE ATT&CK technique id.
    pub mitre: String,
    /// Event count that triggered the alert within the window.
    pub count: u64,
    /// Window length in seconds the count applies to.
    pub window_s: u64,
    /// Composite 0-100 risk score (rule impact + severity + volume).
    pub risk_score: u8,
    /// MITRE ATT&CK tactic id (e.g. TA0011).
    pub tactic: String,
    /// Human-readable MITRE tactic name.
    pub tactic_name: String,
    /// Correlation tags for SIEM routing.
    pub tags: Vec<String>,
    /// Sensor identity that produced the alert (set by the engine).
    #[serde(default)]
    pub sensor: String,
    /// Alert schema version for downstream consumers.
    pub schema_version: u8,
}

/// A partially-built alert produced by a detector, before enrichment.
///
/// Detectors fill these fields; the engine adds `id`, `time`, geo enrichment and
/// the MITRE tag when turning it into a final [`Alert`].
#[derive(Clone, Debug)]
pub struct AlertDraft {
    /// Rule that fired.
    pub rule: RuleId,
    /// Severity.
    pub severity: Severity,
    /// Direction relative to this host.
    pub direction: Direction,
    /// Public peer IP.
    pub peer_ip: IpAddr,
    /// Local IP.
    pub local_ip: IpAddr,
    /// Protocol.
    pub proto: Proto,
    /// Ports.
    pub ports: AlertPorts,
    /// Detail.
    pub detail: String,
    /// Count.
    pub count: u64,
    /// Window seconds.
    pub window_s: u64,
    /// Wall time to stamp on the alert.
    pub time: SystemTime,
}

impl AlertDraft {
    /// Convenience constructor filling common fields from an event.
    pub fn from_event(ev: &PacketEvent, severity: Severity, detail: String, count: u64, window_s: u64, rule: RuleId) -> AlertDraft {
        AlertDraft {
            rule,
            severity,
            direction: ev.direction,
            peer_ip: ev.peer_ip,
            local_ip: ev.local_ip,
            proto: ev.proto,
            ports: AlertPorts { src: ev.src_port, dst: ev.dst_port },
            detail,
            count,
            window_s,
            time: ev.ts,
        }
    }

    /// Convert into a finalized [`Alert`] with a generated id and enriched fields.
    pub fn finish(self, asn: Option<u32>, country: Option<String>) -> Alert {
        let risk = compute_risk_score(self.rule, self.severity, self.count);
        Alert {
            id: gen_id(),
            time: to_utc(self.time),
            rule: self.rule,
            severity: self.severity,
            direction: self.direction,
            peer_ip: self.peer_ip,
            peer_asn: asn,
            peer_country: country,
            local_ip: self.local_ip,
            proto: self.proto,
            ports: self.ports,
            detail: self.detail,
            mitre: self.rule.mitre().to_string(),
            count: self.count,
            window_s: self.window_s,
            risk_score: risk,
            tactic: self.rule.tactic().to_string(),
            tactic_name: self.rule.tactic_name().to_string(),
            tags: self.rule.tags().iter().map(|t| t.to_string()).collect(),
            sensor: String::new(),
            schema_version: 1,
        }
    }
}

/// Convert a [`SystemTime`] to a `chrono` UTC timestamp, falling back to now.
pub fn to_utc(t: SystemTime) -> DateTime<Utc> {
    DateTime::<Utc>::from(t)
}

/// Severity → additive risk points.
fn severity_bonus(sev: Severity) -> u8 {
    match sev {
        Severity::Low => 8,
        Severity::Medium => 18,
        Severity::High => 30,
    }
}

/// Deterministic 0-100 risk score from rule impact weight, configured severity,
/// and the observed event count (log-scaled volume signal). Monotonic in all
/// three inputs so it can be thresholded in a SIEM or an enforcement gate.
pub fn compute_risk_score(rule: RuleId, sev: Severity, count: u64) -> u8 {
    let volume = ((count as f64).ln_1p() * 6.0).clamp(0.0, 20.0) as u8;
    (rule.base_weight() as u16 + severity_bonus(sev) as u16 + volume as u16).min(100) as u8
}

/// Whole-second difference `now - earlier`, saturating at zero.
pub fn secs_between(earlier: SystemTime, now: SystemTime) -> f64 {
    match now.duration_since(earlier) {
        Ok(d) => d.as_secs_f64(),
        Err(_) => 0.0,
    }
}

/// A small, cheap, non-cryptographic unique id for alerts (monotonic + random tail).
pub fn gen_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    // Mix in nanos so ids are unique across process restarts too.
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!("{n:08}-{:08x}", nanos)
}
