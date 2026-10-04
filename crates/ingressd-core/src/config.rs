//! Rule configuration: one typed section per rule with sane defaults.
//!
//! These structs are the deserialization target for the `[rules.*]` tables in
//! `config.toml`. Each rejects unknown keys (`deny_unknown_fields`) and provides
//! a [`Default`] so partial tables are fine. [`RulesConfig::validate`] enforces
//! value ranges with clear messages.

use serde::Deserialize;

use crate::types::Severity;

/// Default TCP ports treated as authentication services for brute-force.
pub const DEFAULT_AUTH_PORTS: [u16; 15] = [
    22,    // SSH
    23,    // Telnet
    21,    // FTP
    3389,  // RDP
    445,   // SMB
    139,   // NetBIOS
    5900,  // VNC
    5901, 5902, 5903, // VNC display N
    5985,  // WinRM HTTP
    5986,  // WinRM HTTPS
    1433,  // MSSQL
    3306,  // MySQL
];

/// Default UDP ports known to be abused for reflection/amplification.
pub const DEFAULT_REFLECT_PORTS: [u16; 6] = [53, 123, 161, 389, 1900, 11211];

/// Default ports associated with backdoors / C2.
pub const DEFAULT_SUSPICIOUS_PORTS: [u16; 16] = [
    1234, 1971, 31337, 4444, 5005, 5555, 6666, 6667, 6697, 7777, 8080, 8443, 9001, 10000, 12345, 12346,
];

/// All rule configuration.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RulesConfig {
    /// Hard cap on simultaneously tracked keys across all rules (LRU evicted).
    pub max_tracked_keys: usize,
    /// `[rules.port-scan]`.
    #[serde(rename = "port-scan")]
    pub port_scan: PortScanCfg,
    #[serde(rename = "invalid-tcp-flags")]
    /// `[rules.invalid-tcp-flags]`.
    pub invalid_tcp_flags: CountCfg,
    #[serde(rename = "brute-force")]
    /// `[rules.brute-force]`.
    pub brute_force: BruteForceCfg,
    #[serde(rename = "syn-flood")]
    /// `[rules.syn-flood]`.
    pub syn_flood: SynFloodCfg,
    #[serde(rename = "udp-flood")]
    /// `[rules.udp-flood]`.
    pub udp_flood: RateCfg,
    #[serde(rename = "icmp-flood")]
    /// `[rules.icmp-flood]`.
    pub icmp_flood: RateCfg,
    #[serde(rename = "reflection-amplification")]
    /// `[rules.reflection-amplification]`.
    pub reflection: ReflectionCfg,
    #[serde(rename = "dns-tunnel")]
    /// `[rules.dns-tunnel]`.
    pub dns_tunnel: DnsTunnelCfg,
    #[serde(rename = "icmp-tunnel")]
    /// `[rules.icmp-tunnel]`.
    pub icmp_tunnel: IcmpTunnelCfg,
    /// `[rules.beaconing]`.
    pub beaconing: BeaconingCfg,
    #[serde(rename = "threat-intel-hit")]
    /// `[rules.threat-intel-hit]`.
    pub threat_intel: SimpleCfg,
    #[serde(rename = "suspicious-port")]
    /// `[rules.suspicious-port]`.
    pub suspicious_port: PortListCfg,
    #[serde(rename = "new-listener-probe")]
    /// `[rules.new-listener-probe]`.
    pub new_listener: NewListenerCfg,
    #[serde(rename = "custom-signature")]
    /// `[rules.custom-signature]` — enable/cooldown/default severity for user signatures.
    pub custom_signature: SimpleCfg,
    /// `[[rules.signature]]` — user-defined detection signatures.
    pub signature: Vec<SignatureCfg>,
}

/// Generic "count within a window" thresholds.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CountCfg {
    /// Enable/disable the rule.
    pub enabled: bool,
    /// Count that triggers an alert.
    pub threshold: usize,
    /// Window length in seconds.
    pub window_s: u64,
    /// Per-(rule,peer) cooldown in seconds.
    pub cooldown_s: u64,
    /// Reported severity.
    pub severity: Severity,
}

/// A pure rate rule (packets per window per target).
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RateCfg {
    /// Enable/disable the rule.
    pub enabled: bool,
    /// Packet count that triggers.
    pub threshold: usize,
    /// Window length in seconds.
    pub window_s: u64,
    /// Cooldown seconds.
    pub cooldown_s: u64,
    /// Severity.
    pub severity: Severity,
}

/// Enabled + severity + cooldown only.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SimpleCfg {
    /// Enable/disable the rule.
    pub enabled: bool,
    /// Cooldown seconds.
    pub cooldown_s: u64,
    /// Severity.
    pub severity: Severity,
    /// After emitting this many alerts for a given key, go quiet (per-key
    /// feedback suppression for recurring low-severity noise). `None` = never.
    pub suppress_after: Option<u64>,
}

/// A rule keyed off a static port set.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PortListCfg {
    /// Enable/disable the rule.
    pub enabled: bool,
    /// Ports to watch.
    pub ports: Vec<u16>,
    /// Cooldown seconds.
    pub cooldown_s: u64,
    /// Severity.
    pub severity: Severity,
}

/// `[rules.port-scan]`.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PortScanCfg {
    /// Enable/disable the rule.
    pub enabled: bool,
    /// Distinct targets (horizontal) or ports (vertical) required.
    pub min_targets: usize,
    /// Window seconds.
    pub window_s: u64,
    /// Cooldown seconds.
    pub cooldown_s: u64,
    /// Severity.
    pub severity: Severity,
}

/// `[rules.brute-force]`.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BruteForceCfg {
    /// Enable/disable the rule.
    pub enabled: bool,
    /// New connections in window that trigger.
    pub threshold: usize,
    /// Window seconds.
    pub window_s: u64,
    /// Cooldown seconds.
    pub cooldown_s: u64,
    /// Severity.
    pub severity: Severity,
    /// Service ports considered (defaults to [`DEFAULT_AUTH_PORTS`]).
    pub ports: Vec<u16>,
}

/// `[rules.syn-flood]`.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SynFloodCfg {
    /// Enable/disable the rule.
    pub enabled: bool,
    /// Inbound SYNs to a local endpoint in window.
    pub threshold: usize,
    /// Window seconds.
    pub window_s: u64,
    /// Cooldown seconds.
    pub cooldown_s: u64,
    /// Severity.
    pub severity: Severity,
    /// Completion ratio (SYN-ACK we sent / SYNs) below which it is a flood.
    pub max_completion_ratio: f64,
}

/// `[rules.reflection-amplification]`.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ReflectionCfg {
    /// Enable/disable the rule.
    pub enabled: bool,
    /// Reflector source ports.
    pub ports: Vec<u16>,
    /// Response payload bytes at/above which an unsolicited reply counts.
    pub min_response_bytes: usize,
    /// Unsolicited responses per peer in window to alert.
    pub threshold: usize,
    /// Window seconds.
    pub window_s: u64,
    /// Cooldown seconds.
    pub cooldown_s: u64,
    /// Severity.
    pub severity: Severity,
}

/// `[rules.dns-tunnel]`.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DnsTunnelCfg {
    /// Enable/disable the rule.
    pub enabled: bool,
    /// Shannon entropy (bits/char) at/above which a qname is suspicious.
    pub entropy_threshold: f64,
    /// QNAME length at/above which it is suspicious.
    pub qname_len_threshold: usize,
    /// Longest single label at/above which it is suspicious.
    pub label_len_threshold: usize,
    /// Unique subdomains under one base domain to alert.
    pub subdomain_threshold: usize,
    /// TXT/NULL query count in window to alert.
    pub txt_threshold: usize,
    /// Window seconds.
    pub window_s: u64,
    /// Cooldown seconds.
    pub cooldown_s: u64,
    /// Severity.
    pub severity: Severity,
}

/// `[rules.icmp-tunnel]`.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct IcmpTunnelCfg {
    /// Enable/disable the rule.
    pub enabled: bool,
    /// Echo payload bytes at/above which it is oversized.
    pub max_payload: usize,
    /// Oversized/large echo count in window to alert.
    pub threshold: usize,
    /// Window seconds.
    pub window_s: u64,
    /// Cooldown seconds.
    pub cooldown_s: u64,
    /// Severity.
    pub severity: Severity,
}

/// `[rules.beaconing]`.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BeaconingCfg {
    /// Enable/disable the rule.
    pub enabled: bool,
    /// Minimum connection samples required.
    pub min_samples: usize,
    /// Coefficient of variation (stdev/mean) at/below which it is a beacon.
    pub max_jitter_cv: f64,
    /// Lookback window seconds (long).
    pub window_s: u64,
    /// Cooldown seconds.
    pub cooldown_s: u64,
    /// Severity.
    pub severity: Severity,
    /// Cap stored intervals per peer.
    pub max_samples: usize,
}

/// `[rules.new-listener-probe]`.
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NewListenerCfg {
    /// Enable/disable the rule.
    pub enabled: bool,
    /// Distinct sources hitting an unlisted port to alert.
    pub min_sources: usize,
    /// Window seconds.
    pub window_s: u64,
    /// Cooldown seconds.
    pub cooldown_s: u64,
    /// Severity.
    pub severity: Severity,
}

/// One user-defined detection signature (`[[rules.signature]]`).
///
/// A signature alerts when a packet matches all of the constraints it declares.
/// Omitted constraints match anything, so set at least one of `protocol`,
/// `direction`, `ports`, or `peer_cidr` (validation enforces this).
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SignatureCfg {
    /// Unique name; shown in the alert detail and used as a cooldown key.
    pub name: String,
    /// Enable/disable without deleting the entry.
    pub enabled: bool,
    /// Restrict to a protocol: `tcp`, `udp`, or `icmp`.
    pub protocol: Option<String>,
    /// Restrict to a direction: `in` or `out`.
    pub direction: Option<String>,
    /// Match when src OR dst port is in this list (empty = any port).
    pub ports: Vec<u16>,
    /// Match when the peer IP is inside any of these CIDRs (empty = any peer).
    pub peer_cidr: Vec<String>,
    /// Per-signature severity override; falls back to `[rules.custom-signature]`.
    pub severity: Option<Severity>,
    /// Payload content to match. Snort-style: literal bytes with `|HH HH|` hex
    /// groups (e.g. `"GetInfo|0D|"`). Requires a transport payload; not available
    /// in flow-log mode.
    pub content: Option<String>,
    /// Case-insensitive content match.
    pub nocase: bool,
    /// Match content only within the first `depth` bytes of the payload.
    pub depth: Option<usize>,
    /// Start matching at this payload offset.
    pub offset: Option<usize>,
    /// Human-readable message (e.g. Snort `msg`). Used in the alert detail.
    pub msg: Option<String>,
    /// Stable signature id (e.g. Snort `sid`). Surfaces in the alert detail.
    pub sid: Option<u32>,
}

// ---- Defaults ----

impl Default for RulesConfig {
    fn default() -> Self {
        RulesConfig {
            max_tracked_keys: 200_000,
            port_scan: PortScanCfg::default(),
            invalid_tcp_flags: CountCfg::default(),
            brute_force: BruteForceCfg::default(),
            syn_flood: SynFloodCfg::default(),
            udp_flood: RateCfg::default(),
            icmp_flood: RateCfg::default(),
            reflection: ReflectionCfg::default(),
            dns_tunnel: DnsTunnelCfg::default(),
            icmp_tunnel: IcmpTunnelCfg::default(),
            beaconing: BeaconingCfg::default(),
            threat_intel: SimpleCfg::default(),
            suspicious_port: PortListCfg::default(),
            new_listener: NewListenerCfg::default(),
            custom_signature: SimpleCfg::default(),
            signature: Vec::new(),
        }
    }
}

impl Default for CountCfg {
    fn default() -> Self {
        CountCfg { enabled: true, threshold: 10, window_s: 60, cooldown_s: 300, severity: Severity::Medium }
    }
}

impl Default for RateCfg {
    fn default() -> Self {
        RateCfg { enabled: true, threshold: 5000, window_s: 5, cooldown_s: 300, severity: Severity::High }
    }
}

impl Default for SimpleCfg {
    fn default() -> Self {
        SimpleCfg { enabled: true, cooldown_s: 3600, severity: Severity::High, suppress_after: None }
    }
}

impl Default for PortListCfg {
    fn default() -> Self {
        PortListCfg {
            enabled: true,
            ports: DEFAULT_SUSPICIOUS_PORTS.to_vec(),
            cooldown_s: 600,
            severity: Severity::Low,
        }
    }
}

impl Default for PortScanCfg {
    fn default() -> Self {
        PortScanCfg { enabled: true, min_targets: 15, window_s: 30, cooldown_s: 300, severity: Severity::Medium }
    }
}

impl Default for BruteForceCfg {
    fn default() -> Self {
        BruteForceCfg {
            enabled: true,
            threshold: 20,
            window_s: 60,
            cooldown_s: 600,
            severity: Severity::High,
            ports: DEFAULT_AUTH_PORTS.to_vec(),
        }
    }
}

impl Default for SynFloodCfg {
    fn default() -> Self {
        SynFloodCfg {
            enabled: true,
            threshold: 2000,
            window_s: 5,
            cooldown_s: 300,
            severity: Severity::High,
            max_completion_ratio: 0.10,
        }
    }
}

impl Default for ReflectionCfg {
    fn default() -> Self {
        ReflectionCfg {
            enabled: true,
            ports: DEFAULT_REFLECT_PORTS.to_vec(),
            min_response_bytes: 512,
            threshold: 10,
            window_s: 10,
            cooldown_s: 300,
            severity: Severity::High,
        }
    }
}

impl Default for DnsTunnelCfg {
    fn default() -> Self {
        DnsTunnelCfg {
            enabled: true,
            entropy_threshold: 4.0,
            qname_len_threshold: 60,
            label_len_threshold: 40,
            subdomain_threshold: 50,
            txt_threshold: 100,
            window_s: 120,
            cooldown_s: 600,
            severity: Severity::Medium,
        }
    }
}

impl Default for IcmpTunnelCfg {
    fn default() -> Self {
        IcmpTunnelCfg { enabled: true, max_payload: 1000, threshold: 20, window_s: 60, cooldown_s: 600, severity: Severity::Medium }
    }
}

impl Default for BeaconingCfg {
    fn default() -> Self {
        BeaconingCfg {
            enabled: true,
            min_samples: 8,
            max_jitter_cv: 0.15,
            window_s: 3600,
            cooldown_s: 3600,
            severity: Severity::High,
            max_samples: 256,
        }
    }
}

impl Default for NewListenerCfg {
    fn default() -> Self {
        NewListenerCfg { enabled: true, min_sources: 20, window_s: 120, cooldown_s: 600, severity: Severity::Low }
    }
}

impl Default for SignatureCfg {
    fn default() -> Self {
        SignatureCfg {
            name: String::new(),
            enabled: true,
            protocol: None,
            direction: None,
            ports: Vec::new(),
            peer_cidr: Vec::new(),
            severity: None,
            content: None,
            nocase: false,
            depth: None,
            offset: None,
            msg: None,
            sid: None,
        }
    }
}

impl RulesConfig {
    /// Validate value ranges. Returns every problem at once with clear messages.
    pub fn validate(&self) -> Result<(), Vec<String>> {
        let mut errs = Vec::new();
        if self.max_tracked_keys < 1_000 {
            errs.push("max_tracked_keys must be >= 1000".to_string());
        }
        let check_win = |name: &str, w: u64, c: u64, errs: &mut Vec<String>| {
            if w == 0 {
                errs.push(format!("{name}: window_s must be > 0"));
            }
            if c == 0 {
                errs.push(format!("{name}: cooldown_s must be > 0"));
            }
        };
        if self.port_scan.min_targets < 2 {
            errs.push("port-scan: min_targets must be >= 2".into());
        }
        check_win("port-scan", self.port_scan.window_s, self.port_scan.cooldown_s, &mut errs);
        check_win("invalid-tcp-flags", self.invalid_tcp_flags.window_s, self.invalid_tcp_flags.cooldown_s, &mut errs);
        if self.brute_force.threshold < 2 {
            errs.push("brute-force: threshold must be >= 2".into());
        }
        check_win("brute-force", self.brute_force.window_s, self.brute_force.cooldown_s, &mut errs);
        if self.brute_force.ports.is_empty() {
            errs.push("brute-force: ports must not be empty".into());
        }
        check_win("syn-flood", self.syn_flood.window_s, self.syn_flood.cooldown_s, &mut errs);
        if !(0.0..=1.0).contains(&self.syn_flood.max_completion_ratio) {
            errs.push("syn-flood: max_completion_ratio must be within 0.0..=1.0".into());
        }
        check_win("udp-flood", self.udp_flood.window_s, self.udp_flood.cooldown_s, &mut errs);
        check_win("icmp-flood", self.icmp_flood.window_s, self.icmp_flood.cooldown_s, &mut errs);
        if self.reflection.ports.is_empty() {
            errs.push("reflection-amplification: ports must not be empty".into());
        }
        if self.reflection.min_response_bytes == 0 {
            errs.push("reflection-amplification: min_response_bytes must be > 0".into());
        }
        check_win("reflection-amplification", self.reflection.window_s, self.reflection.cooldown_s, &mut errs);
        if !(0.0..=8.0).contains(&self.dns_tunnel.entropy_threshold) {
            errs.push("dns-tunnel: entropy_threshold must be within 0.0..=8.0".into());
        }
        check_win("dns-tunnel", self.dns_tunnel.window_s, self.dns_tunnel.cooldown_s, &mut errs);
        if self.icmp_tunnel.max_payload < 8 {
            errs.push("icmp-tunnel: max_payload must be >= 8".into());
        }
        check_win("icmp-tunnel", self.icmp_tunnel.window_s, self.icmp_tunnel.cooldown_s, &mut errs);
        if self.beaconing.min_samples < 3 {
            errs.push("beaconing: min_samples must be >= 3".into());
        }
        if !(0.0..=1.0).contains(&self.beaconing.max_jitter_cv) {
            errs.push("beaconing: max_jitter_cv must be within 0.0..=1.0".into());
        }
        if self.beaconing.max_samples < self.beaconing.min_samples {
            errs.push("beaconing: max_samples must be >= min_samples".into());
        }
        check_win("beaconing", self.beaconing.window_s, self.beaconing.cooldown_s, &mut errs);
        if self.new_listener.min_sources < 2 {
            errs.push("new-listener-probe: min_sources must be >= 2".into());
        }
        check_win("new-listener-probe", self.new_listener.window_s, self.new_listener.cooldown_s, &mut errs);
        if self.suspicious_port.ports.is_empty() {
            errs.push("suspicious-port: ports must not be empty".into());
        }
        if self.custom_signature.cooldown_s == 0 {
            errs.push("custom-signature: cooldown_s must be > 0".into());
        }
        for (i, sig) in self.signature.iter().enumerate() {
            if sig.name.trim().is_empty() {
                errs.push(format!("signature #{i}: name must not be empty"));
            }
            if let Some(p) = &sig.protocol {
                if !matches!(p.as_str(), "tcp" | "udp" | "icmp") {
                    errs.push(format!("signature '{}': protocol must be tcp|udp|icmp", sig.name));
                }
            }
            if let Some(d) = &sig.direction {
                if !matches!(d.as_str(), "in" | "out") {
                    errs.push(format!("signature '{}': direction must be in|out", sig.name));
                }
            }
            // Reject a signature that would match every packet.
            if sig.protocol.is_none() && sig.direction.is_none() && sig.ports.is_empty() && sig.peer_cidr.is_empty() {
                errs.push(format!("signature '{}': set at least one constraint (protocol/direction/ports/peer_cidr)", sig.name));
            }
            for cidr in &sig.peer_cidr {
                if cidr.parse::<ipnet::IpNet>().is_err() {
                    errs.push(format!("signature '{}': invalid peer_cidr '{cidr}'", sig.name));
                }
            }
        }
        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_validate() {
        RulesConfig::default().validate().unwrap();
    }

    #[test]
    fn bad_values_reported() {
        let mut c = RulesConfig::default();
        c.port_scan.min_targets = 1;
        c.syn_flood.max_completion_ratio = 2.0;
        let errs = c.validate().unwrap_err();
        assert!(errs.iter().any(|e| e.contains("port-scan")));
        assert!(errs.iter().any(|e| e.contains("max_completion_ratio")));
    }

    #[test]
    fn partial_toml_uses_defaults() {
        let toml_src = "[port-scan]\nmin_targets = 40\n";
        let c: RulesConfig = toml::from_str(toml_src).expect("parse");
        assert_eq!(c.port_scan.min_targets, 40);
        // untouched field keeps default
        assert!(c.port_scan.enabled);
    }

    #[test]
    fn unknown_key_rejected() {
        let toml_src = "[port-scan]\nmin_targets = 40\ntypo_field = 1\n";
        assert!(toml::from_str::<RulesConfig>(toml_src).is_err());
    }
}
