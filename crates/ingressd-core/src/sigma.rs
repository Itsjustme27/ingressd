//! Sigma rule generation: map every built-in detection rule to a Sigma document
//! so alerts can be ingested and correlated by any Sigma-compatible SIEM
//! (Splunk via pySigma, Elasticsearch, SigNoz, etc.).
//!
//! The alerts `ingressd` emits are a custom log source (`product: ingressd`,
//! `service: alerts`); each generated rule selects on the alert's `rule` field
//! and carries MITRE tags + the same 0-100 risk score the engine computes.

use crate::types::RuleId;

/// Deterministic RFC-4122-shaped id derived from the rule key (stable across runs
/// so SIEM rule identity does not churn when we regenerate the pack).
pub(crate) fn uuid_for(name: &str) -> String {
    // FNV-1a 64 over the bytes, then expand to a UUID-looking string. Good enough
    // for stable identity; not a cryptographic uuid.
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in name.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let h2 = h.rotate_left(17).wrapping_mul(0x9e37_79b9_7f4a_7c15);
    format!(
        "{:08x}-{:04x}-4{:03x}-8{:03x}-{:012x}",
        (h >> 32) as u32,
        (h >> 16) as u16,
        (h & 0x0fff) as u16,
        (h2 & 0x0fff) as u16,
        (h2 >> 16) & 0xffff_ffff_ffff,
    )
}

fn tactic_tag(rule: RuleId) -> &'static str {
    match rule.tactic() {
        "TA0007" => "attack.discovery",
        "TA0006" => "attack.credential_access",
        "TA0040" => "attack.impact",
        "TA0011" => "attack.command_and_control",
        "TA0043" => "attack.reconnaissance",
        _ => "attack.mitre_technique",
    }
}

fn sigma_level(rule: RuleId) -> &'static str {
    match rule {
        RuleId::ThreatIntelHit
        | RuleId::ReflectionAmplification
        | RuleId::SynFlood
        | RuleId::Beaconing => "critical",
        RuleId::UdpFlood | RuleId::IcmpFlood | RuleId::BruteForce => "high",
        RuleId::DnsTunnel | RuleId::IcmpTunnel => "medium",
        RuleId::PortScan | RuleId::InvalidTcpFlags => "medium",
        RuleId::SuspiciousPort | RuleId::NewListenerProbe => "low",
        RuleId::CustomSignature => "medium",
    }
}

fn title_desc(rule: RuleId) -> (&'static str, &'static str) {
    match rule {
        RuleId::PortScan => ("Ingressd Port Scan", "A single public peer contacted many distinct hosts/ports with SYN-only packets (horizontal or vertical scan)."),
        RuleId::InvalidTcpFlags => ("Ingressd Invalid TCP Flags", "NULL, XMAS, FIN-only, SYN+FIN, or SYN+RST packets — typically crafted scan/evasion traffic."),
        RuleId::BruteForce => ("Ingressd Authentication Brute Force", "Repeated new connections from one peer to SSH/RDP/SMB/FTP/Telnet/VNC/WinRM/DB ports."),
        RuleId::SynFlood => ("Ingressd TCP SYN Flood", "SYN rate to a local endpoint far above baseline with a low handshake completion ratio."),
        RuleId::UdpFlood => ("Ingressd UDP Flood", "High per-target UDP packet rate."),
        RuleId::IcmpFlood => ("Ingressd ICMP Flood", "High per-target ICMP packet rate."),
        RuleId::ReflectionAmplification => ("Ingressd UDP Reflection/Amplification", "Unsolicited large UDP replies from known reflector ports with no matching request."),
        RuleId::DnsTunnel => ("Ingressd DNS Tunneling", "High-entropy/long/numerous QNAMEs or abnormal TXT/NULL volume toward one peer."),
        RuleId::IcmpTunnel => ("Ingressd ICMP Tunneling", "Oversized or high-rate ICMP echo payloads."),
        RuleId::Beaconing => ("Ingressd C2 Beaconing", "Outbound connections to one peer at near-constant intervals (low jitter)."),
        RuleId::ThreatIntelHit => ("Ingressd Threat-Intel Hit", "Peer matched a loaded blocklist feed."),
        RuleId::SuspiciousPort => ("Ingressd Suspicious Port", "Traffic involving a known backdoor/C2 port."),
        RuleId::NewListenerProbe => ("Ingressd No-Listener Probe", "Many sources probing a TCP port with no listening socket."),
        RuleId::CustomSignature => ("Ingressd Custom Signature", "A user-defined detection signature matched an event; see the signature name in the alert detail."),
    }
}

/// Emit one Sigma document for `rule`.
pub fn sigma_for(rule: RuleId) -> String {
    let (title, desc) = title_desc(rule);
    let id = uuid_for(rule.as_str());
    let mitre = rule.mitre();
    let tag = tactic_tag(rule);
    let level = sigma_level(rule);
    format!(
        concat!(
            "---\n",
            "title: {title}\n",
            "id: {id}\n",
            "status: stable\n",
            "description: {desc}\n",
            "author: ingressd\n",
            "logsource:\n",
            "  product: ingressd\n",
            "  service: alerts\n",
            "detection:\n",
            "  selection:\n",
            "    rule: '{key}'\n",
            "  condition: selection\n",
            "falsepositives:\n",
            "  - Legitimate administrative scanning or load-balancer/health-check traffic (allowlist these peers)\n",
            "  - Correctly-behaving periodic clients (for beaconing)\n",
            "level: {level}\n",
            "references:\n",
            "  - https://attack.mitre.org/techniques/{mitre}/\n",
            "tags:\n",
            "  - {tag}\n",
            "  - ingressd.{key}\n",
        ),
        title = title,
        id = id,
        desc = desc,
        key = rule.as_str(),
        mitre = mitre,
        level = level,
        tag = tag,
    )
}

/// Emit the whole Sigma rule pack as one multi-document YAML string.
pub fn sigma_pack() -> String {
    RuleId::ALL
        .iter()
        .map(|r| sigma_for(*r))
        .collect::<Vec<_>>()
        .join("")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pack_has_all_rules_and_valid_front_matter() {
        let pack = sigma_pack();
        assert_eq!(pack.matches("title: ").count(), RuleId::ALL.len());
        assert!(pack.contains("rule: 'port-scan'"));
        assert!(pack.contains("attack.command_and_control"));
        // ids must be distinct per rule
        let mut ids: Vec<&str> = pack.lines().filter(|l| l.starts_with("id: ")).collect();
        let before = ids.len();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), before, "sigma ids must be unique");
    }
}
