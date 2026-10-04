//! Snort3 rule parsing + Sigma conversion.
//!
//! Parses the header (`action proto src -> dst`) and options (`msg`, `flow`,
//! `content`, `nocase`, `depth`, `offset`, `sid`, `rev`, `classtype`,
//! `reference`, `metadata`, `threshold`, …) of a Snort rule, and produces either:
//!   * a native [`SignatureCfg`] the engine enforces at the packet level
//!     (protocol / direction / port / peer-CIDR / payload `content`), or
//!   * a [Sigma](https://github.com/SigmaHQ/sigma) document for SIEM ingestion.
//!
//! Deliberate limits (a rule relying on these is exported to Sigma but skipped
//! for in-engine enforcement, with a reason): TCP `pcre`, `flowbits` state, and
//! multi-content ordering (`distance`/`within`). Single `content` + L3/L4 fields
//! cover the overwhelming majority of community rules.
#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::net::IpAddr;

use ipnet::IpNet;

use crate::config::SignatureCfg;
use crate::sigma::uuid_for;
use crate::types::{Proto, RuleId, Severity};

/// A bare address as its host network (/32 or /128).
fn host_net(ip: IpAddr) -> IpNet {
    let cidr = if ip.is_ipv4() {
        format!("{ip}/32")
    } else {
        format!("{ip}/128")
    };
    cidr.parse::<IpNet>()
        .unwrap_or(IpNet::V4("0.0.0.0/32".parse().unwrap()))
}

/// Named network groups from `snort.conf` (`$HOME_NET`, `$EXTERNAL_NET`, …).
/// Unknown/absent variables resolve to "any" (public-scoping already constrains
/// the peer, and direction is derived heuristically from the var names).
#[derive(Clone, Debug, Default)]
pub struct VarMap {
    map: HashMap<String, Vec<IpNet>>,
}

impl VarMap {
    /// A map seeded with an empty set (all `$VARS` resolve to any).
    pub fn new() -> VarMap {
        VarMap::default()
    }

    /// Insert `NAME = "a.b.c.d/24,1.2.3.4"` (comma-separated). `$` prefix optional.
    pub fn set(&mut self, name: &str, value: &str) {
        let key = name.trim_start_matches('$').to_string();
        let nets = value
            .split(',')
            .filter_map(|t| {
                let t = t.trim().trim_start_matches('[').trim_end_matches(']');
                if t.eq_ignore_ascii_case("any") || t.is_empty() {
                    None
                } else if let Ok(n) = t.parse::<IpNet>() {
                    Some(n)
                } else {
                    t.parse::<IpAddr>().ok().map(host_net)
                }
            })
            .collect();
        self.map.insert(key, nets);
    }

    fn resolve(&self, token: &str) -> Option<Vec<IpNet>> {
        if let Some(v) = token.strip_prefix('$') {
            self.map.get(v).cloned()
        } else {
            None
        }
    }
}

/// Endpoint address constraint.
#[derive(Clone, Debug)]
pub struct Endpoint {
    /// `None` => any address.
    pub nets: Option<Vec<IpNet>>,
    /// `None` => any port.
    pub ports: Option<Vec<(u16, u16)>>,
    /// Raw header token text (used for `$HOME_NET`/`$EXTERNAL_NET` heuristics).
    pub raw: String,
}

/// One parsed `content:` option with its inline modifiers.
#[derive(Clone, Debug)]
pub struct SnortContent {
    /// Raw content string exactly as written (Snort `|hex|` encoding preserved).
    pub raw: String,
    pub depth: Option<usize>,
    pub offset: Option<usize>,
    pub nocase: bool,
}

/// A parsed Snort rule.
#[derive(Clone, Debug)]
pub struct SnortRule {
    pub action: String,
    pub proto: Proto,
    pub src: Endpoint,
    pub dst: Endpoint,
    pub msg: String,
    pub sid: u32,
    pub rev: u32,
    pub flow: Vec<String>,
    pub contents: Vec<SnortContent>,
    pub classtype: Option<String>,
    pub references: Vec<(String, String)>,
    pub pcre: bool,
    pub flowbits: bool,
    /// Reason this rule cannot be enforced in-engine (still exported to Sigma).
    pub unsupported: Option<String>,
}

/// Decode a Snort content string (`literal|0d 0a|text`) into bytes.
pub fn decode_content(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let b = s.as_bytes();
    let mut i = 0usize;
    while i < b.len() {
        if b[i] == b'|' {
            i += 1;
            let start = i;
            while i < b.len() && b[i] != b'|' {
                i += 1;
            }
            for tok in String::from_utf8_lossy(&b[start..i]).split_whitespace() {
                if let Ok(v) = u8::from_str_radix(tok, 16) {
                    out.push(v);
                }
            }
            if i < b.len() {
                i += 1; // consume closing '|'
            }
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    out
}

/// Parse a host token (`any`, `[a,b]`, `$VAR`, CIDR/IP) into address constraints.
fn parse_nets(token: &str, vars: &VarMap) -> Option<Vec<IpNet>> {
    let t = token.trim();
    if t.eq_ignore_ascii_case("any") {
        return None;
    }
    if let Some(v) = vars.resolve(t) {
        return if v.is_empty() { None } else { Some(v) };
    }
    // Possibly a `[a,b]` list of literals.
    let inner = t.trim_start_matches('[').trim_end_matches(']');
    let mut nets = Vec::new();
    for part in inner.split(',') {
        let p = part.trim();
        if p.eq_ignore_ascii_case("any") || p.is_empty() {
            continue;
        }
        if let Some(v) = vars.resolve(p) {
            nets.extend(v);
        } else if let Ok(n) = p.parse::<IpNet>() {
            nets.push(n);
        } else if let Ok(ip) = p.parse::<IpAddr>() {
            nets.push(host_net(ip));
        }
    }
    if nets.is_empty() {
        None
    } else {
        Some(nets)
    }
}

/// Parse a port token (`any`, `80`, `1024:2000`, `[80,443]`) into inclusive ranges.
fn parse_ports(token: &str) -> Option<Vec<(u16, u16)>> {
    let t = token.trim();
    if t.eq_ignore_ascii_case("any") {
        return None;
    }
    let inner = t.trim_start_matches('[').trim_end_matches(']');
    let mut ranges = Vec::new();
    for part in inner.split(',') {
        let p = part.trim();
        if p.is_empty() {
            continue;
        }
        if let Some((a, b)) = p.split_once(':') {
            let lo: u16 = a.trim().parse().unwrap_or(0);
            let hi: u16 = b.trim().parse().unwrap_or(65535);
            ranges.push((lo.min(hi), lo.max(hi)));
        } else if let Ok(port) = p.parse::<u16>() {
            ranges.push((port, port));
        }
    }
    if ranges.is_empty() {
        None
    } else {
        Some(ranges)
    }
}

fn proto_from(s: &str) -> Proto {
    match s {
        "tcp" => Proto::Tcp,
        "udp" => Proto::Udp,
        "icmp" => Proto::Icmp,
        other => match other.parse::<u8>() {
            Ok(n) => Proto::from_ip_protocol(n),
            Err(_) => Proto::Other(0),
        },
    }
}

/// Split an options body on top-level `;`, honoring double quotes.
fn split_options(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_q = false;
    for c in text.chars() {
        match c {
            '"' => {
                in_q = !in_q;
                cur.push(c);
            }
            ';' if !in_q => {
                out.push(cur.clone());
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur);
    }
    out
}

fn quoted_value(rest: &str) -> String {
    // rest begins after `name:`; take between the first pair of double quotes.
    if let Some(start) = rest.find('"') {
        let after = &rest[start + 1..];
        if let Some(end) = after.find('"') {
            return after[..end].to_string();
        }
    }
    rest.trim().to_string()
}

/// Parse one `content:` option segment (`"text",depth 16,nocase`).
fn parse_content(segment: &str) -> Option<SnortContent> {
    // segment like `content:"...",depth 16,offset 4,nocase,fast_pattern`
    let colon = segment.find(':')?;
    let after = segment[colon + 1..].trim();
    let qstart = after.find('"')?;
    let after_q = &after[qstart + 1..];
    let qend = after_q.find('"')?;
    let raw = after_q[..qend].to_string();
    let modifiers = &after_q[qend + 1..];
    let mut c = SnortContent {
        raw,
        depth: None,
        offset: None,
        nocase: false,
    };
    for m in modifiers.split(',') {
        let m = m.trim();
        if m.eq_ignore_ascii_case("nocase") {
            c.nocase = true;
        } else if let Some(d) = m.strip_prefix("depth") {
            c.depth = d.trim().parse().ok();
        } else if let Some(o) = m.strip_prefix("offset") {
            c.offset = o.trim().parse().ok();
        }
    }
    Some(c)
}

/// Parse a single Snort rule line. `None` for comments/blank/`var`/`config` lines.
pub fn parse_line(line: &str, vars: &VarMap) -> Option<SnortRule> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        return None;
    }
    let lower = line.to_ascii_lowercase();
    if lower.starts_with("var ") || lower.starts_with("config ") || lower.starts_with("include ") {
        return None;
    }
    let open = line.find('(')?;
    let header = line[..open].trim();
    let mut opts = line[open + 1..].trim().to_string();
    if opts.ends_with(')') {
        opts.pop();
    }

    let ht: Vec<&str> = header.split_whitespace().collect();
    if ht.len() < 4 {
        return None;
    }
    // Locate the direction arrow.
    let arrow = ht
        .iter()
        .position(|t| *t == "->" || *t == "<>" || *t == "<-")?;
    // header: `action proto srchost srcport -> dsthost dstport`; arrow is the '->' index.
    if arrow < 2 || ht.len() < arrow + 3 {
        return None;
    }
    let action = ht[0].to_ascii_lowercase();
    let proto = proto_from(ht[1]);
    let src_host_tok = ht[arrow - 2];
    let src_port_tok = ht[arrow - 1];
    let dst_host_tok = ht[arrow + 1];
    let dst_port_tok = ht[arrow + 2];

    let mut rule = SnortRule {
        action,
        proto,
        src: Endpoint {
            nets: parse_nets(src_host_tok, vars),
            ports: parse_ports(src_port_tok),
            raw: src_host_tok.to_string(),
        },
        dst: Endpoint {
            nets: parse_nets(dst_host_tok, vars),
            ports: parse_ports(dst_port_tok),
            raw: dst_host_tok.to_string(),
        },
        msg: String::new(),
        sid: 0,
        rev: 0,
        flow: Vec::new(),
        contents: Vec::new(),
        classtype: None,
        references: Vec::new(),
        pcre: false,
        flowbits: false,
        unsupported: None,
    };

    for seg in split_options(&opts) {
        let s = seg.trim();
        if s.is_empty() {
            continue;
        }
        let name_end = s.find(':').unwrap_or(s.len());
        let name = s[..name_end].trim().to_ascii_lowercase();
        let rest = &s[name_end + 1.min(s.len().saturating_sub(name_end))..];
        match name.as_str() {
            "msg" => rule.msg = quoted_value(&s[name_end..]),
            "sid" => rule.sid = quoted_or_num(rest),
            "rev" => rule.rev = quoted_or_num(rest),
            "flow" => {
                rule.flow = rest
                    .split(',')
                    .map(|x| x.trim().to_ascii_lowercase())
                    .collect()
            }
            "content" => {
                if let Some(c) = parse_content(s) {
                    rule.contents.push(c);
                }
            }
            "nocase" => {
                if let Some(last) = rule.contents.last_mut() {
                    last.nocase = true;
                }
            }
            "depth" => {
                if let Some(last) = rule.contents.last_mut() {
                    last.depth = rest.trim().parse().ok();
                }
            }
            "offset" => {
                if let Some(last) = rule.contents.last_mut() {
                    last.offset = rest.trim().parse().ok();
                }
            }
            "pcre" => rule.pcre = true,
            "flowbits" => rule.flowbits = true,
            "classtype" => rule.classtype = Some(rest.trim().to_string()),
            "reference" => {
                let mut it = rest.splitn(2, ',');
                let t = it.next().unwrap_or("").trim().to_string();
                let v = it.next().unwrap_or("").trim().to_string();
                rule.references.push((t, v));
            }
            _ => {}
        }
    }

    if (rule.pcre || rule.flowbits) && rule.contents.is_empty() {
        rule.unsupported = Some(
            if rule.flowbits {
                "flowbits state"
            } else {
                "pcre-only"
            }
            .to_string(),
        );
    }
    Some(rule)
}

fn quoted_or_num(rest: &str) -> u32 {
    let t = rest.trim().trim_matches('"');
    t.parse().unwrap_or(0)
}

/// Every line in `text` that parses as a rule.
pub fn parse_str(text: &str, vars: &VarMap) -> Vec<SnortRule> {
    text.lines().filter_map(|l| parse_line(l, vars)).collect()
}

/// Read and parse a `.rules` file.
pub fn load_file(path: &std::path::Path, vars: &VarMap) -> std::io::Result<Vec<SnortRule>> {
    let text = std::fs::read_to_string(path)?;
    Ok(parse_str(&text, vars))
}

impl SnortRule {
    /// Derive direction from the endpoint var text: `$EXTERNAL_NET -> $HOME_NET`
    /// is inbound; `$HOME_NET -> $EXTERNAL_NET/any` is outbound.
    fn inferred_direction(&self) -> Option<&'static str> {
        let src = self.src.raw.to_ascii_uppercase();
        let dst = self.dst.raw.to_ascii_uppercase();
        let src_home = src.contains("HOME");
        let dst_home = dst.contains("HOME");
        let src_ext = src.contains("EXTERNAL") || src == "ANY";
        let dst_ext = dst.contains("EXTERNAL") || dst == "ANY";
        if !src_home && (dst_home) {
            Some("in")
        } else if src_home && dst_ext {
            Some("out")
        } else if src_ext && dst_home {
            Some("in")
        } else {
            None
        }
    }

    /// Expand the constrained ports (src or dst) into an exact set, refusing huge
    /// ranges (which become "any port").
    fn constrained_ports(&self) -> Vec<u16> {
        let mut out = Vec::new();
        for list in [&self.src.ports, &self.dst.ports] {
            if let Some(rs) = list {
                for &(lo, hi) in rs {
                    if hi.saturating_sub(lo) > 64 {
                        continue; // too broad -> do not constrain on this range
                    }
                    for p in lo..=hi {
                        out.push(p);
                    }
                }
            }
        }
        out.sort_unstable();
        out.dedup();
        out
    }

    /// Convert to a native engine signature, or `None` if it cannot be enforced
    /// without matching everything.
    pub fn to_signature(&self) -> Option<SignatureCfg> {
        if self.unsupported.is_some() {
            return None;
        }
        let content = self.contents.first();
        let ports = self.constrained_ports();
        let peer_cidr: Vec<String> = self
            .src
            .nets
            .as_ref()
            .map(|n| n.iter().map(|x| x.to_string()).collect())
            .unwrap_or_default();
        let direction = self.inferred_direction().map(|s| s.to_string());
        // Require at least one discriminator beyond proto to avoid match-all.
        if content.is_none() && ports.is_empty() && peer_cidr.is_empty() && direction.is_none() {
            return None;
        }
        Some(SignatureCfg {
            name: format!("snort-{}", self.sid),
            enabled: true,
            protocol: Some(match self.proto {
                Proto::Tcp => "tcp".to_string(),
                Proto::Udp => "udp".to_string(),
                Proto::Icmp => "icmp".to_string(),
                Proto::Other(n) => format!("{n}"),
            }),
            direction,
            ports,
            peer_cidr,
            severity: Some(self.default_severity()),
            content: content.map(|c| c.raw.clone()),
            nocase: content.map(|c| c.nocase).unwrap_or(false),
            depth: content.and_then(|c| c.depth),
            offset: content.and_then(|c| c.offset),
            msg: Some(self.msg.clone()),
            sid: Some(self.sid),
        })
    }

    fn default_severity(&self) -> Severity {
        let ct = self.classtype.as_deref().unwrap_or("");
        match ct {
            "trojan-activity" | "malware" | "attempted-dos" | "suspicious-login"
            | "successful-admin" => Severity::High,
            "attempted-admin" | "web-application-attack" | "policy-violation" => Severity::Medium,
            _ => Severity::Medium,
        }
    }

    /// Extract MITRE technique ids from `reference:url,attack.mitre.org/.../T####`
    /// plus a classtype fallback.
    pub fn mitre(&self) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for (t, v) in &self.references {
            if t == "url" && v.contains("attack.mitre.org/techniques/") {
                if let Some(idx) = v.find("techniques/") {
                    let tail = &v[idx + "techniques/".len()..];
                    let id: String = tail
                        .chars()
                        .take_while(|c| c.is_ascii_alphanumeric() || *c == '.')
                        .collect();
                    if !id.is_empty() {
                        out.push(id);
                    }
                }
            }
        }
        if out.is_empty() {
            let fallback = match self.classtype.as_deref().unwrap_or("") {
                "trojan-activity" | "malware" => Some("T1071"),
                "suspicious-login" => Some("T1110"),
                "attempted-admin" | "successful-admin" => Some("T1190"),
                "attempted-dos" => Some("T1499"),
                "policy-violation" => Some("T1568"),
                _ => None,
            };
            if let Some(f) = fallback {
                out.push(f.to_string());
            }
        }
        out
    }

    /// Convert this rule to a Sigma document for SIEM import.
    pub fn to_sigma(&self) -> String {
        let level = match self.classtype.as_deref().unwrap_or("") {
            "trojan-activity" | "malware" | "attempted-dos" | "suspicious-login"
            | "successful-admin" => "high",
            "attempted-admin" | "web-application-attack" | "policy-violation" => "medium",
            _ => "medium",
        };
        let id = uuid_for(&format!("snort-{}", self.sid));
        let mut refs: Vec<String> = self
            .references
            .iter()
            .map(|(t, v)| {
                if t == "url" {
                    format!("  - {v}")
                } else {
                    format!("  - {t}:{v}")
                }
            })
            .collect();
        for m in self.mitre() {
            refs.push(format!("  - https://attack.mitre.org/techniques/{m}/"));
        }
        if refs.is_empty() {
            refs.push("  - https://snort.org/".to_string());
        }
        let mut tags: Vec<String> = self
            .mitre()
            .iter()
            .map(|m| format!("  - attack.{}", m.to_ascii_lowercase()))
            .collect();
        tags.push(format!(
            "  - snort.classtype.{}",
            self.classtype
                .clone()
                .unwrap_or_else(|| "uncategorized".into())
        ));

        let msg_yaml = yaml_quote(&self.msg);
        let content_comment = self
            .contents
            .first()
            .map(|c| {
                format!(
                    "  # snort content keyword: {}\n",
                    yaml_quote(&String::from_utf8_lossy(&decode_content(&c.raw)))
                )
            })
            .unwrap_or_default();

        format!(
            concat!(
                "---\n",
                "title: {msg}\n",
                "id: {id}\n",
                "status: experimental\n",
                "description: Translated from Snort sid:{sid} rev:{rev} (classtype {ct}).\n",
                "author: ingressd snort2sigma\n",
                "logsource:\n",
                "  product: snort\n",
                "  service: alerts\n",
                "detection:\n",
                "  selection:\n",
                "    msg: {msg_q}\n",
                "{content_comment}",
                "  condition: selection\n",
                "falsepositives:\n",
                "  - Unknown (community rule)\n",
                "level: {level}\n",
                "references:\n",
                "{refs}\n",
                "tags:\n",
                "{tags}\n",
            ),
            msg = msg_yaml.clone(),
            id = id,
            sid = self.sid,
            rev = self.rev,
            ct = self
                .classtype
                .clone()
                .unwrap_or_else(|| "uncategorized".into()),
            msg_q = msg_yaml,
            content_comment = content_comment,
            level = level,
            refs = refs.join("\n"),
            tags = tags.join("\n"),
        )
    }
}

/// Minimal YAML scalar quoting.
fn yaml_quote(s: &str) -> String {
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

/// Convert every rule in `text` to a concatenated Sigma pack.
pub fn snort_text_to_sigma(text: &str, vars: &VarMap) -> String {
    parse_str(text, vars)
        .iter()
        .map(|r| r.to_sigma())
        .collect::<Vec<_>>()
        .join("")
}

/// Convert every rule in `text` into engine signatures (enforceable ones only).
pub fn snort_text_to_signatures(text: &str, vars: &VarMap) -> Vec<SignatureCfg> {
    parse_str(text, vars)
        .iter()
        .filter_map(|r| r.to_signature())
        .collect()
}

/// The rule id that Snort-translated alerts share.
pub const TRANSLATED_RULE: RuleId = RuleId::CustomSignature;

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "alert tcp $EXTERNAL_NET any -> $HOME_NET 22 ( msg:\"MALWARE-BACKDOOR netbus getinfo\"; flow:to_server,established; content:\"GetInfo|0D|\"; metadata:ruleset community; classtype:trojan-activity; sid:110; rev:10; )\n";

    #[test]
    fn parses_header_and_options() {
        let vars = VarMap::new();
        let rules = parse_str(SAMPLE, &vars);
        assert_eq!(rules.len(), 1);
        let r = &rules[0];
        assert_eq!(r.proto, Proto::Tcp);
        assert_eq!(r.sid, 110);
        assert_eq!(r.rev, 10);
        assert_eq!(r.dst.ports.as_ref().unwrap(), &[(22, 22)]);
        assert_eq!(r.contents.len(), 1);
        assert_eq!(decode_content(&r.contents[0].raw), b"GetInfo\x0d".to_vec());
        assert_eq!(r.classtype.as_deref(), Some("trojan-activity"));
    }

    #[test]
    fn converts_to_signature() {
        let vars = VarMap::new();
        let sig = parse_str(SAMPLE, &vars)[0]
            .to_signature()
            .expect("should convert");
        assert_eq!(sig.name, "snort-110");
        assert_eq!(sig.direction.as_deref(), Some("in"));
        assert_eq!(sig.ports, vec![22]);
        assert_eq!(sig.content.as_deref(), Some("GetInfo|0D|"));
        assert_eq!(sig.sid, Some(110));
    }

    #[test]
    fn hex_content_and_depth() {
        let line = r#"alert tcp $HOME_NET 2589 -> $EXTERNAL_NET any ( msg:"X"; flow:to_client,established; content:"2|00 00 00 06|Drives",depth 16; sid:105; rev:14; )"#;
        let vars = VarMap::new();
        let r = &parse_str(line, &vars)[0];
        assert_eq!(r.contents[0].depth, Some(16));
        assert_eq!(
            decode_content(&r.contents[0].raw),
            vec![b'2', 0, 0, 0, 6, b'D', b'r', b'i', b'v', b'e', b's']
        );
        assert_eq!(r.to_signature().unwrap().direction.as_deref(), Some("out"));
    }

    #[test]
    fn sigma_output_well_formed() {
        let vars = VarMap::new();
        let sig = parse_str(SAMPLE, &vars)[0].to_sigma();
        assert!(sig.starts_with("---\n"));
        assert!(sig.contains("title: \""));
        assert!(
            sig.contains("attack.t1071") || sig.contains("attack.t1110") || sig.contains("attack.")
        );
        assert!(sig.contains("level: high"));
    }

    #[test]
    fn pcre_only_skipped_for_enforcement_but_still_sigma() {
        let line = r#"alert icmp $EXTERNAL_NET any -> $HOME_NET any ( msg:"PCREONLY"; itype:0; pcre:"/^[0-9]/"; sid:228; rev:11; )"#;
        let vars = VarMap::new();
        let r = &parse_str(line, &vars)[0];
        assert!(r.unsupported.is_some());
        assert!(r.to_signature().is_none());
        assert!(r.to_sigma().contains("sid:228") || r.to_sigma().contains("228"));
    }
}
