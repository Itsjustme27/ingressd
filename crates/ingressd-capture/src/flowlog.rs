//! VPC Flow Log input for environments where packet capture is not possible.
//!
//! Supports AWS flow logs (space-delimited text or JSON) and GCP flow logs
//! (JSON) through the same engine. Flow records are aggregated (one event per
//! flow, no TCP flags), so connection-oriented rules (port-scan, brute-force,
//! beaconing, new-listener, threat-intel) work as-is while rate-based flood
//! rules see per-flow rather than per-packet counts. TCP flows are marked as a
//! SYN so they are treated as new connections.
#![forbid(unsafe_code)]

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ingressd_core::metrics::Counters;
use ingressd_core::scope;
use ingressd_core::types::{Direction, PacketEvent, Proto, TcpFlags};
use serde_json::Value;

use crate::{EventTx, HostHandle};

struct FlowRecord {
    src: IpAddr,
    dst: IpAddr,
    sport: Option<u16>,
    dport: Option<u16>,
    proto: u8,
    start: u64,
}

/// Parse one flow-log line into a scoped [`PacketEvent`], or `None`.
pub fn parse_line(line: &str, host: &HostHandle) -> Option<PacketEvent> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let rec = if line.starts_with('{') {
        parse_json(line)?
    } else {
        // AWS text header line: "version accountId ...".
        if line.starts_with("version") {
            return None;
        }
        parse_aws_text(line)?
    };

    let (direction, local_ip, peer_ip) = derive_direction(&rec, host)?;
    if !scope::is_public_global(peer_ip) {
        return None;
    }

    let proto = Proto::from_ip_protocol(rec.proto);
    let tcp_flags = if proto == Proto::Tcp {
        // Flow logs carry no TCP flags; treat each TCP flow as one new connection.
        Some(TcpFlags::from_bits(0x02))
    } else {
        None
    };

    Some(PacketEvent {
        ts: epoch(rec.start),
        direction,
        local_ip,
        peer_ip,
        src_ip: rec.src,
        dst_ip: rec.dst,
        proto,
        src_port: rec.sport,
        dst_port: rec.dport,
        tcp_flags,
        icmp: None,
        dns: None,
        payload_len: 0,
        payload: Vec::new(),
        ip_total_len: 0,
        fragmented: false,
        first_fragment: true,
    })
}

fn derive_direction(rec: &FlowRecord, host: &HostHandle) -> Option<(Direction, IpAddr, IpAddr)> {
    let classified = {
        let h = host.read().unwrap_or_else(|p| p.into_inner());
        h.classify(rec.src, rec.dst)
    };
    if let Some(x) = classified {
        return Some(x);
    }
    // Host addrs unknown (common in flow-log mode): the public side is the peer.
    let src_pub = scope::is_public_global(rec.src);
    let dst_pub = scope::is_public_global(rec.dst);
    match (src_pub, dst_pub) {
        (true, false) => Some((Direction::Inbound, rec.dst, rec.src)),
        (false, true) => Some((Direction::Outbound, rec.src, rec.dst)),
        (true, true) => Some((Direction::Inbound, rec.dst, rec.src)),
        (false, false) => None,
    }
}

fn parse_aws_text(line: &str) -> Option<FlowRecord> {
    let f: Vec<&str> = line.split_whitespace().collect();
    if f.len() < 13 {
        return None;
    }
    let src = f[3].parse().ok()?;
    let dst = f[4].parse().ok()?;
    let sport = parse_opt_port(f[5]);
    let dport = parse_opt_port(f[6]);
    let proto = f[7].parse::<u8>().unwrap_or(0);
    let start = f[10].parse::<u64>().unwrap_or(0);
    Some(FlowRecord { src, dst, sport, dport, proto, start })
}

fn parse_json(line: &str) -> Option<FlowRecord> {
    let v: Value = serde_json::from_str(line).ok()?;
    let src = field(&v, &["srcaddr", "src_ip", "srcIp", "sourceIPAddress"]).and_then(|s| s.parse().ok())?;
    let dst = field(&v, &["dstaddr", "dst_ip", "dstIp", "destinationIPAddress"]).and_then(|s| s.parse().ok())?;
    let sport = field(&v, &["srcport", "src_port", "srcPort"]).and_then(parse_opt_port_owned);
    let dport = field(&v, &["dstport", "dst_port", "dstPort"]).and_then(parse_opt_port_owned);
    let proto = field(&v, &["protocol"]).and_then(|s| s.parse::<u8>().ok()).unwrap_or(0);
    let start = field(&v, &["start", "start_time", "startTime"]).and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
    Some(FlowRecord { src, dst, sport, dport, proto, start })
}

/// Return the first present field as a string (numbers stringified).
fn field<'a>(v: &'a Value, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(x) = v.get(*k) {
            match x {
                Value::String(s) => return Some(s.clone()),
                Value::Number(n) => return Some(n.to_string()),
                Value::Null => {}
                _ => {}
            }
        }
    }
    None
}

fn parse_opt_port(s: &str) -> Option<u16> {
    s.parse::<u16>().ok()
}

fn parse_opt_port_owned(s: String) -> Option<u16> {
    s.parse::<u16>().ok()
}

fn epoch(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

/// Spawn a thread that parses a flow-log file (`-` = stdin) into `tx`.
pub fn spawn(path: &Path, host: HostHandle, tx: EventTx, counters: Arc<Counters>) -> JoinHandle<()> {
    let path = path.to_path_buf();
    std::thread::Builder::new()
        .name("ingressd-flowlog".to_string())
        .spawn(move || run(&path, &host, &tx, &counters))
        .expect("spawn flowlog thread")
}

fn run(path: &Path, host: &HostHandle, tx: &EventTx, counters: &Counters) {
    let reader: Box<dyn BufRead> = if path.to_str() == Some("-") {
        Box::new(BufReader::new(std::io::stdin()))
    } else {
        match File::open(path) {
            Ok(f) => Box::new(BufReader::new(f)),
            Err(e) => {
                tracing::error!(path = %path.display(), "cannot open flow log: {e}");
                return;
            }
        }
    };

    for line in reader.lines() {
        match line {
            Ok(l) => {
                if let Some(ev) = parse_line(&l, host) {
                    counters.inc_packets(1);
                    if tx.blocking_send(ev).is_err() {
                        break;
                    }
                }
            }
            Err(e) => {
                tracing::warn!("flow log read error: {e}");
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ingressd_core::scope::HostAddrs;
    use std::str::FromStr;

    fn host() -> HostHandle {
        Arc::new(std::sync::RwLock::new(HostAddrs::new()))
    }

    #[test]
    fn aws_text_inbound() {
        let line = "2 123456 eni-1 203.0.113.9 198.51.100.5 51234 22 6 1 60 1700000000 1700000001 ACCEPT OK";
        let ev = parse_line(line, &host()).unwrap();
        assert_eq!(ev.direction, Direction::Inbound);
        assert_eq!(ev.peer_ip, IpAddr::from_str("203.0.113.9").unwrap());
        assert_eq!(ev.dst_port, Some(22));
        assert_eq!(ev.proto, Proto::Tcp);
    }

    #[test]
    fn aws_json_inbound() {
        let line = r#"{"version":2,"srcaddr":"203.0.113.9","dstaddr":"198.51.100.5","srcport":"51234","dstport":"22","protocol":"6","start":"1700000000"}"#;
        let ev = parse_line(line, &host()).unwrap();
        assert_eq!(ev.peer_ip, IpAddr::from_str("203.0.113.9").unwrap());
    }

    #[test]
    fn gcp_json_inbound() {
        let line = r#"{"src_ip":"203.0.113.9","dst_ip":"198.51.100.5","src_port":51234,"dst_port":443,"protocol":6,"packets":3}"#;
        let ev = parse_line(line, &host()).unwrap();
        assert_eq!(ev.dst_port, Some(443));
        assert_eq!(ev.direction, Direction::Inbound);
    }

    #[test]
    fn private_only_skipped() {
        let line = "2 1 2 10.0.0.1 10.0.0.2 5 6 7 6 1 60 1 2 ACCEPT OK";
        assert!(parse_line(line, &host()).is_none());
    }
}
