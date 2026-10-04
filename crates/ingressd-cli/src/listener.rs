//! Read the set of locally-listening TCP ports from `/proc/net/tcp{,6}` so the
//! `new-listener-probe` rule can tell a probe-of-nothing from a real service.
//! Returns an empty set on non-Linux systems (the rule then no-ops).

use std::collections::HashSet;
use std::fs;

/// Parse one `/proc/net/tcp`-style file, collecting listening (state `0A`) ports.
fn parse_proc_tcp(path: &str, out: &mut HashSet<u16>) {
    if let Ok(text) = fs::read_to_string(path) {
        for line in text.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 4 {
                continue;
            }
            // f[3] is the connection state; 0A == LISTEN.
            if f[3].eq_ignore_ascii_case("0A") {
                // f[1] local_address == "HEXIP:HEXPORT"
                if let Some(port_hex) = f[1].rsplit(':').next() {
                    if let Ok(port) = u32::from_str_radix(port_hex, 16) {
                        out.insert(port as u16);
                    }
                }
            }
        }
    }
}

/// The current listening TCP port set (IPv4 + IPv6).
pub fn listen_ports() -> HashSet<u16> {
    let mut set = HashSet::new();
    parse_proc_tcp("/proc/net/tcp", &mut set);
    parse_proc_tcp("/proc/net/tcp6", &mut set);
    set
}

/// Nameserver addresses from `/etc/resolv.conf` (never block these).
pub fn resolver_ips() -> Vec<std::net::IpAddr> {
    let mut out = Vec::new();
    if let Ok(text) = fs::read_to_string("/etc/resolv.conf") {
        for line in text.lines() {
            let mut it = line.split_whitespace();
            if it.next() == Some("nameserver") {
                if let Some(ip) = it.next().and_then(|s| s.parse::<std::net::IpAddr>().ok()) {
                    out.push(ip);
                }
            }
        }
    }
    out
}
