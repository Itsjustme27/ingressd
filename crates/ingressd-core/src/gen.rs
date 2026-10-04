//! Synthetic Ethernet/IPv4/TCP/UDP/ICMP/DNS frame builders.
//!
//! Used by the end-to-end replay test and the `ingressd pcapgen` tool to produce
//! representative attack and benign traffic. Checksums are left zero — the
//! decoders do not validate them. This is a library utility, not a packet-sending
//! facility: it returns bytes, it never injects onto a wire.

use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// TCP control-bit helpers.
pub const TCP_SYN: u8 = 0x02;
pub const TCP_ACK: u8 = 0x10;
pub const TCP_SYN_ACK: u8 = 0x12;
pub const TCP_FIN: u8 = 0x01;
pub const TCP_RST: u8 = 0x04;
pub const TCP_NULL: u8 = 0x00;
pub const TCP_XMAS: u8 = 0x29; // FIN+PSH+URG

const ETH_P_IP: [u8; 2] = [0x08, 0x00];

/// Wrap an IPv4 packet in an Ethernet frame.
pub fn ethernet(ipv4: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(14 + ipv4.len());
    f.extend_from_slice(&[0x00; 6]); // dst mac
    f.extend_from_slice(&[0x00; 6]); // src mac
    f.extend_from_slice(&ETH_P_IP);
    f.extend_from_slice(ipv4);
    f
}

/// Build an IPv4 header + transport payload.
fn ipv4(proto: u8, src: Ipv4Addr, dst: Ipv4Addr, l4: &[u8]) -> Vec<u8> {
    let total = 20 + l4.len();
    let mut p = Vec::with_capacity(total);
    p.push(0x45); // v4, IHL=5
    p.push(0); // tos
    p.extend_from_slice(&(total as u16).to_be_bytes());
    p.extend_from_slice(&[0, 0]); // id
    p.extend_from_slice(&[0, 0]); // flags + frag (unfragmented)
    p.push(64); // ttl
    p.push(proto);
    p.extend_from_slice(&[0, 0]); // checksum (not validated)
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    p.extend_from_slice(l4);
    p
}

/// TCP frame.
pub fn tcp(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    flags: u8,
    payload_len: usize,
) -> Vec<u8> {
    tcp_payload(src, dst, sport, dport, flags, &vec![0u8; payload_len])
}

/// TCP frame carrying an explicit `payload` slice.
pub fn tcp_payload(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut t = vec![0u8; 20];
    t[0..2].copy_from_slice(&sport.to_be_bytes());
    t[2..4].copy_from_slice(&dport.to_be_bytes());
    t[12] = 5 << 4; // data offset
    t[13] = flags;
    t.extend_from_slice(payload);
    ethernet(&ipv4(6, src, dst, &t))
}

/// UDP frame with `payload`.
pub fn udp(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut u = Vec::with_capacity(8 + payload.len());
    u.extend_from_slice(&sport.to_be_bytes());
    u.extend_from_slice(&dport.to_be_bytes());
    u.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    u.extend_from_slice(&[0, 0]); // checksum
    u.extend_from_slice(payload);
    ethernet(&ipv4(17, src, dst, &u))
}

/// ICMP echo frame (type 8 request / 0 reply) with an N-byte payload.
pub fn icmp_echo(src: Ipv4Addr, dst: Ipv4Addr, kind: u8, payload_len: usize) -> Vec<u8> {
    let mut i = Vec::with_capacity(8 + payload_len);
    i.push(kind);
    i.push(0); // code
    i.extend_from_slice(&[0, 0]); // checksum
    i.extend_from_slice(&[0, 1]); // id
    i.extend_from_slice(&[0, 2]); // seq
    i.extend(std::iter::repeat(0x41u8).take(payload_len)); // 'A' fill
    ethernet(&ipv4(1, src, dst, &i))
}

/// A minimal DNS query frame for `qname` (dot-separated), QTYPE default A(1).
pub fn dns_query(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, qname: &str, qtype: u16) -> Vec<u8> {
    let mut d = Vec::new();
    d.extend_from_slice(&[0x00, 0x01]); // id
    d.extend_from_slice(&[0, 0]); // flags: standard query
    d.extend_from_slice(&[0, 1]); // QDCOUNT
    d.extend_from_slice(&[0, 0]); // ANCOUNT
    d.extend_from_slice(&[0, 0]); // NSCOUNT
    d.extend_from_slice(&[0, 0]); // ARCOUNT
    for label in qname.split('.') {
        if label.is_empty() {
            continue;
        }
        let bytes = label.as_bytes();
        d.push(bytes.len() as u8);
        d.extend_from_slice(bytes);
    }
    d.push(0); // root label terminator
    d.extend_from_slice(&qtype.to_be_bytes());
    d.extend_from_slice(&[0, 1]); // class IN
    udp(src, dst, sport, 53, &d)
}

/// A TXT query on port 53 (qtype 16).
pub fn dns_txt(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, qname: &str) -> Vec<u8> {
    dns_query(src, dst, sport, qname, 16)
}

/// This host's address used by [`attack_scenario`] (globally routable, not a
/// reserved/documentation range so it survives public-IP scoping).
pub const HOST: Ipv4Addr = Ipv4Addr::new(5, 7, 9, 11);
/// A benign public peer that must never alert.
pub const BENIGN: Ipv4Addr = Ipv4Addr::new(150, 151, 152, 153);

/// An attacker address `200.201.202.<last>`.
pub fn attacker(last: u8) -> Ipv4Addr {
    Ipv4Addr::new(200, 201, 202, last)
}

/// A representative pcap scenario: one burst per detection rule, plus a benign
/// flow. Returns `(timestamp, ethernet frame)` in temporal order. Shared by the
/// end-to-end test and the `ingressd pcapgen` tool.
pub fn attack_scenario() -> Vec<(SystemTime, Vec<u8>)> {
    let base = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    let at = |secs: u64| base + Duration::from_secs(secs);
    let mut s: Vec<(SystemTime, Vec<u8>)> = Vec::new();

    // benign: established ACKs to :443.
    for i in 0..2u16 {
        s.push((at(0), tcp(BENIGN, HOST, 50000 + i, 443, TCP_ACK, 200)));
    }
    // port-scan: one source, 6 distinct ports.
    for p in 0..6u16 {
        s.push((at(1), tcp(attacker(1), HOST, 40000, 1000 + p, TCP_SYN, 0)));
    }
    // brute-force: 5 SYNs to SSH.
    for _ in 0..5u16 {
        s.push((at(2), tcp(attacker(2), HOST, 41000, 22, TCP_SYN, 0)));
    }
    // invalid flags: NULL / XMAS.
    s.push((at(3), tcp(attacker(3), HOST, 42000, 443, TCP_NULL, 0)));
    s.push((at(3), tcp(attacker(3), HOST, 42001, 443, TCP_XMAS, 0)));
    s.push((at(3), tcp(attacker(3), HOST, 42002, 443, TCP_NULL, 0)));
    s.push((at(3), tcp(attacker(3), HOST, 42003, 443, TCP_XMAS, 0)));
    // udp-flood.
    for _ in 0..12u16 {
        s.push((at(4), udp(attacker(4), HOST, 33000, 30000, b"hi")));
    }
    // icmp-flood.
    for _ in 0..12u16 {
        s.push((at(5), icmp_echo(attacker(5), HOST, 8, 20)));
    }
    // icmp-tunnel: oversized echoes.
    for _ in 0..4u16 {
        s.push((at(6), icmp_echo(attacker(6), HOST, 8, 600)));
    }
    // reflection: unsolicited large 53-source replies.
    for _ in 0..4u16 {
        s.push((at(7), udp(attacker(7), HOST, 53, 45000, &vec![0u8; 600])));
    }
    // dns-tunnel: 6 distinct high-entropy queries.
    let names = [
        "a1b2c3d4e5.tunnel9f.example.org",
        "ff00aa55bb.tunnel1x.example.org",
        "9z8y7x6w.tunnel2q.example.org",
        "deadbeefcafe.tunnel3w.example.org",
        "0123abcdxy.tunnel4e.example.org",
        "q7w8e9r0t1.tunnel5r.example.org",
    ];
    for (i, n) in names.iter().enumerate() {
        s.push((
            at(8 + i as u64),
            dns_query(HOST, attacker(8), 51000 + i as u16, n, 1),
        ));
    }
    // beaconing: 4 outbound connections at exact 60s spacing.
    for i in 0..4u64 {
        s.push((
            at(100 + i * 60),
            tcp(HOST, attacker(9), 52000, 9999, TCP_SYN, 0),
        ));
    }
    // threat-intel: one listed IP.
    s.push((at(200), tcp(attacker(10), HOST, 43000, 80, TCP_ACK, 10)));
    // suspicious-port: traffic on 4444.
    s.push((at(201), tcp(attacker(11), HOST, 44000, 4444, TCP_ACK, 10)));
    // new-listener-probe: 3 sources to an un-listened port.
    for last in [12u8, 13, 14] {
        s.push((at(202), tcp(attacker(last), HOST, 46000, 65000, TCP_SYN, 0)));
    }
    // syn-flood: 25 SYNs to :80, 2 SYN-ACK completions.
    for i in 0..25u16 {
        s.push((
            at(300 + i as u64 / 10),
            tcp(
                attacker(20 + (i % 10) as u8),
                HOST,
                47000 + i,
                80,
                TCP_SYN,
                0,
            ),
        ));
    }
    for i in 0..2u16 {
        s.push((
            at(302),
            tcp(HOST, attacker(20 + i as u8), 80, 47000 + i, TCP_SYN_ACK, 0),
        ));
    }
    s
}

/// Total frames in [`attack_scenario`].
pub fn scenario_len() -> usize {
    attack_scenario().len()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decode::decode_frame;
    use std::net::IpAddr;

    #[test]
    fn tcp_syn_roundtrips_through_decoder() {
        let src = Ipv4Addr::new(203, 0, 113, 7);
        let dst = Ipv4Addr::new(198, 51, 100, 5);
        let frame = tcp(src, dst, 40000, 22, TCP_SYN, 0);
        let pkt = decode_frame(&frame).unwrap();
        assert_eq!(IpAddr::V4(src), pkt.src_ip);
        match pkt.transport {
            crate::decode::Transport::Tcp(t) => {
                assert!(t.flags.is_syn_only());
                assert_eq!(t.dst, 22);
            }
            _ => panic!("expected tcp"),
        }
    }

    #[test]
    fn dns_qname_roundtrips() {
        let frame = dns_query(
            Ipv4Addr::new(203, 0, 113, 9),
            Ipv4Addr::new(8, 8, 8, 8),
            51234,
            "sub.example.com",
            1,
        );
        let pkt = decode_frame(&frame).unwrap();
        match pkt.transport {
            crate::decode::Transport::Udp(u) => {
                let q = u.dns.expect("dns parsed");
                assert_eq!(q.qname, "sub.example.com");
            }
            _ => panic!("expected udp"),
        }
    }
}
