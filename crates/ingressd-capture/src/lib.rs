//! `ingressd-capture` — capture inputs that decode link-layer frames (or VPC
//! flow-log records) into scoped [`PacketEvent`]s and hand them to the async
//! engine over a bounded channel.
//!
//! Layout:
//! - [`pcap_file`] — offline `.pcap` replay (portable, used by all tests).
//! - [`flowlog`] — AWS/GCP VPC Flow Log parsing (portable).
//! - [`afpacket`] — live AF_PACKET capture (Linux only, `live-capture` feature,
//!   the single `unsafe` module in the workspace).
//!
//! The crate allows `unsafe` only inside `afpacket`; the other modules forbid it
//! locally.
#![warn(unsafe_code)]

pub mod flowlog;
pub mod pcap_file;

#[cfg(all(target_os = "linux", feature = "live-capture"))]
pub mod afpacket;

use std::sync::Arc;
use std::sync::RwLock;
use std::time::SystemTime;

use ingressd_core::decode::{self, DecodeError, RawPacket, Transport};
use ingressd_core::metrics::Counters;
use ingressd_core::scope::{self, HostAddrs};
use ingressd_core::types::PacketEvent;
use ingressd_core::types::Proto;

/// Bounded sender of decoded events (capture threads -> engine task).
pub type EventTx = tokio::sync::mpsc::Sender<PacketEvent>;
/// Corresponding receiver.
pub type EventRx = tokio::sync::mpsc::Receiver<PacketEvent>;

/// The host address set, shared so a refresh task can update it while capture
/// threads read it.
pub type HostHandle = Arc<RwLock<HostAddrs>>;

/// Create a bounded event channel (capacity is clamped to >= 1).
pub fn event_channel(capacity: usize) -> (EventTx, EventRx) {
    let (tx, rx) = tokio::sync::mpsc::channel(capacity.max(1));
    (tx, rx)
}

/// What live capture does when the bounded channel is full.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueuePolicy {
    /// Fail-open: shed load, keep capturing, count drops.
    Drop,
    /// Apply backpressure (block until the consumer drains).
    Stall,
    /// Fail-closed: stop capture so we never silently miss packets under load.
    Exit,
}

impl QueuePolicy {
    /// Parse the `general.on_queue_full` string (defaults to Drop).
    pub fn parse(s: &str) -> QueuePolicy {
        match s {
            "stall" => QueuePolicy::Stall,
            "exit" => QueuePolicy::Exit,
            _ => QueuePolicy::Drop,
        }
    }
}

/// Decode one link-layer frame into a public-scoped, direction-tagged event.
///
/// Returns `None` for non-IP frames (skipped), for traffic that does not involve
/// this host (transit on a mirror port), and for peers that are not globally
/// routable. Counters reflect parse errors and skipped non-public peers.
pub fn frame_to_event(bytes: &[u8], ts: SystemTime, host: &HostHandle, counters: &Counters) -> Option<PacketEvent> {
    match decode::decode_frame(bytes) {
        Ok(raw) => classify(raw, ts, host, counters),
        // ARP and other non-IP protocols are expected on a live wire: skip quietly.
        Err(DecodeError::Unsupported(_)) => None,
        // Malformed frames are a parse error worth counting.
        Err(_) => {
            counters.inc_parse_errors(1);
            None
        }
    }
}

fn classify(raw: RawPacket, ts: SystemTime, host: &HostHandle, counters: &Counters) -> Option<PacketEvent> {
    // Transit that does not involve this host (mirror noise) is skipped via `?`.
    let (direction, local_ip, peer_ip) = {
        let h = host.read().unwrap_or_else(|p| p.into_inner());
        h.classify(raw.src_ip, raw.dst_ip)?
    };

    if !scope::is_public_global(peer_ip) {
        counters.inc_skipped_nonpublic(1);
        return None;
    }

    let (src_port, dst_port, proto, tcp_flags, icmp, dns, payload_len, payload) = match raw.transport {
        Transport::Tcp(t) => (Some(t.src), Some(t.dst), Proto::Tcp, Some(t.flags), None, None, t.payload_len, t.payload),
        Transport::Udp(u) => (Some(u.src), Some(u.dst), Proto::Udp, None, None, u.dns, u.payload_len, u.payload),
        Transport::Icmp(i) => (None, None, Proto::Icmp, None, Some(i), None, i.payload_len, Vec::new()),
        Transport::Other => (None, None, Proto::Other(raw.ip_protocol), None, None, None, 0, Vec::new()),
    };

    Some(PacketEvent {
        ts,
        direction,
        local_ip,
        peer_ip,
        src_ip: raw.src_ip,
        dst_ip: raw.dst_ip,
        proto,
        src_port,
        dst_port,
        tcp_flags,
        icmp,
        dns,
        payload_len,
        payload,
        ip_total_len: raw.ip_total_len,
        fragmented: raw.fragmented,
        first_fragment: raw.first_fragment,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn host_with(addrs: &[&str]) -> HostHandle {
        let mut h = HostAddrs::new();
        h.set(addrs.iter().map(|s| s.parse::<IpAddr>().unwrap()));
        Arc::new(RwLock::new(h))
    }

    fn eth_tcp_frame(src: [u8; 4], dst: [u8; 4], syn: bool) -> Vec<u8> {
        let mut v = vec![0u8; 14];
        v[12] = 0x08;
        v[13] = 0x00;
        let mut ip = vec![0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0];
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&40000u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&22u16.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = if syn { 0x02 } else { 0x10 };
        v.extend_from_slice(&ip);
        v.extend_from_slice(&tcp);
        v
    }

    #[test]
    fn inbound_public_is_classified() {
        let host = host_with(&["198.51.100.5"]);
        let c = Counters::new();
        let frame = eth_tcp_frame([203, 0, 113, 9], [198, 51, 100, 5], true);
        let ev = frame_to_event(&frame, SystemTime::now(), &host, &c).unwrap();
        assert_eq!(ev.direction, ingressd_core::types::Direction::Inbound);
        assert_eq!(ev.peer_ip.to_string(), "203.0.113.9");
        assert_eq!(c.skipped_nonpublic(), 0);
    }

    #[test]
    fn private_peer_is_skipped() {
        let host = host_with(&["198.51.100.5"]);
        let c = Counters::new();
        let frame = eth_tcp_frame([10, 0, 0, 1], [198, 51, 100, 5], true);
        assert!(frame_to_event(&frame, SystemTime::now(), &host, &c).is_none());
        assert_eq!(c.skipped_nonpublic(), 1);
    }
}
