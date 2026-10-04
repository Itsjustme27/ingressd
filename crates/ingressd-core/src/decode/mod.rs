//! Bounds-checked, `unsafe`-free decoders for Ethernet / IPv4 / IPv6 / TCP / UDP /
//! ICMP / DNS. Every reader is total: malformed or truncated input returns an
//! error or `None`, never a panic and never reads out of bounds.

use std::net::IpAddr;

use crate::types::{DnsQuery, IcmpInfo, TcpFlags, MAX_PAYLOAD_SNAP};

/// Decoder failure modes.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    /// Input shorter than the minimum size for the parsed header.
    #[error("truncated: needed at least {needed} bytes, had {had}")]
    TooShort {
        /// Bytes required.
        needed: usize,
        /// Bytes available.
        had: usize,
    },
    /// A header layer we do not decode (non-IP ethertype, unknown protocol).
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
    /// A structurally invalid header (bad IHL, impossible lengths, loops).
    #[error("malformed: {0}")]
    Malformed(&'static str),
}

/// Result of decoding a whole frame.
#[derive(Clone, Debug)]
pub struct RawPacket {
    /// Source IP.
    pub src_ip: IpAddr,
    /// Destination IP.
    pub dst_ip: IpAddr,
    /// IP protocol number (6, 17, 1, 58, ...).
    pub ip_protocol: u8,
    /// Total length of the IP datagram in bytes.
    pub ip_total_len: u16,
    /// True when the datagram is a fragment.
    pub fragmented: bool,
    /// True when this is the first fragment (carries the L4 header).
    pub first_fragment: bool,
    /// The transport payload.
    pub transport: Transport,
}

/// Transport-layer view of a packet.
#[derive(Clone, Debug)]
pub enum Transport {
    /// TCP.
    Tcp(TcpInfo),
    /// UDP (with a best-effort DNS question when present).
    Udp(UdpInfo),
    /// ICMP / ICMPv6.
    Icmp(IcmpInfo),
    /// Anything else.
    Other,
}

/// TCP view.
#[derive(Clone, Debug)]
pub struct TcpInfo {
    /// Source port.
    pub src: u16,
    /// Destination port.
    pub dst: u16,
    /// Flags.
    pub flags: TcpFlags,
    /// Payload length (after the TCP header).
    pub payload_len: usize,
    /// Bounded payload snapshot for content matching.
    pub payload: Vec<u8>,
}

/// UDP view.
#[derive(Clone, Debug)]
pub struct UdpInfo {
    /// Source port.
    pub src: u16,
    /// Destination port.
    pub dst: u16,
    /// Payload length.
    pub payload_len: usize,
    /// Bounded payload snapshot for content matching.
    pub payload: Vec<u8>,
    /// Parsed DNS question when this is a well-formed DNS message.
    pub dns: Option<DnsQuery>,
}

// EtherTypes.
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_ARP: u16 = 0x0806;
const ETHERTYPE_IPV6: u16 = 0x86DD;
const ETHERTYPE_VLAN: u16 = 0x8100;
const ETHERTYPE_QINQ: u16 = 0x88A8;

/// A tiny bounds-checked cursor over a byte slice.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }
    fn u8(&mut self) -> Result<u8, DecodeError> {
        let b = *self
            .data
            .get(self.pos)
            .ok_or(DecodeError::TooShort { needed: 1, had: 0 })?;
        self.pos += 1;
        Ok(b)
    }
    fn u16(&mut self) -> Result<u16, DecodeError> {
        if self.remaining() < 2 {
            return Err(DecodeError::TooShort {
                needed: 2,
                had: self.remaining(),
            });
        }
        let v = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }
    fn u32(&mut self) -> Result<u32, DecodeError> {
        if self.remaining() < 4 {
            return Err(DecodeError::TooShort {
                needed: 4,
                had: self.remaining(),
            });
        }
        let v = u32::from_be_bytes([
            self.data[self.pos],
            self.data[self.pos + 1],
            self.data[self.pos + 2],
            self.data[self.pos + 3],
        ]);
        self.pos += 4;
        Ok(v)
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        if self.remaining() < n {
            return Err(DecodeError::TooShort {
                needed: n,
                had: self.remaining(),
            });
        }
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn rest(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }
}

/// Decode an Ethernet frame down to transport.
///
/// Handles single and double VLAN tags. Non-IP ethertypes (ARP, etc.) return
/// [`DecodeError::Unsupported`]; the caller counts those as parse errors or skips.
pub fn decode_frame(bytes: &[u8]) -> Result<RawPacket, DecodeError> {
    let mut r = Reader::new(bytes);
    // Ethernet: 6 dst + 6 src + ethertype.
    let _dst = r.take(6)?;
    let _src = r.take(6)?;
    let mut ethertype = r.u16()?;

    // Peel up to two VLAN tags.
    let mut tag_hops = 0;
    while (ethertype == ETHERTYPE_VLAN || ethertype == ETHERTYPE_QINQ) && tag_hops < 2 {
        // VLAN: 2 bytes TCI, then real ethertype.
        let _tci = r.u16()?;
        ethertype = r.u16()?;
        tag_hops += 1;
    }

    match ethertype {
        ETHERTYPE_IPV4 => decode_ipv4(r.rest()),
        ETHERTYPE_IPV6 => decode_ipv6(r.rest()),
        ETHERTYPE_ARP => Err(DecodeError::Unsupported("ARP")),
        other => Err(DecodeError::Unsupported(if other == 0 {
            "non-IP"
        } else {
            "unknown ethertype"
        })),
    }
}

fn decode_ipv4(bytes: &[u8]) -> Result<RawPacket, DecodeError> {
    let mut r = Reader::new(bytes);
    let vihl = r.u8()?; // version(4) | IHL(4)
    let version = vihl >> 4;
    let ihl = (vihl & 0x0F) as usize * 4;
    if version != 4 {
        return Err(DecodeError::Malformed("ipv4 version nibble"));
    }
    if ihl < 20 || r.data.len() < ihl {
        return Err(DecodeError::Malformed("ipv4 IHL too small"));
    }
    let _tos = r.u8()?;
    let total_len = r.u16()?;
    let identification = r.u16()?;
    let flags_frag = r.u16()?;
    let flags = (flags_frag >> 13) & 0x07;
    let frag_offset = flags_frag & 0x1FFF;
    let more_frags = flags & 0x01 != 0;
    let _ttl = r.u8()?;
    let protocol = r.u8()?;
    let _csum = r.u16()?;
    let src = IpAddr::from(r.take(4)?.try_to_array4()?);
    let dst = IpAddr::from(r.take(4)?.try_to_array4()?);

    // Options occupy the rest of the header.
    let header_end = ihl;
    if bytes.len() < header_end {
        return Err(DecodeError::TooShort {
            needed: header_end,
            had: bytes.len(),
        });
    }
    let l4_all = &bytes[header_end..];

    let fragmented = more_frags || frag_offset != 0;
    // Non-zero identification with a fragment and no "more fragments" is the last
    // fragment; either way we only inspect L4 in the first fragment.
    let first_fragment = frag_offset == 0;
    let _ = identification;

    let transport = if fragmented && !first_fragment {
        Transport::Other
    } else {
        decode_l4(protocol, l4_all)?
    };

    Ok(RawPacket {
        src_ip: src,
        dst_ip: dst,
        ip_protocol: protocol,
        ip_total_len: total_len,
        fragmented,
        first_fragment,
        transport,
    })
}

fn decode_ipv6(bytes: &[u8]) -> Result<RawPacket, DecodeError> {
    let mut r = Reader::new(bytes);
    let vtc0 = r.u32()?; // version(4)+tc(8)+flowlabel(20)
    let version = vtc0 >> 28;
    if version != 6 {
        return Err(DecodeError::Malformed("ipv6 version nibble"));
    }
    let payload_len = r.u16()? as usize;
    let next_header = r.u8()?;
    let _hoplimit = r.u8()?;
    let src = IpAddr::from(r.take(16)?.try_to_array16()?);
    let dst = IpAddr::from(r.take(16)?.try_to_array16()?);

    let mut nh = next_header;
    let mut ext = r.rest();
    let mut fragmented = false;
    let mut first_fragment = true;
    let mut hops = 0;

    // Walk extension headers, bounded to prevent loops.
    while hops < 8 {
        hops += 1;
        match nh {
            // Hop-by-hop(0), Routing(43), Destination(60/156 for some), AH(51), ESP(50), etc.
            0 | 43 | 60 | 135 | 139 | 140 | 253 | 254 => {
                if ext.len() < 2 {
                    return Err(DecodeError::TooShort {
                        needed: 2,
                        had: ext.len(),
                    });
                }
                nh = ext[0];
                let hdr_len = (ext[1] as usize + 1) * 8;
                if ext.len() < hdr_len {
                    return Err(DecodeError::Malformed("ipv6 ext header length"));
                }
                ext = &ext[hdr_len..];
            }
            44 => {
                // Fragment header.
                if ext.len() < 8 {
                    return Err(DecodeError::TooShort {
                        needed: 8,
                        had: ext.len(),
                    });
                }
                nh = ext[0];
                let off_more = u16::from_be_bytes([ext[2], ext[3]]);
                let more_frags = off_more & 0x1 != 0;
                let frag_off = off_more >> 3;
                fragmented = more_frags || frag_off != 0;
                first_fragment = frag_off == 0;
                ext = &ext[8..];
                if fragmented && !first_fragment {
                    return Ok(RawPacket {
                        src_ip: src,
                        dst_ip: dst,
                        ip_protocol: nh,
                        ip_total_len: 40u16.saturating_add(payload_len as u16),
                        fragmented,
                        first_fragment,
                        transport: Transport::Other,
                    });
                }
            }
            _ => break,
        }
    }

    let transport = decode_l4(nh, ext)?;
    Ok(RawPacket {
        src_ip: src,
        dst_ip: dst,
        ip_protocol: nh,
        ip_total_len: 40u16.saturating_add(payload_len as u16),
        fragmented,
        first_fragment,
        transport,
    })
}

fn decode_l4(protocol: u8, l4: &[u8]) -> Result<Transport, DecodeError> {
    match protocol {
        6 => Ok(Transport::Tcp(decode_tcp(l4)?)),
        17 => Ok(Transport::Udp(decode_udp(l4)?)),
        1 => Ok(Transport::Icmp(decode_icmp(l4, false))),
        58 => Ok(Transport::Icmp(decode_icmp(l4, true))),
        _ => Ok(Transport::Other),
    }
}

fn decode_tcp(l4: &[u8]) -> Result<TcpInfo, DecodeError> {
    if l4.len() < 20 {
        return Err(DecodeError::TooShort {
            needed: 20,
            had: l4.len(),
        });
    }
    let src = u16::from_be_bytes([l4[0], l4[1]]);
    let dst = u16::from_be_bytes([l4[2], l4[3]]);
    let data_offset = (l4[12] >> 4) as usize * 4;
    if data_offset < 20 || data_offset > l4.len() {
        return Err(DecodeError::Malformed("tcp data offset"));
    }
    let flags = TcpFlags::from_bits(l4[13]);
    let payload_len = l4.len() - data_offset;
    let payload: Vec<u8> = l4[data_offset..]
        .iter()
        .copied()
        .take(MAX_PAYLOAD_SNAP)
        .collect();
    Ok(TcpInfo {
        src,
        dst,
        flags,
        payload_len,
        payload,
    })
}

fn decode_udp(l4: &[u8]) -> Result<UdpInfo, DecodeError> {
    if l4.len() < 8 {
        return Err(DecodeError::TooShort {
            needed: 8,
            had: l4.len(),
        });
    }
    let src = u16::from_be_bytes([l4[0], l4[1]]);
    let dst = u16::from_be_bytes([l4[2], l4[3]]);
    let declared = u16::from_be_bytes([l4[4], l4[5]]) as usize;
    let payload = &l4[8..];
    // UDP length includes the 8-byte header; clamp to what we actually have.
    let declared_payload = declared.saturating_sub(8).min(payload.len());
    let snap: Vec<u8> = payload.iter().copied().take(MAX_PAYLOAD_SNAP).collect();
    let dns = if src == 53 || dst == 53 || src == 5353 || dst == 5353 {
        parse_dns(payload).ok()
    } else {
        None
    };
    Ok(UdpInfo {
        src,
        dst,
        payload_len: declared_payload,
        payload: snap,
        dns,
    })
}

fn decode_icmp(l4: &[u8], v6: bool) -> IcmpInfo {
    let kind = l4.first().copied().unwrap_or(0);
    let code = l4.get(1).copied().unwrap_or(0);
    let echo = if v6 {
        kind == 128 || kind == 129
    } else {
        kind == 8 || kind == 0
    };
    let payload_len = l4.len().saturating_sub(8);
    IcmpInfo {
        kind,
        code,
        echo,
        payload_len,
    }
}

/// Maximum labels / pointer hops accepted before we treat DNS as malformed.
const DNS_MAX_NAME_LEN: usize = 512;
const DNS_MAX_POINTER_HOPS: usize = 32;

/// Parse the first question of a DNS message. Never panics; returns
/// [`DecodeError::Malformed`] on any structural problem.
pub fn parse_dns(msg: &[u8]) -> Result<DnsQuery, DecodeError> {
    if msg.len() < 12 {
        return Err(DecodeError::TooShort {
            needed: 12,
            had: msg.len(),
        });
    }
    let flags = u16::from_be_bytes([msg[2], msg[3]]);
    let is_response = flags & 0x8000 != 0;
    let qdcount = u16::from_be_bytes([msg[4], msg[5]]);
    if qdcount == 0 {
        return Err(DecodeError::Malformed("zero question count"));
    }
    let mut pos = 12usize;
    let mut name = String::new();
    let mut hops = 0usize;
    let mut jumped = false;
    let mut end_for_type = 0usize;

    loop {
        if !jumped {
            end_for_type = pos;
        }
        if pos >= msg.len() {
            return Err(DecodeError::Malformed("name out of bounds"));
        }
        let len = msg[pos] as usize;
        if len == 0 {
            pos += 1;
            if !jumped {
                end_for_type = pos;
            }
            break;
        }
        if len & 0xC0 == 0xC0 {
            // Compression pointer.
            if pos + 2 > msg.len() {
                return Err(DecodeError::Malformed("pointer out of bounds"));
            }
            let ptr = (((len & 0x3F) as usize) << 8) | msg[pos + 1] as usize;
            if ptr >= msg.len() || ptr == pos + 1 {
                return Err(DecodeError::Malformed("bad pointer target"));
            }
            if !jumped {
                end_for_type = pos + 2;
            }
            pos = ptr;
            jumped = true;
            hops += 1;
            if hops > DNS_MAX_POINTER_HOPS {
                return Err(DecodeError::Malformed("pointer loop"));
            }
            continue;
        }
        if len & 0xC0 != 0 {
            return Err(DecodeError::Malformed("reserved label type"));
        }
        let label_start = pos + 1;
        let label_end = label_start + len;
        if label_end > msg.len() {
            return Err(DecodeError::Malformed("label out of bounds"));
        }
        if !name.is_empty() {
            name.push('.');
        }
        let label = &msg[label_start..label_end];
        for &b in label {
            // Keep names printable-ish; replace others with '.' to avoid control output.
            let c = if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'*' | b'=') {
                b as char
            } else {
                '.'
            };
            name.push(c);
        }
        if name.len() > DNS_MAX_NAME_LEN {
            return Err(DecodeError::Malformed("name too long"));
        }
        pos = label_end;
    }

    // After the (expanded) name we need QTYPE + QCLASS from the *non-jumped* end.
    let qpos = if jumped { end_for_type } else { pos };
    if qpos + 4 > msg.len() {
        return Err(DecodeError::Malformed("missing qtype/qclass"));
    }
    let qtype = u16::from_be_bytes([msg[qpos], msg[qpos + 1]]);
    let qclass = u16::from_be_bytes([msg[qpos + 2], msg[qpos + 3]]);
    Ok(DnsQuery {
        qname: name,
        qtype,
        qclass,
        is_response,
    })
}

// Helpers to convert fixed slices into arrays without panicking.
trait ToArray {
    fn try_to_array4(&self) -> Result<[u8; 4], DecodeError>;
    fn try_to_array16(&self) -> Result<[u8; 16], DecodeError>;
}
impl ToArray for [u8] {
    fn try_to_array4(&self) -> Result<[u8; 4], DecodeError> {
        let a: [u8; 4] = self
            .try_into()
            .map_err(|_| DecodeError::Malformed("ipv4 len"))?;
        Ok(a)
    }
    fn try_to_array16(&self) -> Result<[u8; 16], DecodeError> {
        let a: [u8; 16] = self
            .try_into()
            .map_err(|_| DecodeError::Malformed("ipv6 len"))?;
        Ok(a)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eth_ipv4_payload(l4: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&[0; 12]); // dst+src
        v.extend_from_slice(&[0x08, 0x00]);
        let mut ip = vec![0x45, 0, 0, (20 + l4.len()) as u8, 0, 0, 0, 0, 64, 6, 0, 0];
        ip.extend_from_slice(&[1, 2, 3, 4]);
        ip.extend_from_slice(&[5, 6, 7, 8]);
        v.extend_from_slice(&ip);
        v.extend_from_slice(l4);
        v
    }

    #[test]
    fn decodes_tcp_syn() {
        let mut tcp = vec![0u8; 20];
        tcp[0..2].copy_from_slice(&1234u16.to_be_bytes());
        tcp[2..4].copy_from_slice(&80u16.to_be_bytes());
        tcp[12] = 5 << 4;
        tcp[13] = 0x02; // SYN
        let frame = eth_ipv4_payload(&tcp);
        let p = decode_frame(&frame).unwrap();
        assert_eq!(p.src_ip.to_string(), "1.2.3.4");
        assert_eq!(p.dst_ip.to_string(), "5.6.7.8");
        match p.transport {
            Transport::Tcp(t) => {
                assert_eq!(t.src, 1234);
                assert_eq!(t.dst, 80);
                assert!(t.flags.is_syn_only());
            }
            _ => panic!("expected tcp"),
        }
    }

    #[test]
    fn truncated_never_panics() {
        for n in 0..40 {
            let frame = vec![0u8; n];
            let _ = decode_frame(&frame);
        }
    }

    #[test]
    fn parses_dns_query() {
        // id=1 flags=0 qd=1, qname = 3"foo"3"bar"2"io"0, qtype=1 qclass=1
        let mut m = vec![0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        m.extend_from_slice(&[3, b'f', b'o', b'o', 3, b'b', b'a', b'r', 2, b'i', b'o', 0]);
        m.extend_from_slice(&[0, 1, 0, 1]);
        let q = parse_dns(&m).unwrap();
        assert_eq!(q.qname, "foo.bar.io");
        assert_eq!(q.qtype, 1);
        assert!(!q.is_response);
    }
}
