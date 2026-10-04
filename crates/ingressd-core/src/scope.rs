//! Public-IP (globally routable) scoping and host-relative direction.
//!
//! Only globally routable peers are analysed; every other range the design spec
//! calls out is skipped (and counted by the caller). Direction is derived from
//! the set of addresses this host owns.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hashbrown::HashSet;

use crate::types::Direction;

/// Returns `true` only for globally routable unicast addresses.
///
/// Skips RFC1918, loopback, link-local (incl. `169.254.169.254`), CGNAT,
/// multicast, broadcast, documentation and reserved ranges, and the IPv6
/// equivalents.
pub fn is_public_global(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_public_v4(v4),
        IpAddr::V6(v6) => is_public_v6(v6),
    }
}

fn is_public_v4(ip: Ipv4Addr) -> bool {
    let [a, b, _c, _d] = ip.octets();
    // 0.0.0.0/8 "this host on this network".
    if a == 0 {
        return false;
    }
    // 10.0.0.0/8.
    if a == 10 {
        return false;
    }
    // 100.64.0.0/10 CGNAT.
    if a == 100 && (b & 0xC0) == 64 {
        return false;
    }
    // 127.0.0.0/8 loopback.
    if a == 127 {
        return false;
    }
    // 169.254.0.0/16 link-local (includes cloud metadata 169.254.169.254).
    if a == 169 && b == 254 {
        return false;
    }
    // 172.16.0.0/12.
    if a == 172 && (16..=31).contains(&b) {
        return false;
    }
    // 192.0.0.0/24 IETF protocol assignments.
    if a == 192 && b == 0 && _c == 0 {
        return false;
    }
    // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24 documentation.
    if (a == 192 && b == 0 && _c == 2) || (a == 198 && b == 51 && _c == 100) || (a == 203 && b == 0 && _c == 113) {
        return false;
    }
    // 192.88.99.0/24 6to4 anycast relay (reserved).
    if a == 192 && b == 88 && _c == 99 {
        return false;
    }
    // 192.168.0.0/16.
    if a == 192 && b == 168 {
        return false;
    }
    // 198.18.0.0/15 benchmarking.
    if a == 198 && (b == 18 || b == 19) {
        return false;
    }
    // 224.0.0.0/4 multicast.
    if (224..=239).contains(&a) {
        return false;
    }
    // 240.0.0.0/4 reserved + 255.255.255.255 broadcast.
    if a >= 240 {
        return false;
    }
    true
}

fn is_public_v6(ip: Ipv6Addr) -> bool {
    let seg0 = ip.segments()[0];
    // :: and ::1.
    if ip.is_unspecified() || ip.is_loopback() {
        return false;
    }
    // fc00::/7 unique-local (fc00..fdff).
    if seg0 & 0xFE00 == 0xFC00 {
        return false;
    }
    // fe80::/10 link-local.
    if seg0 & 0xFFC0 == 0xFE80 {
        return false;
    }
    // ff00::/8 multicast.
    if seg0 & 0xFF00 == 0xFF00 {
        return false;
    }
    // 100::/64 discard-only.
    if seg0 == 0x0100 {
        return false;
    }
    // 2001:db8::/32 documentation.
    let s = ip.segments();
    if s[0] == 0x2001 && s[1] == 0x0db8 {
        return false;
    }
    // 2001::/23 IETF protocol assignments (includes Teredo 2001::/32).
    if s[0] == 0x2001 && (s[1] & 0xFE00) == 0 {
        return false;
    }
    // 3ffe::/16 legacy 6bone, 5f00::/16 Segment Routing (documentation-ish).
    if s[0] == 0x3ffe || s[0] == 0x5f00 {
        return false;
    }
    true
}

/// Cloud metadata endpoints, matched even though they are non-public so the
/// enforcement layer can protect them explicitly.
pub fn is_cloud_metadata(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4 == Ipv4Addr::new(169, 254, 169, 254),
        IpAddr::V6(v6) => {
            // AWS IPv6 IMDS: fd00:ec2::254.
            let s = v6.segments();
            s[0] == 0xfd00 && s[1] == 0xec2
        }
    }
}

/// The set of addresses this host owns, refreshed periodically by the caller.
#[derive(Clone, Debug, Default)]
pub struct HostAddrs {
    v4: HashSet<Ipv4Addr>,
    v6: HashSet<Ipv6Addr>,
}

impl HostAddrs {
    /// Empty host set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the address set.
    pub fn set(&mut self, addrs: impl IntoIterator<Item = IpAddr>) {
        self.v4.clear();
        self.v6.clear();
        for a in addrs {
            match a {
                IpAddr::V4(v4) => {
                    self.v4.insert(v4);
                }
                IpAddr::V6(v6) => {
                    self.v6.insert(v6);
                }
            }
        }
    }

    /// True when `ip` is one of this host's addresses.
    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => self.v4.contains(&v4),
            IpAddr::V6(v6) => self.v6.contains(&v6),
        }
    }

    /// Number of known host addresses (for metrics / sanity).
    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    /// True when no host addresses are known.
    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    /// Derive direction and the (local, peer) split from a packet's endpoints.
    ///
    /// Returns `None` when neither endpoint belongs to this host (e.g. forwarded
    /// third-party traffic on a mirrored port) so the caller can skip it.
    pub fn classify(&self, src: IpAddr, dst: IpAddr) -> Option<(Direction, IpAddr, IpAddr)> {
        let src_host = self.contains(src);
        let dst_host = self.contains(dst);
        match (src_host, dst_host) {
            (false, true) => Some((Direction::Inbound, dst, src)),
            (true, false) => Some((Direction::Outbound, src, dst)),
            // Hairpin (both ours): treat as outbound toward `dst`.
            (true, true) => Some((Direction::Outbound, src, dst)),
            // Transit that does not involve us: skip.
            (false, false) => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn v4_scoping() {
        let pub_ip = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert!(is_public_global(pub_ip));
        for s in [
            "10.0.0.1",
            "192.168.1.1",
            "172.16.5.4",
            "100.64.0.1",
            "169.254.169.254",
            "127.0.0.1",
            "224.0.0.5",
            "255.255.255.255",
            "192.0.2.1",
            "198.51.100.1",
            "203.0.113.1",
            "0.0.0.0",
        ] {
            let ip: IpAddr = s.parse().unwrap();
            assert!(!is_public_global(ip), "{s} should be non-public");
        }
    }

    #[test]
    fn v6_scoping() {
        let pub6: IpAddr = "2606:4700:4700::1111".parse().unwrap();
        assert!(is_public_global(pub6));
        for s in ["::1", "::", "fe80::1", "fd12::1", "ff02::1", "2001:db8::1", "100::1"] {
            let ip: IpAddr = s.parse().unwrap();
            assert!(!is_public_global(ip), "{s} should be non-public");
        }
    }

    #[test]
    fn metadata() {
        assert!(is_cloud_metadata("169.254.169.254".parse().unwrap()));
    }

    #[test]
    fn direction() {
        let mut h = HostAddrs::new();
        h.set(["203.0.113.7".parse::<IpAddr>().unwrap()].into_iter());
        let inbound = h.classify("198.51.100.9".parse().unwrap(), "203.0.113.7".parse().unwrap());
        assert_eq!(inbound.unwrap().0, Direction::Inbound);
        let transit = h.classify("198.51.100.9".parse().unwrap(), "192.0.2.5".parse().unwrap());
        assert!(transit.is_none());
    }
}
