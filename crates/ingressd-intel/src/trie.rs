//! Binary prefix trie for longest-prefix blocklist matching.
//!
//! Insertion walks `prefix_len` bits; lookup walks the address bits and keeps
//! the deepest terminal seen, so a query is O(32) for IPv4 / O(128) for IPv6 and
//! independent of how many prefixes are loaded.

use std::net::IpAddr;

use ipnet::IpNet;

use ingressd_core::intel::{IntelHit, ThreatIntelSource};

#[derive(Default)]
struct Node {
    zero: Option<Box<Node>>,
    one: Option<Box<Node>>,
    /// `Some` when a prefix terminates here; carries the list label.
    hit: Option<String>,
}

impl Node {
    fn child(&mut self, bit: u8) -> &mut Box<Node> {
        if bit == 0 {
            self.zero.get_or_insert_with(|| Box::new(Node::default()))
        } else {
            self.one.get_or_insert_with(|| Box::new(Node::default()))
        }
    }
}

/// A longest-prefix-match blocklist over both address families.
#[derive(Default)]
pub struct TrieIntel {
    v4: Node,
    v6: Node,
    count: usize,
}

fn bit_at(bytes: &[u8], i: usize) -> u8 {
    (bytes[i / 8] >> (7 - (i % 8))) & 1
}

impl TrieIntel {
    /// Empty trie.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a prefix, tagging it with `source`.
    pub fn insert(&mut self, net: IpNet, source: impl Into<Option<String>>) {
        let src = source.into();
        let (bytes, prefix_len, total_bits) = match net {
            IpNet::V4(v4) => (v4.network().octets().to_vec(), v4.prefix_len() as usize, 32usize),
            IpNet::V6(v6) => (v6.network().octets().to_vec(), v6.prefix_len() as usize, 128usize),
        };
        let root = if total_bits == 32 { &mut self.v4 } else { &mut self.v6 };
        let mut cur = root;
        for i in 0..prefix_len {
            cur = cur.child(bit_at(&bytes, i));
        }
        if cur.hit.is_none() {
            self.count += 1;
        }
        if cur.hit.is_none() || src.is_some() {
            cur.hit = src;
        }
    }

    /// Number of distinct prefixes stored.
    pub fn len(&self) -> usize {
        self.count
    }

    /// True when empty.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    fn lookup_addr(&self, ip: IpAddr) -> Option<IntelHit> {
        let (bytes, bits, root) = match ip {
            IpAddr::V4(v4) => (v4.octets().to_vec(), 32usize, &self.v4),
            IpAddr::V6(v6) => (v6.octets().to_vec(), 128usize, &self.v6),
        };
        let mut cur = root;
        let mut best: Option<String> = cur.hit.clone();
        for i in 0..bits {
            let next = match bit_at(&bytes, i) {
                0 => cur.zero.as_deref(),
                _ => cur.one.as_deref(),
            };
            match next {
                Some(n) => {
                    cur = n;
                    if cur.hit.is_some() {
                        best = cur.hit.clone();
                    }
                }
                None => break,
            }
        }
        best.map(|source| IntelHit { source: Some(source) })
    }
}

impl ThreatIntelSource for TrieIntel {
    fn lookup(&self, ip: IpAddr) -> Option<IntelHit> {
        self.lookup_addr(ip)
    }
    fn len(&self) -> usize {
        TrieIntel::len(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    #[test]
    fn longest_prefix_wins() {
        let mut t = TrieIntel::new();
        t.insert(net("10.0.0.0/8"), Some("broad".to_string()));
        t.insert(net("10.1.0.0/16"), Some("narrow".to_string()));
        let hit = t.lookup_addr(IpAddr::from([10, 1, 2, 3])).unwrap();
        assert_eq!(hit.source.as_deref(), Some("narrow"));
        let hit2 = t.lookup_addr(IpAddr::from([10, 9, 0, 1])).unwrap();
        assert_eq!(hit2.source.as_deref(), Some("broad"));
    }

    #[test]
    fn host_route() {
        let mut t = TrieIntel::new();
        t.insert(net("203.0.113.5/32"), None::<String>);
        assert!(t.lookup_addr(IpAddr::from([203, 0, 113, 5])).is_some());
        assert!(t.lookup_addr(IpAddr::from([203, 0, 113, 6])).is_none());
    }

    #[test]
    fn v6_prefix() {
        let mut t = TrieIntel::new();
        t.insert(net("2001:db8::/32"), Some("doc".to_string()));
        let ip: IpAddr = "2001:db8::1".parse().unwrap();
        assert!(t.lookup_addr(ip).is_some());
        let ip2: IpAddr = "2001:db9::1".parse().unwrap();
        assert!(t.lookup_addr(ip2).is_none());
    }

    #[test]
    fn default_route_matches_all() {
        let mut t = TrieIntel::new();
        t.insert(net("0.0.0.0/0"), Some("all".to_string()));
        assert!(t.lookup_addr(IpAddr::from([8, 8, 8, 8])).is_some());
    }
}
