//! Blocklist parsing and HTTPS fetching.
//!
//! Parsing is deliberately forgiving (blank/comment lines, inline comments, bare
//! IPs, CIDRs) but every entry is validated by `ipnet` before use. Feed content
//! is treated purely as data, never as instructions.

use std::net::IpAddr;

use ipnet::IpNet;

use crate::trie::TrieIntel;

/// Refuse to buffer a feed larger than this (16 MiB).
pub const MAX_FEED_BYTES: usize = 16 * 1024 * 1024;

/// Errors surfaced while fetching a feed.
#[derive(Debug, thiserror::Error)]
pub enum FeedError {
    /// Network / client error.
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    /// Non-2xx status.
    #[error("unexpected status {0}")]
    HttpStatus(u16),
    /// Body exceeded [`MAX_FEED_BYTES`].
    #[error("feed too large: {0} bytes")]
    TooLarge(usize),
    /// Filesystem error.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// Parse a single token as an IP network (CIDR) or a bare host address.
pub fn parse_token(token: &str) -> Option<IpNet> {
    if let Ok(net) = token.parse::<IpNet>() {
        return Some(net);
    }
    // A bare IP is its own host network (/32 or /128).
    if let Ok(ip) = token.parse::<IpAddr>() {
        let cidr = if ip.is_ipv4() {
            format!("{ip}/32")
        } else {
            format!("{ip}/128")
        };
        if let Ok(net) = cidr.parse::<IpNet>() {
            return Some(net);
        }
    }
    None
}

/// Load every valid entry from `text` into `trie`, tagged with `source`.
///
/// Returns the number of entries added. Invalid lines are skipped silently
/// (counted by the caller via [`parse_lines_stats`] if desired).
pub fn load_text(trie: &mut TrieIntel, text: &str, source: &str) -> usize {
    let mut added = 0;
    for line in text.lines() {
        let s = line.split('#').next().unwrap_or("").trim();
        let token = match s.split_whitespace().next() {
            Some(t) => t,
            None => continue,
        };
        if let Some(net) = parse_token(token) {
            trie.insert(net, Some(source.to_string()));
            added += 1;
        }
    }
    added
}

/// `(valid, invalid)` line counts for a blocklist body.
pub fn parse_lines_stats(text: &str) -> (usize, usize) {
    let (mut ok, mut bad) = (0, 0);
    for line in text.lines() {
        let s = line.split('#').next().unwrap_or("").trim();
        let token = match s.split_whitespace().next() {
            Some(t) => t,
            None => continue,
        };
        if parse_token(token).is_some() {
            ok += 1;
        } else {
            bad += 1;
        }
    }
    (ok, bad)
}

/// Fetch a feed body over HTTPS with a hard size ceiling.
pub async fn fetch_text(client: &reqwest::Client, url: &str) -> Result<String, FeedError> {
    let resp = client.get(url).send().await?;
    let status = resp.status();
    if !status.is_success() {
        return Err(FeedError::HttpStatus(status.as_u16()));
    }
    let bytes = resp.bytes().await?;
    if bytes.len() > MAX_FEED_BYTES {
        return Err(FeedError::TooLarge(bytes.len()));
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ingressd_core::intel::ThreatIntelSource;

    #[test]
    fn parses_mixed_feed() {
        let text = "\
# comment
1.2.3.0/24
5.6.7.8        # trailing comment
2001:db8::/32
not-an-ip
::1
";
        let mut t = TrieIntel::new();
        let added = load_text(&mut t, text, "test");
        assert_eq!(added, 4, "should skip 'not-an-ip' and blanks");
        assert!(t.lookup(std::net::IpAddr::from([1, 2, 3, 99])).is_some());
        assert!(t.lookup(std::net::IpAddr::from([5, 6, 7, 8])).is_some());
    }

    #[test]
    fn bare_ip_is_host_net() {
        assert_eq!(parse_token("8.8.8.8").unwrap().prefix_len(), 32);
        assert_eq!(
            parse_token("8.8.8.0/24").unwrap().network().to_string(),
            "8.8.8.0"
        );
    }

    #[test]
    fn stats_counts_invalid() {
        let (ok, bad) = parse_lines_stats("1.2.3.4\nfoo\n5.6.7.8/32\n");
        assert_eq!((ok, bad), (2, 1));
    }
}
