//! `ingressd-intel` — threat-intel feeds, a longest-prefix blocklist trie, and
//! optional offline GeoIP/ASN enrichment.
//!
//! [`Intel`] is the live store the detection engine queries. It keeps an
//! immutable [`TrieIntel`] behind an `Arc` and swaps it wholesale on refresh, so
//! lookups on the packet path are lock-light and never block a reload. Per-feed
//! on-disk caches implement the "on fetch failure keep the last good copy" rule.
#![forbid(unsafe_code)]

pub mod feed;
pub mod trie;

#[cfg(feature = "geoip")]
pub mod geoip;

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime};

use ingressd_core::intel::{IntelHit, ThreatIntelSource};

pub use feed::{fetch_text, load_text, parse_token, FeedError, MAX_FEED_BYTES};
pub use trie::TrieIntel;

#[cfg(feature = "geoip")]
pub use geoip::GeoDb;

/// Where a blocklist comes from.
#[derive(Clone, Debug)]
pub enum FeedLocation {
    /// HTTPS URL to fetch (and cache locally).
    Url(String),
    /// Local file path.
    File(PathBuf),
}

/// A named blocklist feed.
#[derive(Clone, Debug)]
pub struct FeedSpec {
    /// Human-readable name, used as the alert source label and cache key.
    pub name: String,
    /// URL or file path.
    pub location: FeedLocation,
}

impl FeedSpec {
    /// An HTTPS feed.
    pub fn url(name: impl Into<String>, url: impl Into<String>) -> Self {
        FeedSpec {
            name: name.into(),
            location: FeedLocation::Url(url.into()),
        }
    }
    /// A local blocklist file.
    pub fn file(name: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        FeedSpec {
            name: name.into(),
            location: FeedLocation::File(path.into()),
        }
    }
}

/// Summary of one load/refresh pass.
#[derive(Clone, Debug, Default)]
pub struct RefreshReport {
    /// Total prefixes now in the trie.
    pub entries: usize,
    /// Feeds that loaded (from network, file, or cache).
    pub feeds_ok: usize,
    /// Feed names that could not be sourced this pass.
    pub failed: Vec<String>,
}

fn cache_path(dir: &Path, spec: &FeedSpec) -> PathBuf {
    let safe: String = spec
        .name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    dir.join(format!("{safe}.cache"))
}

/// The live blocklist store shared with the detection engine.
pub struct Intel {
    current: RwLock<Arc<TrieIntel>>,
    last_update: Mutex<Option<SystemTime>>,
    client: reqwest::Client,
}

impl Default for Intel {
    fn default() -> Self {
        Intel::new()
    }
}

impl Intel {
    /// New store with a 30s per-request timeout.
    pub fn new() -> Self {
        Intel::with_timeout(Duration::from_secs(30))
    }

    /// New store with an explicit HTTP timeout.
    pub fn with_timeout(timeout: Duration) -> Self {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .user_agent(concat!("ingressd/", env!("CARGO_PKG_VERSION")))
            .build()
            .unwrap_or_default();
        Intel {
            current: RwLock::new(Arc::new(TrieIntel::new())),
            last_update: Mutex::new(None),
            client,
        }
    }

    /// Snapshot the current trie (cheap Arc clone).
    fn snapshot(&self) -> Arc<TrieIntel> {
        let g = self.current.read().unwrap_or_else(|p| p.into_inner());
        Arc::clone(&g)
    }

    fn swap(&self, trie: TrieIntel) {
        let mut w = self.current.write().unwrap_or_else(|p| p.into_inner());
        *w = Arc::new(trie);
    }

    fn mark_updated(&self) {
        let mut g = self.last_update.lock().unwrap_or_else(|p| p.into_inner());
        *g = Some(SystemTime::now());
    }

    /// Seconds since the last successful refresh (for the feed-age metric).
    pub fn age_seconds(&self) -> Option<u64> {
        let g = self.last_update.lock().unwrap_or_else(|p| p.into_inner());
        g.map(|t| {
            SystemTime::now()
                .duration_since(t)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        })
    }

    /// Synchronously load file feeds and any cached URL feeds (no network).
    ///
    /// Used at startup so detection has blocklists before the first refresh.
    pub fn load_local(&self, specs: &[FeedSpec], cache_dir: Option<&Path>) -> RefreshReport {
        let mut t = TrieIntel::new();
        let mut ok = 0usize;
        let mut failed = Vec::new();
        for f in specs {
            match &f.location {
                FeedLocation::File(p) => match std::fs::read_to_string(p) {
                    Ok(txt) => {
                        load_text(&mut t, &txt, &f.name);
                        ok += 1;
                    }
                    Err(e) => {
                        tracing::warn!(feed = %f.name, "cannot read local feed: {e}");
                        failed.push(f.name.clone());
                    }
                },
                FeedLocation::Url(_) => {
                    if let Some(dir) = cache_dir {
                        if let Ok(txt) = std::fs::read_to_string(cache_path(dir, f)) {
                            load_text(&mut t, &txt, &f.name);
                            ok += 1;
                        } else {
                            failed.push(f.name.clone());
                        }
                    } else {
                        failed.push(f.name.clone());
                    }
                }
            }
        }
        let entries = t.len();
        if entries > 0 {
            self.swap(t);
            self.mark_updated();
        }
        RefreshReport {
            entries,
            feeds_ok: ok,
            failed,
        }
    }

    /// Fetch all feeds and swap in the result, preserving last-good on failure.
    pub async fn refresh(&self, specs: &[FeedSpec], cache_dir: Option<&Path>) -> RefreshReport {
        let mut t = TrieIntel::new();
        let mut ok = 0usize;
        let mut failed = Vec::new();

        for f in specs {
            match &f.location {
                FeedLocation::File(p) => match std::fs::read_to_string(p) {
                    Ok(txt) => {
                        load_text(&mut t, &txt, &f.name);
                        ok += 1;
                    }
                    Err(e) => {
                        tracing::warn!(feed = %f.name, "cannot read local feed: {e}");
                        failed.push(f.name.clone());
                    }
                },
                FeedLocation::Url(u) => match fetch_text(&self.client, u).await {
                    Ok(body) => {
                        if let Some(dir) = cache_dir {
                            let _ = std::fs::write(cache_path(dir, f), body.as_bytes());
                        }
                        load_text(&mut t, &body, &f.name);
                        ok += 1;
                    }
                    Err(e) => {
                        tracing::warn!(feed = %f.name, "feed fetch failed, trying cache: {e}");
                        let mut recovered = false;
                        if let Some(dir) = cache_dir {
                            if let Ok(txt) = std::fs::read_to_string(cache_path(dir, f)) {
                                load_text(&mut t, &txt, &f.name);
                                recovered = true;
                            }
                        }
                        if recovered {
                            ok += 1;
                        } else {
                            failed.push(f.name.clone());
                        }
                    }
                },
            }
        }

        let entries = t.len();
        // Only swap when we have something; otherwise keep the previous good copy.
        if entries > 0 {
            self.swap(t);
            self.mark_updated();
        }
        RefreshReport {
            entries,
            feeds_ok: ok,
            failed,
        }
    }
}

impl ThreatIntelSource for Intel {
    fn lookup(&self, ip: IpAddr) -> Option<IntelHit> {
        self.snapshot().lookup(ip)
    }
    fn len(&self) -> usize {
        self.snapshot().len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_local_file_and_query() {
        let dir = std::env::temp_dir().join(format!("ingressd-intel-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("drop.txt");
        std::fs::write(&f, "198.51.100.0/24\n203.0.113.7\n").unwrap();

        let store = Intel::new();
        let specs = vec![FeedSpec::file("test-drop", &f)];
        let report = store.load_local(&specs, None);
        assert_eq!(report.entries, 2);
        assert_eq!(store.len(), 2);
        assert!(store.lookup(IpAddr::from([198, 51, 100, 42])).is_some());
        assert!(store.lookup(IpAddr::from([8, 8, 8, 8])).is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_load_keeps_last_good() {
        let store = Intel::new();
        // Seed once.
        let mut t = TrieIntel::new();
        t.insert("10.0.0.0/8".parse().unwrap(), Some::<String>("x".into()));
        store.swap(t);
        assert_eq!(store.len(), 1);
        // A load that yields zero entries must NOT clear the previous good copy.
        let report = store.load_local(&[], None);
        assert_eq!(report.entries, 0);
        assert_eq!(store.len(), 1, "last good copy preserved");
    }
}
