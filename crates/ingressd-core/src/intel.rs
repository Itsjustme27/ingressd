//! Trait contracts that decouple `ingressd-core` from the `ingressd-intel` crate.
//!
//! The engine holds `Arc<dyn ThreatIntelSource>` and an optional
//! `Arc<dyn GeoSource>`; `ingressd-cli` wires the concrete implementations from
//! `ingressd-intel`. Keeping the traits here means core has no dependency on the
//! intel crate and stays unit-testable in isolation.

use std::net::IpAddr;
use std::sync::Arc;

/// A threat-intel match for a peer IP.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IntelHit {
    /// The feed/list the entry came from, when known.
    pub source: Option<String>,
}

/// Longest-prefix blocklist lookup, implemented by `ingressd-intel`.
pub trait ThreatIntelSource: Send + Sync {
    /// Return a hit if `ip` is in any loaded blocklist.
    fn lookup(&self, ip: IpAddr) -> Option<IntelHit>;
    /// Number of distinct prefixes loaded.
    fn len(&self) -> usize;
    /// True when no entries are loaded.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// GeoIP/ASN enrichment, implemented by `ingressd-intel` over a local MaxMind DB.
pub trait GeoSource: Send + Sync {
    /// Resolve `(asn, country_code)` for `ip`, if any.
    fn lookup(&self, ip: IpAddr) -> (Option<u32>, Option<String>);
}

/// A threat-intel source that never matches; used as the default so the engine
/// works before feeds are loaded and in core-only tests.
#[derive(Clone, Copy, Debug, Default)]
pub struct NullIntel;

impl ThreatIntelSource for NullIntel {
    fn lookup(&self, _ip: IpAddr) -> Option<IntelHit> {
        None
    }
    fn len(&self) -> usize {
        0
    }
}

/// An `Arc<dyn ...>` pair the engine takes.
pub type IntelArc = Arc<dyn ThreatIntelSource>;
/// Optional geo enrichment handle.
pub type GeoArc = Option<Arc<dyn GeoSource>>;
