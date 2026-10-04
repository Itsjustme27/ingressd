//! `ingressd-core` — the safe, portable heart of the ingressd traffic threat detector.
//!
//! This crate contains:
//! - Zero-copy, bounds-checked L2/L3/L4/DNS/ICMP decoders ([`decode`]).
//! - A portable libpcap file reader/writer used for offline replay and tests
//!   ([`pcap`]). Live capture lives in `ingressd-capture`.
//! - Public-IP (globally routable) scoping and direction derivation ([`scope`]).
//! - Bounded, LRU-capped sliding-window state ([`state`]).
//! - The detection rules and the [`engine::Engine`] that runs them.
//! - Rule configuration ([`config`]), alert types ([`types`]) and
//!   metrics counters ([`metrics`]).
//!
//! The whole crate forbids `unsafe`; the only unsafe code in the workspace is
//! the isolated AF_PACKET module in `ingressd-capture`.
#![forbid(unsafe_code)]
#![allow(clippy::type_complexity)]
#![warn(clippy::all)]

pub mod config;
pub mod decode;
pub mod engine;
pub mod gen;
pub mod intel;
pub mod metrics;
pub mod pcap;
pub mod rules;
pub mod scope;
pub mod sigma;
pub mod snort;
pub mod state;
pub mod types;

pub use config::RulesConfig;
pub use engine::Engine;
pub use metrics::Counters;
pub use types::{Alert, Direction, PacketEvent, Proto, RuleId, Severity};

/// Crate version, re-exported for `--version`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
