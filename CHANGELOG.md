# Changelog

All notable changes to **ingressd** are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Snort3 rule parser + `snort2sigma` converter and in-engine `custom-signature` enforcement.
- Declarative TOML signatures (`[[rules.signature]]`) and `[custom_signatures]` file loading.
- 0–100 risk scoring, MITRE tactic mapping, correlation tags, and sensor id on every alert.
- Sigma rule-pack export (`ingressd sigma`).
- `/healthz` and `/readyz` probes; `custom_signatures_total` metric.
- Fail-open / fail-closed backpressure policy (`general.on_queue_full`).
- PII redaction (`sinks.redact_local_ip`) and time-based retention (`sinks.retention_days`).
- Per-key feedback suppression (`suppress_after`) for recurring low-severity noise.
- Deployment: hardened systemd unit, AppArmor + seccomp profiles, Docker, and a Kubernetes DaemonSet.
- CI: fmt, `clippy -D warnings`, tests, `live-capture,geoip` build, portability, bench, audit.

## [0.1.0]

### Added
- Initial `ingressd` workspace: `ingressd-core`, `ingressd-intel`, `ingressd-capture`, `ingressd-cli`.
- Zero-copy Ethernet/VLAN/IPv4/IPv6/TCP/UDP/ICMP/DNS decoders (total, bounds-checked).
- Public-IP scoping and host-relative direction; skip of RFC1918/ULA/link-local/metadata/CGNAT/doc ranges.
- 13 built-in sliding-window detectors with LRU-capped state and per-(rule,peer) cooldowns.
- Longest-prefix threat-intel trie with HTTPS/local feed loading, per-feed caching and last-good fallback.
- JSON-Lines alerts (stdout + size-rotated file), syslog and webhook (retry/backoff, ECS) sinks.
- Prometheus metrics on a loopback endpoint.
- Opt-in nftables / cloud-hook active response, dry-run by default with never-block guardrails.
- AF_PACKET live capture (Linux, feature-gated), pcap replay, and VPC flow-log inputs.

[Unreleased]: https://github.com/kalidada18/ingressd/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/kalidada18/ingressd/releases/tag/v0.1.0
