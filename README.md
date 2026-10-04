# ingressd

**Passive public-IP traffic threat detector for Linux cloud VMs.**

`ingressd` runs on an Ubuntu/Debian VM and inspects traffic to and from
**publicly routable** IP addresses on the instance's internet-facing interface,
alerting on scans, brute force, floods, reflection/amplification, DNS and ICMP
tunneling, C2 beaconing, and contact with known-bad IPs.

It is **defensive and passive by default**: observe, alert, export metrics.
Blocking (`--enforce`) is opt-in and dry-run by default. Only deploy it on
infrastructure you own or are authorized to monitor.

---

## Workspace layout

| Crate | Role |
|---|---|
| `ingressd-core` | Decoders (Ethernet/VLAN/IPv4/IPv6/TCP/UDP/ICMP/DNS), public-IP scoping, bounded LRU sliding-window state, 13 detection rules, engine, config model, metrics. `#![forbid(unsafe_code)]`. |
| `ingressd-intel` | Longest-prefix blocklist trie, HTTPS/local feed loader with last-good caching, optional GeoIP/ASN. |
| `ingressd-capture` | AF_PACKET live capture (Linux), portable `.pcap` replay, AWS/GCP VPC flow-log input, bounded channel. Only `unsafe` module. |
| `ingressd-cli` | The `ingressd` binary: config load/validation, sinks (stdout / rotating JSONL file / syslog / webhook), Prometheus endpoint, SIGHUP reload, SIGTERM shutdown, optional nftables enforcement. |

A separate `fuzz/` crate (excluded from the workspace) holds `cargo-fuzz` targets.

---

## Build

Requires Rust stable **1.75+**.

```bash
# Portable build + full test suite. No privileges, no libpcap, no network.
cargo build
cargo test --workspace

# Production binary with live AF_PACKET capture (Linux only):
cargo build --release --features live-capture

# With offline GeoIP/ASN enrichment:
cargo build --release --features live-capture,geoip
```

### Why `live-capture` is off by default

Live capture is the only `unsafe`, Linux-only code. Keeping it behind a feature
means `cargo test` compiles the entire safe pipeline (decoders → scoping → rules
→ engine) and runs the end-to-end replay test **everywhere, without root or
libpcap**. Build the deployment binary with `--features live-capture`.

### Static binary

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl --features live-capture
```

---

## Quick test with a pcap (no privileges)

```bash
# 1. Generate a sample attack+benign pcap (one burst per rule).
cargo run --release --bin ingressd -- pcapgen /tmp/sample.pcap

# 2. Replay it through the real engine; alerts are printed as JSON Lines.
cargo run --release --bin ingressd -- --pcap /tmp/sample.pcap --check-config
#   (drop --check-config to actually run the replay and print alerts)
```

`--pcap` uses the pcap file's own timestamps as the clock, so windows are
reproducible.

---

## Deploy on a cloud VM

Run `deploy/install.sh` as root. It builds with `live-capture`, creates a
dedicated non-root `ingressd` user, installs the binary with `CAP_NET_RAW` file
capabilities, drops everything else, and installs the hardened systemd unit.

```bash
sudo apt-get install -y libcap2-bin
sudo ./deploy/install.sh
systemctl status ingressd
journalctl -u ingressd -f
curl -s http://127.0.0.1:9102/metrics
```

Config lives at `/etc/ingressd/config.toml` (see `config.example.toml`). Reload
thresholds / allowlist / blocklists with `systemctl reload ingressd` (SIGHUP).

### Which interface

`ingressd` binds the interface carrying the default route (override with
`general.iface` or `--iface eth0`). It derives inbound/outbound from the host's
own addresses (auto-detected + `general.host_ips`, refreshed every
`refresh_host_secs`).

### Cloud-specific notes

- **AWS** — the primary ENI (`eth0`) carries the public IP when using an Elastic
  IP or auto-assigned public IPv4. Traffic to/from the instance is visible
  directly. `169.254.169.254` (IMDS) is auto-excluded as non-public; never block
  it. For VPC-level visibility without a NIC in promisc mode, use **VPC Traffic
  Mirroring** to a GWLB and capture the mirror interface, or set
  `general.flow_log` to a VPC Flow Log stream and use the flow-log input.
  Keep your bastion/health-check ranges in `allowlist`. Review the instance
  security group: `ingressd` adds no inbound rules.
- **GCP** — the instance's primary NIC sees its own traffic; public IPs are
  often NAT'd, so pair with **VPC Flow Logs** (`general.flow_log`) for full
  external-peer visibility. Cloud health checks (`130.211.0.0/22`,
  `35.191.0.0/16`) belong in `allowlist`.
- **Azure** — capture the primary NIC, or use **VNet Traffic Analytics / NSG
  Flow Logs** exported to the flow-log input. Azure platform health-probe source
  IP (`168.63.129.16`) must be allowlisted. IMDS `169.254.169.254` is excluded
  automatically.

- **Mirror / TAP** — on self-managed hardware, capture from a SPAN/TAP interface
  and list the monitored hosts' addresses in `general.host_ips`; direction and
  public-scoping are derived from them. Traffic not involving any listed address
  is skipped (transit).

---

## Detection rules

Every rule has a configurable `threshold`/`min_*`, `window_s`, `cooldown_s`, and
`severity`, keeps bounded sliding-window state keyed by public peer IP, and tags
a MITRE ATT&CK technique. Alerts are deduplicated per (rule, peer) by cooldown.

| Rule key | Detects | ATT&CK | Default severity |
|---|---|---|---|
| `port-scan` | N distinct `(dst, port)` SYN targets from one peer; horizontal vs vertical | T1046 | medium |
| `invalid-tcp-flags` | NULL, XMAS, FIN-only, SYN+FIN, SYN+RST | T1046 | medium |
| `brute-force` | repeated new connections to SSH/RDP/SMB/FTP/Telnet/VNC/WinRM/DB ports | T1110 | high |
| `syn-flood` | SYN rate to a local endpoint above baseline with low completion ratio | T1498.001 | high |
| `udp-flood` | per-target UDP packet rate | T1498 | high |
| `icmp-flood` | per-target ICMP packet rate | T1498 | high |
| `reflection-amplification` | unsolicited large UDP replies from reflector ports (53/123/161/389/1900/11211) with no matching request | T1498.002 | high |
| `dns-tunnel` | high-entropy / long / many-subdomain QNAMEs, abnormal TXT/NULL volume | T1071.004 | medium |
| `icmp-tunnel` | oversized or high-rate echo payloads | T1095 | medium |
| `beaconing` | outbound connections at near-constant intervals (low jitter) | T1071 | high |
| `threat-intel-hit` | peer matches a loaded blocklist | T1071 | high |
| `suspicious-port` | traffic on known backdoor/C2 ports | T1571 | low |
| `new-listener-probe` | many sources probing a port with no listening socket | T1595 | low |

Tracked keys are capped at `rules.max_tracked_keys` (LRU); overflow is counted by
`ingressd_evictions_total`, so a spoofed-source flood cannot exhaust memory.

### Tuning

- **Start noisier, then tighten.** Run a week at defaults, review
  `alerts.jsonl`, and raise `threshold`/`min_*` for anything over-firing (common:
  `port-scan` behind a load balancer — allowlist the LB and CDN ranges;
  `new-listener-probe` if the listener set changes often).
- **Flood rules** (`syn/udp/icmp-flood`) are per-target rates; set them just
  above your normal peak pps to a service.
- **Beaconing** needs a long `window_s` and enough `min_samples`; expect false
  positives on legitimately periodic clients (NTP, metrics) — allowlist them.
- Cooldowns suppress alert storms; raise them where downstream is chatty.

---

## Outputs

- **Alerts** are JSON Lines with `time` (RFC3339 UTC), `rule`, `severity`,
  `direction`, `peer_ip`, `peer_asn`, `peer_country`, `local_ip`, `proto`,
  `ports`, `detail`, `mitre`, `count`, `window_s`. Sent to stdout and/or a
  size-rotated file, optionally syslog and a webhook (with retry/backoff and an
  ECS field mapping).
- **Prometheus** at `127.0.0.1:9102/metrics`: `ingressd_packets_total`,
  `ingressd_bytes_total`, `ingressd_parse_errors_total`, `ingressd_drops_total`,
  `ingressd_skipped_nonpublic_total`, `ingressd_alerts_total`,
  `ingressd_alerts_by_rule{rule=...}`, `ingressd_tracked_keys`,
  `ingressd_channel_depth`, `ingressd_evictions_total`,
  `ingressd_intel_feed_age_seconds`.

---

## Active response (opt-in)

`[enforce] enabled = true` (keep `dry_run = true` first) blocks peers by adding
them to an `nftables` set with a timeout, or by invoking a user-supplied
`hook_command` (e.g. a security-group revoker) when configured. It **never**
blocks allowlisted peers, the host's own addresses, cloud metadata, in-use DNS
resolvers, or the current SSH peer, and caps total entries. Every action is
logged with the triggering alert id and is reversible:

```bash
ingressd unblock 203.0.113.9
```

Requires `CAP_NET_ADMIN` when using local nft (kept in the unit's bounding set;
remove it if you only use a hook).

---

## Quality

- Decoders are bounds-checked and total (no panics on malformed input);
  `cargo-fuzz` targets: `decode_frame`, `parse_dns`, `pcap_reader`.
- `proptest` covers window/LRU invariants; per-rule unit tests; end-to-end pcap
  replay asserts the full alert set with zero benign false positives.
- `cargo fmt`, `cargo clippy -- -D warnings`, `cargo audit` are expected to pass.
- `criterion` benchmark: `cargo bench -p ingressd-core`.

### Known limitations (deliberate, documented)

- **Live capture uses a plain `AF_PACKET` `recv` loop, not `TPACKET_V3`.** It is
  correct and privilege-light; sustained >1 Gbit/s line-rate needs the mmap ring
  path swapped in behind the same interface. The decode→engine path is the
  optimized part; the capture syscall loop is the current throughput limiter.
- **Flow-log input is per-flow, not per-packet** (no TCP flags, aggregated
  counts). Connection-oriented rules work; rate-based flood rules under-count.
- DNS-tunnel "unique subdomains" is approximated by unique QNAMEs per peer.
- **No `libpcap`/`pnet` dependency** — pcap read/write and AF_PACKET are
  hand-rolled, so the offline path has zero native-library requirements.

---

## Alert schema & risk scoring

Every alert is a JSON line. The schema now carries an explicit risk score and
correlation metadata (see `sigma/` for the SIEM view of the same taxonomy):

```json
{
  "id": "00000012-1a2b3c4d",
  "time": "2026-10-04T12:00:00.000000000Z",
  "rule": "brute-force", "severity": "high", "risk_score": 78,
  "direction": "inbound", "peer_ip": "203.0.113.7", "local_ip": "5.7.9.11",
  "peer_asn": 64512, "peer_country": "US",
  "proto": "tcp", "ports": {"src": 51234, "dst": 22},
  "detail": "brute force: 24 new connections to auth ports [22] in 60s",
  "mitre": "T1110", "tactic": "TA0006", "tactic_name": "Credential Access",
  "tags": ["credential-access", "brute-force"],
  "count": 24, "window_s": 60, "sensor": "web-01",
  "schema_version": 1
}
```

**`risk_score` (0–100)** is deterministic: `base_weight(rule) + severity_bonus +
log-scaled volume`, clamped. It is monotonic in rule impact, configured severity,
and observed count, so you can gate enforcement or SIEM tiers on it (e.g. block
when `risk_score >= 70`). The `[enforce] min_severity` gate is severity-based; the
score is available to your SIEM/hook for finer policy.

**Structured logging** is `tracing`-based. Set `RUST_LOG` or `[log] level`. For
distributed tracing, add an OpenTelemetry layer at the `tracing_subscriber` init
point (`tracing-opentelemetry` + an OTLP exporter) and read the spans the engine
emits; the code already emits `tracing` events with `rule`, `peer_ip`, and
counts as structured fields. Example OTLP collector config in `deploy/`.

## SIEM / Sigma integration

`ingressd sigma` emits the full rule pack as multi-document Sigma YAML, kept in
lock-step with the engine so it never drifts. Convert to Splunk/Elastic/Loki with
pySigma (see [`sigma/README.md`](sigma/README.md)). Alerts use log source
`product: ingressd`, `service: alerts`; correlation is by `rule`, `tags`, `mitre`,
`tactic`, and `risk_score`. The webhook sink can emit ECS-mapped JSON
(`[sinks] webhook_ecs = true`) for direct Elastic ingestion.

## Extending detection (custom signatures & feeds)

Two no-recompile extension points:

1. **Threat-intel feeds** (`[intel.feeds]`) — add any HTTPS or local file of
   IPs/CIDRs (one per line; comments and inline `#` supported; bare IPs become
   /32, /128). Spamhaus DROP/EDROP, abuse.ch, Emerging Threats, or your own
   honeypot output. Validated on load, cached per-feed, last-good kept on fetch
   failure. A hit fires `threat-intel-hit` (Sigma-mapped, high by default).
2. **Declarative signatures** (`[[rules.signature]]`) — match packets by
   protocol / direction / ports / peer CIDR and raise a `custom-signature` alert
   with per-signature severity, cooldown per (peer, name), and MITRE + tags
   inherited by the pipeline:

```toml
[[rules.signature]]
name = "rdp-from-internet"
protocol = "tcp"
direction = "in"
ports = [3389]
severity = "high"

[[rules.signature]]
name = "suspicious-outbound-udp"
direction = "out"
protocol = "udp"
peer_cidr = ["0.0.0.0/0"]   # every public peer
ports = [4444, 8888]
```

Tune any built-in rule's thresholds/window/severity and port lists under
`[rules.*]`, and add bastion/LB/monitoring peers to `[general] allowlist` so they
never alert or get blocked. Example in `config.example.toml`.

## Snort rule integration

Point `ingressd` at community or your own Snort3 `.rules` files. Two things happen:

- **Sigma conversion (SIEM)** — `ingressd snort2sigma snort3-community.rules > snort.yml`
  emits one Sigma document per rule (title=`msg`, stable id from `sid`, log source
  `product: snort`, level from `classtype`, MITRE `tags`/`references` extracted from
  `reference:url,attack.mitre.org/...` and a `classtype` fallback).
- **In-engine enforcement** — set `[custom_signatures]` and list `files` and/or
  inline `rules`. Each rule is parsed (protocol, direction from `$HOME_NET` /
  `$EXTERNAL_NET`, port lists/ranges, peer CIDR, payload `content` with `nocase` /
  `depth` / `offset`, plus `sid`/`msg`/`classtype`) and enforced as a
  `custom-signature` alert next to the built-in rules. `pcre`/`flowbits`-only rules
  are exported to Sigma but skipped in-engine (reported at startup with a reason).

```toml
[custom_signatures]
enabled = true
files = ["/etc/ingressd/snort3-community.rules"]
rules = ['alert tcp $EXTERNAL_NET any -> $HOME_NET 22 ( msg:"ssh grab"; content:"SSH-2.0-evil"; nocase; sid:9000001; )']
[custom_signatures.vars]
HOME_NET = "0.0.0.0/0"
EXTERNAL_NET = "any"
```

Snort `content` matching requires the transport payload, which the decoder snapshots
per packet (bounded to `MAX_PAYLOAD_SNAP`); content rules therefore do not fire in
flow-log mode (no payload). Reload with `systemctl reload ingressd` (SIGHUP).

## Enterprise deployment

- **systemd**: `deploy/ingressd.service` + `deploy/install.sh` (non-root user,
  `setcap cap_net_raw=ep`, hardened sandbox).
- **Docker**: `deploy/Dockerfile` (musl static, distroless) +
  `deploy/docker-compose.yml` (host networking, `NET_RAW`, optional seccomp).
- **Kubernetes**: `deploy/k8s/` — `DaemonSet` (hostNetwork, `NET_RAW` only,
  readOnly rootfs, seccomp `RuntimeDefault`, liveness/readiness probes on
  `/healthz`/`/readyz`), `ConfigMap`, headless `Service` + `ServiceMonitor`, and
  an optional stricter `deploy/seccomp/ingressd.json`. Deploy:

```bash
kubectl apply -f deploy/k8s/
```

## Validation & production-readiness

- **Functional**: `cargo test --workspace` (per-rule unit tests, `proptest` window
  invariants, e2e pcap replay asserting the full alert set with zero benign FPs).
- **Load**: `cargo test -p ingressd-capture --test stress` (bounded memory,
  evictions exercised, no benign FPs at 200x volume). For real line-rate:
  `sudo IFACE=eth0 TARGET_MPPS=140 ./scripts/stress_test.sh` (tcpreplay, RSS
  guard). The optimized decode→engine path plus LRU-bounded state is designed for
  the 1 Gbit/s / 300 MB target; the plain `recv` capture loop (no TPACKET_V3 ring)
  is the throughput ceiling and is where you would upgrade first.
- **Fail-open/fail-closed**: `sudo ./scripts/failopen_test.sh` verifies
  `on_queue_full = drop` (survives, counts drops) vs `exit` (stops capture).

### Production-readiness scorecard

Reproducible gates (adapt to CI). Scores are the state of this implementation:

| # | Area | Gate | Status |
|---|------|------|--------|
| 1 | Capability dropping | non-root user, `setcap`/`NET_RAW` only, bounding set | ✅ systemd+install |
| 2 | Seccomp / sandbox | unit hardening flags; optional profile; K8s RuntimeDefault | ✅ (profile optional) |
| 3 | Memory safety | `#![forbid(unsafe_code)]` except gated capture; LRU key caps; RSS budget/`MemoryMax` | ✅ |
| 4 | Observability | Prometheus `/metrics`, `/healthz`+`/readyz`, structured `tracing` (otel-ready) | ✅ |
| 5 | Alert fidelity | risk score, MITRE technique+tactic, tags, sensor, schema version | ✅ |
| 6 | SIEM | Sigma export, JSONL/rotating file, syslog, webhook (+ECS), retries | ✅ |
| 7 | Reliability | graceful SIGTERM, SIGHUP hot-reload, feed last-good cache, run-state checkpoint | ✅ |
| 8 | Performance | bounded channels, zero-copy total decode, feature-gated live path | ✅ (ring-buffer deferred) |
| 9 | Extensibility | `[[rules.signature]]` + `[custom_signatures]` (Snort) + `[intel.feeds]` | ✅ |
| 10 | Snort integration | parser + `snort2sigma` converter + content enforcement | ✅ |
| 11 | Active response | off by default, dry-run, never-block guards, `unblock` | ✅ |
| 12 | Validation | unit+proptest+e2e+stress+snort-replay, fail-open/closed | ✅ |
| 13 | Deployment | systemd, Docker, Compose, K8s DaemonSet/ServiceMonitor | ✅ |
| 14 | Compliance | JSONL audit trail, `retention_days`, `redact_local_ip`, allowlisting, per-key `suppress_after` | ✅ |
| 15 | Performance | bounded channels, zero-copy decode, content snapshot cap, `AllowedCPUs`/`on_queue_full` | ✅ (ring-buffer deferred) |
| 16 | Local compile verification | `cargo build/test/clippy/fmt/audit` | ⚠ NOT run here (no toolchain); verify in VM |

## Development

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings   # live code may need --features live-capture
cargo test --workspace
cargo bench -p ingressd-core
cargo +nightly fuzz run decode_frame       # in fuzz/ (its own workspace)
```

## Security posture

`ingressd` never injects packets, never scans third parties, and treats feed
content as data only. Run it on hosts you own.
