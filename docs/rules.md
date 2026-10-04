# Detection rules

Every built-in rule keeps bounded, per-peer sliding-window state, applies a
per-(rule,peer) cooldown, and emits an alert with a MITRE technique/tactic,
severity, and 0–100 `risk_score`. Thresholds live under `[rules.<name>]`.

## Built-in detectors

| Rule | Fires when | Key | ATT&CK |
|---|---|---|---|
| `port-scan` | ≥ `min_targets` distinct `(dst, port)` SYN targets from one peer in `window_s`; classified horizontal/vertical | peer | T1046 |
| `invalid-tcp-flags` | ≥ `threshold` NULL/XMAS/FIN-only/SYN+FIN/SYN+RST packets from a peer in `window_s` | peer | T1046 |
| `brute-force` | ≥ `threshold` new connections to `ports` (SSH/RDP/SMB/FTP/Telnet/VNC/WinRM/DB) from a peer | peer | T1110 |
| `syn-flood` | ≥ `threshold` inbound SYNs to a local endpoint with SYN-ACK/SYN ratio < `max_completion_ratio` | local endpoint | T1498.001 |
| `udp-flood` / `icmp-flood` | ≥ `threshold` packets to a target in `window_s` | target | T1498 |
| `reflection-amplification` | ≥ `threshold` unsolicited inbound UDP ≥ `min_response_bytes` from `ports` (53/123/161/389/1900/11211) with no matching outbound request | peer | T1498.002 |
| `dns-tunnel` | high-entropy/long/many-subdomain QNAMEs or abnormal TXT/NULL volume toward a peer | peer | T1071.004 |
| `icmp-tunnel` | ≥ `threshold` echo payloads ≥ `max_payload` bytes | peer | T1095 |
| `beaconing` | ≥ `min_samples` outbound conns to a peer with interval CV ≤ `max_jitter_cv` over `window_s` | peer | T1071 |
| `threat-intel-hit` | peer matches a loaded blocklist | peer | T1071 |
| `suspicious-port` | traffic on a configured backdoor/C2 `ports` | peer | T1571 |
| `new-listener-probe` | ≥ `min_sources` distinct peers SYN a port with no listening socket (needs the live listener set) | port | T1595 |
| `custom-signature` | a Snort rule or `[[rules.signature]]` matches | peer, name | per-rule |

## Tuning

- **Start loose, tighten from data.** Run a week at defaults, review
  `alerts.jsonl`, then raise `threshold`/`min_*` on anything over-firing.
- **Behind a load balancer / CDN**, allowlist the LB/health-check/CDN ranges —
  they look like scanners. This is the single biggest false-positive source for
  `port-scan` and `new-listener-probe`.
- **Flood rules** (`syn/udp/icmp-flood`) are per-target rates: set them just
  above your normal peak pps to each service.
- **Beaconing** needs a long `window_s` and enough `min_samples`; allowlist
  legitimately periodic clients (NTP, telemetry, update servers).
- **`suppress_after`** (custom-signature) quiets a (peer, signature) pair after N
  alerts — useful for noisy low-severity rules.
- Cooldowns suppress alert storms per key; raise `cooldown_s` where downstream is
  chatty, lower it where you want repeat notifications.

## Memory bound

`rules.max_tracked_keys` caps each rule's key map with LRU eviction
(`ingressd_evictions_total` counts evictions), so a spoofed-source flood cannot
exhaust memory. Raise it (and the systemd `MemoryMax`) on high-cardinality hosts.
