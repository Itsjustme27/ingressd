# Configuration

`ingressd` reads a TOML file (default `/etc/ingressd/config.toml`, override with
`--config` or `INGRESSD_CONFIG`). Unknown keys are **rejected** and every value
is validated at load; a bad config exits non-zero with all problems listed.
`SIGHUP` reloads rules, allowlist, signatures and feeds without restart.

A fully commented template lives at
[`config.example.toml`](../config.example.toml). Sections:

## `[general]`

| Key | Default | Meaning |
|---|---|---|
| `iface` | `""` | Live capture interface; empty auto-detects the default route. |
| `pcap` | unset | Replay a `.pcap` instead of live (mutually exclusive). |
| `flow_log` | unset | Parse a VPC flow-log file (`-` = stdin). |
| `host_ips` | `[]` | Extra owned addresses (IP/CIDR) merged with auto-detected. |
| `refresh_host_secs` | `30` | Host-address refresh interval. |
| `allowlist` | `[]` | Peers (IP/CIDR) that never alert or get blocked. |
| `cache_dir` | unset | Feed caches + run-state checkpoint. |
| `channel_capacity` | `100000` | Bounded capture→engine queue size. |
| `sensor_id` | `$HOSTNAME` | Identifier stamped on every alert. |
| `on_queue_full` | `drop` | `drop` (fail-open) / `stall` / `exit` (fail-closed). |
| `cpu_affinity` | `[]` | Informational; pin via systemd `AllowedCPUs=`. |

## `[rules]`

`max_tracked_keys` (default 200000) caps each rule's state. Every built-in rule
has its own `[rules.<name>]` table with `enabled`, `threshold`/`min_*`,
`window_s`, `cooldown_s`, `severity` (see [rules.md](rules.md)).

### `[rules.custom-signature]` + `[[rules.signature]]`

Enable and tune declarative signatures:

```toml
[rules.custom-signature]
enabled = true
cooldown_s = 600
severity = "medium"
suppress_after = 25          # optional per-(peer,name) feedback suppression

[[rules.signature]]
name = "rdp-from-internet"
protocol = "tcp"             # tcp | udp | icmp  (omit = any)
direction = "in"             # in | out          (omit = any)
ports = [3389]               # match src OR dst  (empty = any)
peer_cidr = ["0.0.0.0/0"]    # match peer        (empty = any)
severity = "high"            # optional override
content = "SSH-2.0-evil"     # optional payload match (|hex| groups allowed)
nocase = true
depth = 64                   # optional content window
offset = 0                   # optional content start
```

## `[custom_signatures]` — Snort `.rules` loading

```toml
[custom_signatures]
enabled = true
files   = ["rules/snort3-community.rules", "/etc/ingressd/local.rules"]
rules   = ['alert tcp $EXTERNAL_NET any -> $HOME_NET 3389 ( msg:"RDP"; sid:9000001; )']
[custom_signatures.vars]
HOME_NET = "0.0.0.0/0"
EXTERNAL_NET = "any"
```
See [snort-integration.md](snort-integration.md).

## `[intel]`

`refresh_secs` (default 3600), optional `geoip_db` (needs `--features geoip`),
and `[[intel.feeds]]` entries (`name` + `url` **or** `path` + `enabled`). Feeds
are validated, cached per-feed, and the last-good copy is kept on fetch failure.

## `[metrics]`

`enabled`, `listen` (default `127.0.0.1:9102`). Endpoints: `/metrics`,
`/healthz`, `/readyz`.

## `[sinks]`

`stdout`, `alerts_file` + `rotate_max_bytes`/`rotate_max_files`,
`retention_days` (age-based delete), `redact_local_ip` (PII), `syslog`,
`webhook_url`/`webhook_token`/`webhook_ecs`.

## `[enforce]`

`enabled` (off by default), `dry_run` (on by default), nft `family`/`table`/`set`,
`timeout_secs`, `max_entries`, `min_severity`, optional `hook_command`
(`{{ip}}` substituted). Never blocks allowlisted peers, host addresses, cloud
metadata, DNS resolvers, or the current SSH peer.

## `[log]`

`level` = `error|warn|info|debug|trace` (overridden by `RUST_LOG` if set).
