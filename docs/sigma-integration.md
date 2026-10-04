# Sigma & SIEM integration

ingressd emits **Sigma** rules and **Sigma-compatible alert fields** so it drops
into Splunk, Elastic, Grafana Loki, or any pySigma backend.

## Export the rule pack

```bash
# Built-in rules (kept in lock-step with the engine, so it never drifts):
ingressd sigma > ingressd_rules.yml

# Plus your Snort rules:
ingressd snort2sigma rules/snort3-community.rules > snort_rules.yml
```

## Convert to your SIEM (pySigma)

```bash
pip install sigma-cli

sigma-convert --backend splunk         ingressd_rules.yml -o splunk.xml
sigma-convert --backend elasticsearch --backend-options ecs-version=8.0 \
                                          ingressd_rules.yml -o elastic.yml
sigma-convert --backend loki           ingressd_rules.yml -o loki.yml
sigma-convert --backend sigma          snort_rules.yml -o normalized.yml
```

## Alert log source

ingressd alerts are a custom log source:

```yaml
logsource:
  product: ingressd
  service: alerts
```

Each rule selects on the alert's `rule` field. Correlate on the structured
fields below.

## Alert fields (JSON Lines)

| Field | Example | Notes |
|---|---|---|
| `time` | `2026-10-04T12:00:00Z` | RFC 3339 UTC |
| `rule` | `brute-force` | stable key, matches Sigma `detection` |
| `severity` | `high` | `low`/`medium`/`high` |
| `risk_score` | `78` | 0–100 composite (impact + severity + volume) |
| `mitre` / `tactic` / `tactic_name` | `T1110` / `TA0006` / `Credential Access` | |
| `tags` | `["credential-access","brute-force"]` | routing/correlation keys |
| `direction` | `inbound` | |
| `peer_ip` / `local_ip` | | peer is always globally routable |
| `peer_asn` / `peer_country` | | with `--features geoip` |
| `proto` / `ports` | `tcp` / `{src,dst}` | |
| `count` / `window_s` | | window the alert summarizes |
| `sensor` | `web-01` | host/instance id |
| `schema_version` | `1` | for consumer compatibility |

## Direct ingestion

- **Elastic** — set `[sinks] webhook_ecs = true` to POST ECS-mapped JSON
  (`event.severity`, `source.ip`, `destination.ip`, `network.*`, `rule.*`,
  `mitre.*`, `tags`) to a webhook ingest endpoint.
- **Splunk / generic webhook** — `[sinks] webhook_url` receives one JSON alert
  per POST (with optional bearer token and retry/backoff).
- **syslog** — `[sinks] syslog = true` (Unix, to `/dev/log`).
- **File** — `[sinks] alerts_file` writes size-rotated JSON-Lines; ship it with
  Filebeat/Fluent Bit/Promtail.

## Thresholding on risk

Because `risk_score` is monotonic, SIEM correlation rules can tier on it (e.g.
page on `risk_score >= 80`, ticket `50–79`) instead of re-deriving severity.
