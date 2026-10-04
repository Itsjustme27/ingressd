# Snort rule integration

ingressd ingests Snort3 `.rules` files two ways: **convert to Sigma** for your
SIEM, and **enforce in-engine** as `custom-signature` alerts.

## 1. Convert to Sigma

```bash
ingressd snort2sigma rules/snort3-community.rules > snort.yml
# or from source:
cargo run --release --bin ingressd -- snort2sigma rules/snort3-community.rules
```

Each rule becomes a Sigma document: `title` = `msg`, a stable `id` from `sid`,
`logsource.product: snort`, `level` from `classtype`, and MITRE `tags`/
`references` extracted from `reference:url,attack.mitre.org/techniques/T####`
(with a `classtype` fallback). Import with pySigma — see
[sigma-integration.md](sigma-integration.md).

## 2. Enforce in the engine

```toml
[custom_signatures]
enabled = true
files   = ["/etc/ingressd/snort3-community.rules", "/etc/ingressd/local.rules"]
rules   = ['alert tcp $EXTERNAL_NET any -> $HOME_NET 3389 ( msg:"RDP"; sid:9000001; )']

[custom_signatures.vars]
HOME_NET     = "0.0.0.0/0"     # or your real home ranges
EXTERNAL_NET = "any"
```

At startup (and on `SIGHUP`) each rule is parsed and compiled into a signature.
A match emits `rule: custom-signature` with the `sid`/`msg` in `detail`,
severity from `classtype` (or the `[rules.custom-signature]` default), plus the
standard risk score, MITRE and tags.

## Supported Snort syntax

Enforced in-engine:

- **Header:** `action proto src_host src_port -> dst_host dst_port`
- **Addresses:** `any`, CIDR, IP, `[a,b]` lists, `$VAR` (resolved via `vars`)
- **Ports:** single, `lo:hi` ranges, `[a,b]` lists
- **`flow:`** → direction heuristic (`$EXTERNAL_NET -> $HOME_NET` = inbound)
- **`content:"..."`** with `|hex bytes|` groups, `nocase`, `depth`, `offset`
- **`sid`, `rev`, `msg`, `classtype`, `reference`**

Exported to Sigma but **not** enforced in-engine:

- **`pcre:`** — a rule whose only matcher is a regex is skipped (logged).
- **`flowbits:`** — stateful flow correlation is not implemented.
- **`distance` / `within`** multi-content ordering — only the first `content` is
  matched, positionally via `depth`/`offset`.

This covers the large majority of community rules; the skipped ones still reach
your SIEM via Sigma.

## Payload requirement

`content` matching inspects the packet payload, which the decoder snapshots up to
`MAX_PAYLOAD_SNAP` (512 B) per event. Therefore:

- `content` rules require live capture or pcap replay (not flow logs).
- If a rule's `content` sits beyond the snapshot window, raise `MAX_PAYLOAD_SNAP`
  (code change) or move that detection to Sigma/SIEM.

## Validating a rules file

```bash
ingressd snort2sigma rules/local.rules.example | head -n 40   # parse + view Sigma
```
Unparseable lines are skipped; the startup log reports how many rules loaded and
how many became enforceable signatures.
