# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| `main` (latest) | ✅ |
| `0.1.x` | ✅ |

## Reporting a vulnerability

Please **do not** open a public issue for security problems. Report them
privately via GitHub's
[private vulnerability reporting](https://github.com/kalidada18/ingressd/security/advisories/new),
or email the maintainer with the subject prefix `ingressd-security`.

We aim to:

- Acknowledge reports within **3 business days**.
- Ship a fix or mitigation within **30 days** for confirmed issues.
- Publish a GitHub Security Advisory and credit the reporter (with permission).

## Scope

Reportable: memory-safety / `unsafe` soundness in the capture path, parser
panics or out-of-bounds reads on untrusted packets, privilege escalation,
allowlist/never-block bypass, credential or feed-content handling flaws, and
DoS that exhausts resources beyond the documented bounds.

Not in scope: findings requiring you to already control the host, or issues in
third-party dependencies we do not vendor (report those upstream; we track
advisories via `cargo audit` in CI and Dependabot).

## Hardening defaults (defense in depth)

- `#![forbid(unsafe_code)]` everywhere except the isolated `AF_PACKET` module.
- Runs as a non-root `ingressd` user with `CAP_NET_RAW` only
  (`CAP_NET_ADMIN` only when active response is enabled).
- Hardened `systemd` unit (see `deploy/systemd/ingressd.service`) plus optional
  AppArmor (`deploy/security/apparmor/ingressd`) and seccomp
  (`deploy/security/seccomp/ingressd.json`).
- Bounded, LRU-capped state and bounded channels; no unbounded queues.
- Metrics bound to loopback by default; active response is opt-in and dry-run.

## Safe-use policy

ingressd is a **passive detector**. It never injects packets, never scans third
parties, and treats threat-intel content strictly as data. Deploy it only on
infrastructure you own or are authorized to monitor.
