# Contributing to ingressd

Thanks for your interest in improving ingressd! This guide covers how to build,
test, and submit changes.

## Code of conduct

Be respectful and constructive. ingressd is a **defensive** tool; issues or PRs
that repurpose it for attacking third parties will be closed.

## Development setup

```bash
# Rust stable (>= 1.75). Components come from rust-toolchain.toml.
git clone https://github.com/kalidada18/ingressd
cd ingressd
cargo build                         # safe, portable default build
cargo test --workspace              # no privileges / no network required
```

Live capture is Linux-only and behind a feature flag:

```bash
cargo build --release --features live-capture
cargo test  --workspace --features live-capture,geoip
```

## Before you open a PR

CI enforces all of these — run them locally first:

```bash
cargo fmt --all                     # formatting (rustfmt.toml)
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

- Add or update tests for any behavior change. Rule changes need a synthetic
  packet/pcap test; window/LRU logic changes need `proptest` coverage.
- Keep `#![forbid(unsafe_code)]` everywhere except the isolated `afpacket`
  module; any new `unsafe` needs a `// SAFETY:` comment.
- Update `CHANGELOG.md` under **Unreleased**.

## Commit messages

We use [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add ICMP tunneling detector
fix(cli): correct allowlist parsing for IPv6
docs: expand Snort integration guide
ci: pin rust-cache to v2
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `perf`, `chore`, `ci`, `style`.

## Pull requests

- Fill in the PR template; link the issue it closes.
- Keep PRs focused and small where possible.
- CI must be green (or explain any known-flaky job).

## Reporting bugs

Use the **Bug report** issue template and include: ingressd version, config
(redact secrets/IPs as needed), the pcap or a `pcapgen` scenario that reproduces
it, and the relevant `journalctl`/`/metrics` output.

## License

By contributing you agree that your contributions are licensed under the
project's MIT OR Apache-2.0 dual license.
