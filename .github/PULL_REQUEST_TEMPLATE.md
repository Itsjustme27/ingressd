## Summary

<!-- What does this PR do, and why? Link the issue with "Closes #123". -->

Closes #

## Type of change

- [ ] Bug fix
- [ ] New detection rule / Snort capability
- [ ] Feature / enhancement
- [ ] Performance
- [ ] Documentation
- [ ] Refactor

## How to test

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
# if capture/rules changed:
cargo test --workspace --features live-capture,geoip
```

## Checklist

- [ ] Tests added/updated (synthetic packets or pcap for rule changes; `proptest` for window/LRU logic)
- [ ] `#![forbid(unsafe_code)]` preserved (any new `unsafe` has a `// SAFETY:` note)
- [ ] No false positives introduced on benign traffic (e2e replay asserts this)
- [ ] `CHANGELOG.md` updated under **Unreleased**
- [ ] Docs/config example updated if behavior or config changed
- [ ] Conventional Commits used (`feat:`/`fix:`/`docs:`/…)

## Notes for reviewers

<!-- Risk areas, follow-ups, or anything to look at closely. -->
