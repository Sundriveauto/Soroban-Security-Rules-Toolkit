## Summary

<!-- What does this change and why? Link the issue. -->

## Checklist

- [ ] `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings` and `cargo test --workspace` pass
- [ ] New/changed rule: unit tests for true positives **and** false positives
- [ ] New/changed rule: fixtures updated (`// expect:` markers; safe contracts still clean)
- [ ] Docs updated (`docs/rules/`, README rule table, configuration)
- [ ] `CHANGELOG.md` entry under *Unreleased* (note any new findings on existing code)
