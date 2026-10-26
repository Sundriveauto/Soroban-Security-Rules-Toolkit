# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/). Changes that make an existing rule report new findings
are listed under **Changed**.

## [Unreleased]

### Changed

- SG-001 no longer trusts a helper because of its name alone (`require_admin`, `check_owner_auth`, …)
  when the crate defines it: the helper's body must actually authorize. Names are still trusted for
  helpers defined outside the crate.
- SG-001 reports upgrades, outflows and privileged writes whose only authorization runs on some code
  paths (inside an `if` without `else`, one `match` arm, or a loop body) with medium confidence.
- SG-003 treats `i128` / `u128` function parameters as token amounts regardless of name (medium
  confidence at most).
- Real-world baseline (`docs/validation.md`): no change on soroban-examples; one extra `info` finding
  on OpenZeppelin stellar-contracts.

## [0.1.0] - 2026-10-26

### Added

- `stellar-guard` CLI with `scan`, `rules`, `explain` and `init` subcommands.
- Rules:
  - SG-001 `missing-authorization`
  - SG-002 `storage-tier-misuse`
  - SG-003 `unchecked-arithmetic` (aware of `overflow-checks`)
  - SG-004 `unbounded-iteration`
  - SG-005 `unprotected-initializer`
- Crate-wide semantic model that follows helper functions transitively.
- Output formats: text, JSON (schema 1.0), SARIF 2.1.0, GitHub annotations, Markdown; multiple
  outputs per run with `--report FORMAT=PATH`.
- `stellar-guard.toml` configuration with strict validation, severity overrides, per-rule options
  and confidence filtering.
- Inline (`stellar-guard-ignore`) and file-level suppressions.
- Configurable exit codes via `--fail-on`.
- Deterministic reports with line-independent fingerprints.
- Vulnerable and safe fixture contracts (compile against soroban-sdk 22) with marker-driven tests.
- Real-world precision baseline on soroban-examples and OpenZeppelin stellar-contracts (`docs/validation.md`).
- GitHub Action with PR annotations, job summary and code-scanning upload.
- CI (fmt, clippy, tests on Linux/macOS/Windows, MSRV, docs, self-scan, action test, audit) and
  release workflows.

[Unreleased]: https://github.com/petermuazu/Soroban-Security-Rules-Toolkit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/petermuazu/Soroban-Security-Rules-Toolkit/releases/tag/v0.1.0
