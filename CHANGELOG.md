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
- SG-001 reports a balance debit keyed by an address that did not authorize
  (`caller.require_auth(); spend_balance(&e, &victim, amount)`), `require_auth_for_args` calls that
  sign none of the amounts or addresses, and balance debits behind conditional authorization. Auth
  inside closures counts as conditional. Contract upgrades through
  `deployer().update_current_contract(..)` are recognised.
- SG-002 reports a `Map`/`Vec` kept under one instance key that grows with caller-supplied entries.
- SG-003 tracks amounts through local variables and reports division before multiplication (info).
  Per-package `[profile.release.package.<name>] overflow-checks` overrides are honoured.
- SG-004 recognises length caps checked in helpers or where the storage key is written, under any
  variable name (4 fewer false positives on OpenZeppelin stellar-contracts).
- SG-005 reports initializer guards on a key the initializer never writes.
- SG-004 traces where a collection's length comes from: lists built element-wise from parameters or
  returned by cross-contract calls are no longer treated as storage-backed, `len() == MAX` counts as
  a cap, and lists derived from a capped stored list inherit the cap (OpenZeppelin stellar-contracts:
  10 → 3 warnings, recall unchanged at 12 / 12).
- Calls are resolved by module path, impl type and trait (`a::f`, `Self::f`, `<T as Tr>::f`), trait
  default methods are modelled, and helpers in local dependency crates of the same workspace are
  followed.
- Storage keys defined as constants (`const KEY: Symbol = symbol_short!("ADMIN")`) are resolved.
- Files starting with `#![cfg(test)]` and cargo-fuzz `fuzz_targets/` are treated as test code.
- Throughput is about 25% lower than 0.1.0 (see `docs/benchmarks.md`).

### Added

- SG-006 `negative-amount`: `i128` parameters written to storage without a sign check.
- SG-007 `missing-ttl-extension` (info): persistent / instance data whose TTL is never extended.
- SG-008 `ignored-try-call`: discarded results of `client.try_*` cross-contract calls.
- SG-009 `weak-check-auth` (error): custom-account `__check_auth` that verifies no signature, or a
  signature not bound to `signature_payload`.
- `scripts/seeded_bugs.py` recall check: 12 / 12 seeded bugs detected in soroban-examples (0.1.0:
  6 / 12). Real-world baseline updated in `docs/validation.md`.
- Golden-file tests for every report format (text, JSON, SARIF, GitHub, Markdown).

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
