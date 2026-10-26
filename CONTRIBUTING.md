# Contributing to stellar-guard

Thanks for helping make Soroban contracts safer. Useful contributions include new rules, better
precision for existing rules, fixtures, false-positive reports, docs and CI integrations.

## Development setup

```sh
git clone https://github.com/petermuazu/Soroban-Security-Rules-Toolkit
cd Soroban-Security-Rules-Toolkit
cargo test --workspace          # unit, fixture and CLI tests
cargo run -- scan fixtures      # try the CLI (the workspace default binary is stellar-guard)
cargo bench -p guard-cli        # scan benchmark
```

Before opening a pull request:

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

The minimum supported Rust version is **1.88**; CI checks it.

## Project layout

| Crate | Responsibility |
|---|---|
| `guard-parser` | file discovery, `syn` parsing, Cargo metadata, the per-crate `CrateModel` |
| `guard-engine` | `Rule` trait, configuration, suppressions, findings, fingerprints, the scan pipeline |
| `guard-rules` | one module per rule |
| `guard-reporters` | output formats |
| `guard-cli` | the `stellar-guard` binary, integration tests, benchmarks |

See [docs/architecture.md](docs/architecture.md).

## Adding a rule

1. **Open an issue first** using the *New rule* template: the pattern, why it is dangerous on
   Soroban, a vulnerable example, a safe look-alike, and expected false positives.
2. **Pick the next free ID** (`SG-006`, …). IDs are never reused.
3. **Create `crates/guard-rules/src/sgNNN_<name>.rs`** implementing `guard_engine::Rule`:
   * a `static META: RuleMeta` with `id`, kebab-case `name`, one-line `summary`, a `description`
     explaining what is detected *and why it matters on Soroban*, a short `remediation`,
     `default_severity`, `tags` and any `options`;
   * `check()` that pushes `Diagnostic`s with an accurate `Confidence` and `in_function(..)`.
   * Prefer the precomputed `cx.model.facts` and `cx.model.witness(..)` over re-walking bodies.
   * Point the span at the code the user must change (the operation, or the call into the helper).
4. **Register it** in `guard_rules::all()` (keep IDs sorted).
5. **Unit tests in the same file**, at least:
   * true positives, including one that goes through a helper function;
   * false positives that must *not* be reported (the safe look-alikes);
   * every option.
6. **Fixtures:**
   * add a vulnerable example under `fixtures/vulnerable-examples/<name>/` (a small, realistic
     Soroban crate with its own `Cargo.toml` and `[workspace]`). Mark every line that must be
     reported with a trailing `// expect: SG-NNN` comment. `crates/guard-cli/tests/fixtures.rs`
     fails if a marker is missed or anything unmarked is reported;
   * make sure `fixtures/safe-contracts/` still produces zero findings, and add safe patterns there
     if your rule could plausibly misfire on them.
   * Fixtures should compile: `cd fixtures/... && cargo check --lib`.
7. **Docs:** add `docs/rules/SG-NNN.md` (copy an existing page: detects, why it matters, example
   and fix, known limitations, options, fixtures), and add the rule to `docs/rules/README.md` and
   the table in `README.md`. A test checks that every rule has a docs page.
8. **Changelog:** add an entry under *Unreleased* in `CHANGELOG.md`.

### Rule quality bar

* **Precision over recall.** A noisy rule gets disabled, and then it protects no one. If a pattern
  is ambiguous, lower the confidence rather than dropping the check.
* **Deterministic.** No hash-map iteration order in output, no timestamps.
* **Explainable.** The message says what was found; the help says what to do.
* **Honest docs.** Document known false positives and false negatives.

## Reporting false positives or false negatives

Use the *False positive / negative* issue template with a minimal code snippet. These reports are
the most valuable input for improving rules. If you can, add the snippet as a unit test.

## Commit and PR guidelines

* Keep pull requests focused; one rule per PR.
* Describe behaviour changes to existing rules (new findings on existing code are breaking for
  users with `--fail-on`).
* By contributing you agree that your contributions are dual licensed under MIT OR Apache-2.0.
