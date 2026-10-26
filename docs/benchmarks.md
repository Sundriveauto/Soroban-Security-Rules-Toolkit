# Benchmarks

The benchmark in [`crates/guard-cli/benches/scan.rs`](../crates/guard-cli/benches/scan.rs) builds
synthetic projects by copying every fixture file into N separate Soroban crates, then times a full
`Engine::scan` (discovery, parsing, crate resolution, model building, all nine rules,
post-processing).

```sh
cargo bench -p guard-cli
```

## Results

Measured on a 2-vCPU GitHub Codespace (Intel Xeon Platinum 8573C), Rust 1.99, release profile:

| Files | Source size | Time (median) | Throughput |
|---|---|---|---|
| 15 | ~31 KiB | 14.7 ms | 2.1 MiB/s |
| 150 | ~311 KiB | 147 ms | 2.1 MiB/s |
| 750 | ~1.55 MiB | 665 ms | 2.3 MiB/s |

Scan time grows linearly with the amount of source. A typical Soroban workspace (a few to a few
dozen files) scans in well under 100 ms, so stellar-guard adds no meaningful time to CI.

Real repositories (release build, same machine, median of 5 runs, including process start):

| Repository | Files | Time |
|---|---|---|
| stellar/soroban-examples | 109 | 0.10 s |
| OpenZeppelin/stellar-contracts | 257 | 0.73 s |

Compared with 0.1.0 (five rules, name-only call resolution), throughput is about 25% lower: the
model now tracks authorization subjects, debits, call arguments and dependency crates, and four
rules were added.

## Where the time goes

Profiling the 110-file case with `valgrind --tool=callgrind`:

| Phase | Share (0.1.0) |
|---|---|
| `syn` parsing (with span locations) | ~63% |
| Model building and rules | ~21% |
| Discovery, I/O, crate resolution, reporting | ~16% |

Profiling OpenZeppelin stellar-contracts (257 files) with the current version: `syn` parsing ~68%,
model building ~18%, rules and reporting the rest. Parsing cannot be parallelised without
restructuring, because `syn` trees hold `proc_macro2` tokens that cannot move between threads and
the model borrows them.

Parsing dominates, so rule changes rarely affect performance noticeably. When adding a rule, avoid
converting large syntax trees to token streams repeatedly (e.g. calling `syntax::idents` on whole
function bodies inside a loop); prefer the precomputed `FnFacts` in `CrateModel`.
