# Benchmarks

The benchmark in [`crates/guard-cli/benches/scan.rs`](../crates/guard-cli/benches/scan.rs) builds
synthetic projects by copying every fixture file into N separate Soroban crates, then times a full
`Engine::scan` (discovery, parsing, crate resolution, model building, all five rules,
post-processing).

```sh
cargo bench -p guard-cli
```

## Results

Measured on a 2-vCPU GitHub Codespace (Intel Xeon Platinum 8573C), Rust 1.99, release profile:

| Files | Source size | Time (median) | Throughput |
|---|---|---|---|
| 11 | ~21 KiB | 6.2 ms | 3.4 MiB/s |
| 110 | ~214 KiB | 67 ms | 3.1 MiB/s |
| 550 | ~1.05 MiB | 350 ms | 3.0 MiB/s |

Scan time grows linearly with the amount of source. A typical Soroban workspace (a few to a few
dozen files) scans in well under 100 ms, so stellar-guard adds no meaningful time to CI.

## Where the time goes

Profiling the 110-file case with `valgrind --tool=callgrind`:

| Phase | Share |
|---|---|
| `syn` parsing (with span locations) | ~63% |
| Model building and rules | ~21% |
| Discovery, I/O, crate resolution, reporting | ~16% |

Parsing dominates, so rule changes rarely affect performance noticeably. When adding a rule, avoid
converting large syntax trees to token streams repeatedly (e.g. calling `syntax::idents` on whole
function bodies inside a loop); prefer the precomputed `FnFacts` in `CrateModel`.
