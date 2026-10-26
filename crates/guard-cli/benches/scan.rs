//! Scan throughput benchmark.
//!
//! Builds synthetic Soroban projects by replicating the fixture contracts,
//! then measures a full scan (discovery, parsing, modelling, all rules).
//!
//! Run with `cargo bench -p guard-cli`.

use std::fs;
use std::path::{Path, PathBuf};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use guard_engine::{Engine, Settings};

fn fixture_sources() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures");
    let mut out = Vec::new();
    let mut stack = vec![root.clone()];
    while let Some(dir) = stack.pop() {
        for e in fs::read_dir(&dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                let rel = p.strip_prefix(&root).unwrap().to_string_lossy().replace(['/', '\\'], "_");
                out.push((rel, fs::read_to_string(&p).unwrap()));
            }
        }
    }
    out.sort();
    out
}

/// Creates `crates` copies of every fixture file, each in its own Soroban crate.
fn synthetic_project(dir: &Path, crates: usize) -> (PathBuf, usize, u64) {
    let sources = fixture_sources();
    let mut files = 0;
    let mut bytes = 0u64;
    for c in 0..crates {
        let krate = dir.join(format!("contract_{c}"));
        fs::create_dir_all(krate.join("src")).unwrap();
        fs::write(
            krate.join("Cargo.toml"),
            format!("[package]\nname = \"c{c}\"\nversion = \"0.0.0\"\n[dependencies]\nsoroban-sdk = \"22\"\n"),
        )
        .unwrap();
        for (name, text) in &sources {
            fs::write(krate.join("src").join(name), text).unwrap();
            files += 1;
            bytes += text.len() as u64;
        }
    }
    (dir.to_path_buf(), files, bytes)
}

fn bench_scan(c: &mut Criterion) {
    let engine = Engine::new(guard_rules::all());
    let settings = Settings::default();
    let mut group = c.benchmark_group("scan");
    group.sample_size(20);
    for crates in [1usize, 10, 50] {
        let tmp = tempfile::tempdir().unwrap();
        let (root, files, bytes) = synthetic_project(tmp.path(), crates);
        group.throughput(Throughput::Bytes(bytes));
        group.bench_with_input(BenchmarkId::new("files", files), &root, |b, root| {
            b.iter(|| {
                let report = engine.scan(std::slice::from_ref(root), &settings).unwrap();
                assert!(!report.findings.is_empty());
                report
            })
        });
    }
    group.finish();
}

criterion_group!(benches, bench_scan);
criterion_main!(benches);
