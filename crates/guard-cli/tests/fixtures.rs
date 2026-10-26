//! Fixture contracts are the ground truth for rule behaviour:
//! * every `// expect: SG-xxx` marker in `fixtures/vulnerable-examples` must be
//!   reported on exactly that line, and nothing else may be reported;
//! * `fixtures/safe-contracts` must produce no findings at all.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use guard_engine::{Engine, Settings};

fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures")
}

fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = fs::read_dir(dir).unwrap().map(|e| e.unwrap().path()).collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            rs_files(&p, out);
        } else if p.extension().is_some_and(|e| e == "rs") {
            out.push(p);
        }
    }
}

/// `(relative file, line, rule)` triples from `// expect:` markers.
fn expected(root: &Path) -> BTreeSet<(String, usize, String)> {
    let mut files = Vec::new();
    rs_files(root, &mut files);
    let mut set = BTreeSet::new();
    for f in files {
        let rel = f.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
        for (i, line) in fs::read_to_string(&f).unwrap().lines().enumerate() {
            if let Some(idx) = line.find("// expect:") {
                for id in line[idx + "// expect:".len()..].split(',') {
                    let id = id.trim();
                    let valid = id.len() == 6 && id.starts_with("SG-") && id[3..].bytes().all(|b| b.is_ascii_digit());
                    assert!(valid, "malformed marker `{id}` in {rel}:{}", i + 1);
                    set.insert((rel.clone(), i + 1, id.to_string()));
                }
            }
        }
    }
    set
}

fn actual(root: &Path) -> BTreeSet<(String, usize, String)> {
    let report =
        Engine::new(guard_rules::all()).scan(&[root.to_path_buf()], &Settings::default()).expect("scan succeeds");
    assert!(report.parse_failures.is_empty(), "{:?}", report.parse_failures);
    let root_str = root.to_string_lossy().replace('\\', "/");
    report
        .findings
        .iter()
        .map(|f| {
            let file = f.location.file.replace('\\', "/");
            let rel =
                file.strip_prefix(&root_str).map(|s| s.trim_start_matches('/').to_string()).unwrap_or_else(|| {
                    // Path was made relative to the current directory.
                    let abs = fs::canonicalize(&file).unwrap();
                    let root = fs::canonicalize(root).unwrap();
                    abs.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/")
                });
            (rel, f.location.start_line, f.rule_id.clone())
        })
        .collect()
}

fn diff(expected: &BTreeSet<(String, usize, String)>, actual: &BTreeSet<(String, usize, String)>) -> String {
    let missing: Vec<_> = expected.difference(actual).collect();
    let extra: Vec<_> = actual.difference(expected).collect();
    format!("missing (false negatives): {missing:#?}\nunexpected (false positives): {extra:#?}")
}

#[test]
fn vulnerable_examples_match_markers() {
    let root = fixtures_dir().join("vulnerable-examples");
    let exp = expected(&root);
    assert!(exp.len() >= 15, "fixtures should contain markers");
    let rules: BTreeSet<_> = exp.iter().map(|(_, _, r)| r.clone()).collect();
    assert_eq!(rules.len(), guard_rules::all().len(), "every rule needs vulnerable fixtures: {rules:?}");
    let act = actual(&root);
    assert_eq!(exp, act, "\n{}", diff(&exp, &act));
}

#[test]
fn safe_contracts_are_clean() {
    let root = fixtures_dir().join("safe-contracts");
    assert!(expected(&root).is_empty(), "safe fixtures must not contain markers");
    let act = actual(&root);
    assert!(act.is_empty(), "false positives in safe contracts: {act:#?}");
}

#[test]
fn each_vulnerable_fixture_is_detected_in_isolation() {
    let root = fixtures_dir().join("vulnerable-examples");
    for entry in fs::read_dir(&root).unwrap() {
        let dir = entry.unwrap().path();
        if dir.is_dir() {
            let exp = expected(&dir);
            let act = actual(&dir);
            assert_eq!(exp, act, "fixture {}:\n{}", dir.display(), diff(&exp, &act));
        }
    }
}
