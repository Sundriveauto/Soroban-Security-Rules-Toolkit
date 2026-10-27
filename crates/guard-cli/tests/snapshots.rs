//! Golden-file tests for every report format.
//!
//! Each format is rendered for a vulnerable fixture (several rules, helper
//! chains, suppressible findings) and for the safe contracts (an empty report
//! with a suppressed finding), then compared with `tests/snapshots/`.
//!
//! After an intentional output change, regenerate with:
//! `UPDATE_SNAPSHOTS=1 cargo test -p stellar-guard --test snapshots` and review the diff.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use guard_engine::{Engine, Settings};
use guard_reporters::{render, Format, RenderOptions};

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn snapshot(name: &str, actual: &str) {
    // Keep snapshots stable across releases.
    let actual = actual.replace(env!("CARGO_PKG_VERSION"), "<version>");
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/snapshots").join(name);
    if std::env::var_os("UPDATE_SNAPSHOTS").is_some() {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, &actual).unwrap();
        return;
    }
    let expected = fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("missing snapshot {}; run with UPDATE_SNAPSHOTS=1", path.display()))
        .replace("\r\n", "\n");
    if expected != actual {
        let first = expected.lines().zip(actual.lines()).position(|(a, b)| a != b);
        panic!(
            "snapshot {name} differs (first differing line: {first:?}); run with UPDATE_SNAPSHOTS=1 and review.\n\
--- expected\n{expected}\n--- actual\n{actual}"
        );
    }
}

/// Tests in this file change the working directory; run them one at a time.
static CWD: Mutex<()> = Mutex::new(());

fn check_all(fixture: &str, prefix: &str) {
    // Scan with a path relative to the workspace root so snapshots do not depend on the machine.
    let _guard = CWD.lock().unwrap_or_else(|e| e.into_inner());
    let cwd = std::env::current_dir().unwrap();
    std::env::set_current_dir(root()).unwrap();
    let report = Engine::new(guard_rules::all()).scan(&[PathBuf::from(fixture)], &Settings::default());
    std::env::set_current_dir(cwd).unwrap();
    let report = report.expect("scan succeeds");
    for (format, ext) in [
        (Format::Text, "txt"),
        (Format::Json, "json"),
        (Format::Sarif, "sarif"),
        (Format::Github, "github"),
        (Format::Markdown, "md"),
    ] {
        let out = render(&report, format, &RenderOptions { color: false });
        snapshot(&format!("{prefix}.{ext}"), &out);
    }
}

#[test]
fn vulnerable_missing_auth() {
    check_all("fixtures/vulnerable-examples/missing-auth", "missing-auth");
}

#[test]
fn safe_contracts() {
    check_all("fixtures/safe-contracts", "safe");
}
