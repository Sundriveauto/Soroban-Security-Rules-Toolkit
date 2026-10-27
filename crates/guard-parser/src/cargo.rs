//! Minimal Cargo manifest inspection: which crate a file belongs to, whether
//! that crate depends on `soroban-sdk`, and whether release builds enable
//! `overflow-checks`.

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

/// Facts about the Cargo package a source file belongs to.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CrateInfo {
    /// Directory containing the package `Cargo.toml`, if one was found.
    pub root: Option<PathBuf>,
    /// Package name from the manifest.
    pub name: Option<String>,
    /// `true` when the package depends on `soroban-sdk`.
    pub depends_on_soroban: bool,
    /// `overflow-checks` for the release profile: `Some(true)`/`Some(false)` when
    /// a manifest was found, `None` when unknown.
    pub overflow_checks: Option<bool>,
    /// Names of local dependencies (`path = ".."` or `workspace = true`), with `-`
    /// replaced by `_`. Helpers in these crates are followed when resolving calls.
    pub local_deps: Vec<String>,
    /// `true` for test-support crates: a regular (non-dev) dependency enables a
    /// `testutils` feature, which `soroban-sdk` rejects on wasm, so the crate is
    /// never deployed (integration test suites, mock contracts built for tests).
    pub test_support: bool,
}

impl CrateInfo {
    /// Package name as used in Rust paths (`my-lib` → `my_lib`).
    pub fn rust_name(&self) -> Option<String> {
        self.name.as_ref().map(|n| n.replace('-', "_"))
    }
}

/// Caches manifest lookups so each directory is inspected at most once.
#[derive(Debug, Default)]
pub struct CrateResolver {
    by_dir: HashMap<PathBuf, Option<PathBuf>>,
    crates: Vec<CrateInfo>,
}

impl CrateResolver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the index of the crate owning `file` (creating it if needed).
    /// Files outside any Cargo package share a single "unknown" crate.
    pub fn crate_for(&mut self, file: &Path) -> usize {
        let start = file.parent().map(Path::to_path_buf).unwrap_or_default();
        let start = fs::canonicalize(&start).unwrap_or(start);
        match self.package_dir(&start) {
            Some(dir) => {
                if let Some(idx) = self.crates.iter().position(|c| c.root.as_deref() == Some(&dir)) {
                    return idx;
                }
                let info = load_crate_info(&dir);
                self.crates.push(info);
                self.crates.len() - 1
            }
            None => {
                if let Some(idx) = self.crates.iter().position(|c| c.root.is_none()) {
                    return idx;
                }
                self.crates.push(CrateInfo::default());
                self.crates.len() - 1
            }
        }
    }

    fn package_dir(&mut self, start: &Path) -> Option<PathBuf> {
        if let Some(cached) = self.by_dir.get(start) {
            return cached.clone();
        }
        let mut found = None;
        let mut cur = Some(start);
        while let Some(dir) = cur {
            let manifest = dir.join("Cargo.toml");
            if manifest.is_file() && read_manifest(&manifest).is_some_and(|t| t.contains_key("package")) {
                found = Some(dir.to_path_buf());
                break;
            }
            cur = dir.parent();
        }
        self.by_dir.insert(start.to_path_buf(), found.clone());
        found
    }

    pub fn into_crates(self) -> Vec<CrateInfo> {
        self.crates
    }
}

fn read_manifest(path: &Path) -> Option<toml::Table> {
    let text = fs::read_to_string(path).ok()?;
    text.parse::<toml::Table>().ok()
}

/// Dependencies declared with `path = ".."` or `workspace = true` (normalized names).
fn local_deps(table: &toml::Table) -> Vec<String> {
    let mut out: Vec<String> = ["dependencies", "dev-dependencies"]
        .iter()
        .filter_map(|k| table.get(*k)?.as_table())
        .flat_map(|deps| deps.iter())
        .filter(|(_, spec)| {
            spec.as_table()
                .is_some_and(|t| t.contains_key("path") || t.get("workspace").and_then(|w| w.as_bool()) == Some(true))
        })
        .map(|(name, spec)| {
            let real = spec.as_table().and_then(|t| t.get("package")).and_then(|p| p.as_str()).unwrap_or(name);
            real.replace('-', "_")
        })
        .filter(|n| n != "soroban_sdk")
        .collect();
    out.sort();
    out.dedup();
    out
}

fn has_soroban_dep(table: &toml::Table) -> bool {
    let dep_tables = ["dependencies", "dev-dependencies", "build-dependencies"];
    let direct = dep_tables
        .iter()
        .any(|k| table.get(*k).and_then(|v| v.as_table()).is_some_and(|t| t.contains_key("soroban-sdk")));
    let target_specific = table.get("target").and_then(|t| t.as_table()).is_some_and(|targets| {
        targets.values().any(|cfg| {
            cfg.as_table().is_some_and(|cfg| {
                dep_tables
                    .iter()
                    .any(|k| cfg.get(*k).and_then(|v| v.as_table()).is_some_and(|t| t.contains_key("soroban-sdk")))
            })
        })
    });
    direct || target_specific
}

fn enables_testutils(table: &toml::Table) -> bool {
    let in_deps = |t: &toml::Table| {
        t.get("dependencies").and_then(|d| d.as_table()).is_some_and(|deps| {
            deps.values().any(|spec| {
                spec.as_table()
                    .and_then(|s| s.get("features"))
                    .and_then(|f| f.as_array())
                    .is_some_and(|f| f.iter().any(|x| x.as_str() == Some("testutils")))
            })
        })
    };
    in_deps(table)
        || table
            .get("target")
            .and_then(|t| t.as_table())
            .is_some_and(|targets| targets.values().any(|cfg| cfg.as_table().is_some_and(in_deps)))
}

fn release_overflow_checks(table: &toml::Table) -> Option<bool> {
    table.get("profile")?.as_table()?.get("release")?.as_table()?.get("overflow-checks")?.as_bool()
}

/// `[profile.release.package.<name>] overflow-checks`. The `"*"` pattern only
/// applies to non-workspace dependencies, so it is ignored for scanned crates.
fn package_overflow_checks(table: &toml::Table, package: &str) -> Option<bool> {
    table
        .get("profile")?
        .as_table()?
        .get("release")?
        .as_table()?
        .get("package")?
        .as_table()?
        .get(package)?
        .as_table()?
        .get("overflow-checks")?
        .as_bool()
}

/// Loads crate facts for the package rooted at `dir`.
pub fn load_crate_info(dir: &Path) -> CrateInfo {
    let manifest = read_manifest(&dir.join("Cargo.toml")).unwrap_or_default();
    let name = manifest.get("package").and_then(|p| p.get("name")).and_then(|n| n.as_str()).map(str::to_string);

    // Profiles are only honoured in the workspace root manifest. Find the
    // closest ancestor (including the package itself) declaring `[workspace]`.
    let mut overflow = None;
    let mut cur = Some(dir);
    let mut root_manifest = None;
    while let Some(d) = cur {
        if let Some(t) = read_manifest(&d.join("Cargo.toml")) {
            if t.contains_key("workspace") {
                root_manifest = Some(t);
                break;
            }
        }
        cur = d.parent();
    }
    let root_manifest = root_manifest.unwrap_or_else(|| manifest.clone());
    if let Some(v) = release_overflow_checks(&root_manifest) {
        overflow = Some(v);
    }
    if let Some(v) = name.as_deref().and_then(|n| package_overflow_checks(&root_manifest, n)) {
        overflow = Some(v);
    }
    // Cargo's release default is `false` when unspecified.
    let overflow_checks = Some(overflow.unwrap_or(false));

    CrateInfo {
        root: Some(dir.to_path_buf()),
        name,
        depends_on_soroban: has_soroban_dep(&manifest),
        overflow_checks,
        local_deps: local_deps(&manifest),
        test_support: enables_testutils(&manifest),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, rel: &str, text: &str) {
        let p = dir.join(rel);
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(p, text).unwrap();
    }

    #[test]
    fn detects_soroban_and_workspace_overflow_checks() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "Cargo.toml", "[workspace]\nmembers=[\"c\"]\n[profile.release]\noverflow-checks = true\n");
        write(d.path(), "c/Cargo.toml", "[package]\nname=\"c\"\n[dependencies]\nsoroban-sdk = { workspace = true }\n");
        write(d.path(), "c/src/lib.rs", "");
        let mut r = CrateResolver::new();
        let idx = r.crate_for(&d.path().join("c/src/lib.rs"));
        let info = &r.into_crates()[idx];
        assert_eq!(info.name.as_deref(), Some("c"));
        assert!(info.depends_on_soroban);
        assert_eq!(info.overflow_checks, Some(true));
    }

    #[test]
    fn testutils_in_regular_dependencies_marks_a_test_support_crate() {
        let d = tempfile::tempdir().unwrap();
        let cases = [
            ("suite", "[dependencies]\nsoroban-sdk = { workspace = true, features = [\"testutils\"] }\n", true),
            ("mock", "[dependencies]\npool = { path = \"../pool\", features = [\"testutils\"] }\n", true),
            (
                "contract",
                "[dependencies]\nsoroban-sdk = \"22\"\n[dev-dependencies]\nsoroban-sdk = { version = \"22\", features = [\"testutils\"] }\n\
[features]\ntestutils = [\"soroban-sdk/testutils\"]\n",
                false,
            ),
        ];
        for (name, deps, expected) in cases {
            write(d.path(), &format!("{name}/Cargo.toml"), &format!("[package]\nname=\"{name}\"\n{deps}"));
            write(d.path(), &format!("{name}/src/lib.rs"), "");
            let mut r = CrateResolver::new();
            let idx = r.crate_for(&d.path().join(format!("{name}/src/lib.rs")));
            assert_eq!(r.into_crates()[idx].test_support, expected, "{name}");
        }
    }

    #[test]
    fn package_profile_override_wins() {
        let d = tempfile::tempdir().unwrap();
        write(
            d.path(),
            "Cargo.toml",
            "[workspace]\nmembers=[\"a\",\"b\"]\n[profile.release]\noverflow-checks = true\n\
[profile.release.package.a]\noverflow-checks = false\n[profile.release.package.\"*\"]\noverflow-checks = false\n",
        );
        for c in ["a", "b"] {
            write(d.path(), &format!("{c}/Cargo.toml"), &format!("[package]\nname=\"{c}\"\n"));
            write(d.path(), &format!("{c}/src/lib.rs"), "");
        }
        let mut r = CrateResolver::new();
        let a = r.crate_for(&d.path().join("a/src/lib.rs"));
        let b = r.crate_for(&d.path().join("b/src/lib.rs"));
        let crates = r.into_crates();
        assert_eq!(crates[a].overflow_checks, Some(false));
        assert_eq!(crates[b].overflow_checks, Some(true), "\"*\" does not apply to workspace members");
    }

    #[test]
    fn standalone_package_defaults_to_no_overflow_checks() {
        let d = tempfile::tempdir().unwrap();
        write(d.path(), "Cargo.toml", "[package]\nname=\"x\"\n[dependencies]\nserde=\"1\"\n");
        write(d.path(), "src/lib.rs", "");
        let mut r = CrateResolver::new();
        let a = r.crate_for(&d.path().join("src/lib.rs"));
        let b = r.crate_for(&d.path().join("src/lib.rs"));
        assert_eq!(a, b);
        let info = &r.into_crates()[a];
        assert!(!info.depends_on_soroban);
        assert_eq!(info.overflow_checks, Some(false));
    }
}
