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

fn release_overflow_checks(table: &toml::Table) -> Option<bool> {
    table.get("profile")?.as_table()?.get("release")?.as_table()?.get("overflow-checks")?.as_bool()
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
    // Cargo's release default is `false` when unspecified.
    let overflow_checks = Some(overflow.unwrap_or(false));

    CrateInfo { root: Some(dir.to_path_buf()), name, depends_on_soroban: has_soroban_dep(&manifest), overflow_checks }
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
