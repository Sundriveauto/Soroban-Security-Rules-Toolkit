//! Finding Rust source files to analyze.

use std::path::{Path, PathBuf};

use globset::{Glob, GlobSet, GlobSetBuilder};

/// Glob patterns excluded unless tests are explicitly included.
pub const DEFAULT_TEST_EXCLUDES: &[&str] =
    &["**/tests/**", "**/benches/**", "**/test_snapshots/**", "**/fuzz_targets/**"];

/// Directory names that are never descended into.
const SKIPPED_DIRS: &[&str] = &["target", "node_modules", ".git"];

#[derive(Debug, Clone, Default)]
pub struct DiscoverOptions {
    /// Extra glob patterns (matched against the path relative to the scan root).
    pub exclude: Vec<String>,
    /// When `true`, test files and `#[cfg(test)]` code are analyzed too.
    pub include_tests: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum DiscoverError {
    #[error("path does not exist: {0}")]
    NotFound(PathBuf),
    #[error("invalid exclude pattern `{pattern}`: {source}")]
    BadGlob {
        pattern: String,
        #[source]
        source: globset::Error,
    },
    #[error("failed to read directory {path}: {source}")]
    Walk {
        path: PathBuf,
        #[source]
        source: walkdir::Error,
    },
}

fn build_globset(opts: &DiscoverOptions) -> Result<GlobSet, DiscoverError> {
    let mut builder = GlobSetBuilder::new();
    let defaults: &[&str] = if opts.include_tests { &[] } else { DEFAULT_TEST_EXCLUDES };
    for pattern in defaults.iter().copied().chain(opts.exclude.iter().map(String::as_str)) {
        let glob =
            Glob::new(pattern).map_err(|source| DiscoverError::BadGlob { pattern: pattern.to_string(), source })?;
        builder.add(glob);
        // `dir/**` should also match the directory itself relative paths like `dir`.
        if let Some(stripped) = pattern.strip_prefix("**/") {
            if let Ok(g) = Glob::new(stripped) {
                builder.add(g);
            }
        }
    }
    builder.build().map_err(|source| DiscoverError::BadGlob { pattern: "<combined>".into(), source })
}

/// Returns every `.rs` file below `root` (or `root` itself if it is a file),
/// sorted for deterministic output.
pub fn discover(root: &Path, opts: &DiscoverOptions) -> Result<Vec<PathBuf>, DiscoverError> {
    if !root.exists() {
        return Err(DiscoverError::NotFound(root.to_path_buf()));
    }
    if root.is_file() {
        return Ok(vec![root.to_path_buf()]);
    }
    let globs = build_globset(opts)?;
    let mut out = Vec::new();
    let walker = walkdir::WalkDir::new(root).follow_links(false).into_iter().filter_entry(|e| {
        if e.depth() == 0 || !e.file_type().is_dir() {
            return true;
        }
        let name = e.file_name().to_string_lossy();
        !(name.starts_with('.') || SKIPPED_DIRS.contains(&name.as_ref()))
    });
    for entry in walker {
        let entry = entry.map_err(|source| DiscoverError::Walk { path: root.to_path_buf(), source })?;
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let rel = path.strip_prefix(root).unwrap_or(path);
        if globs.is_match(rel) {
            continue;
        }
        out.push(path.to_path_buf());
    }
    out.sort();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn finds_rs_files_and_skips_target_and_tests() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for p in ["src/lib.rs", "src/a/b.rs", "target/x.rs", "tests/it.rs", ".hidden/x.rs", "README.md"] {
            let full = root.join(p);
            fs::create_dir_all(full.parent().unwrap()).unwrap();
            fs::write(full, "").unwrap();
        }
        let files = discover(root, &DiscoverOptions::default()).unwrap();
        let rel: Vec<_> =
            files.iter().map(|p| p.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/")).collect();
        assert_eq!(rel, vec!["src/a/b.rs", "src/lib.rs"]);

        let with_tests = discover(root, &DiscoverOptions { include_tests: true, ..Default::default() }).unwrap();
        assert_eq!(with_tests.len(), 3);
    }

    #[test]
    fn custom_excludes() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for p in ["src/lib.rs", "src/generated/x.rs"] {
            let full = root.join(p);
            fs::create_dir_all(full.parent().unwrap()).unwrap();
            fs::write(full, "").unwrap();
        }
        let files = discover(root, &DiscoverOptions { exclude: vec!["src/generated/**".into()], include_tests: false })
            .unwrap();
        assert_eq!(files.len(), 1);
    }

    #[test]
    fn missing_root_is_error() {
        assert!(matches!(
            discover(Path::new("/definitely/not/here"), &DiscoverOptions::default()),
            Err(DiscoverError::NotFound(_))
        ));
    }
}
