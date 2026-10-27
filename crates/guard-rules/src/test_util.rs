//! Test harness: run one rule over inline source.

use guard_engine::{Engine, Finding, Rule, Settings};
use guard_parser::CrateInfo;

pub fn soroban_crate(overflow_checks: Option<bool>) -> CrateInfo {
    CrateInfo {
        root: None,
        name: Some("test".into()),
        depends_on_soroban: true,
        overflow_checks,
        local_deps: vec![],
        test_support: false,
    }
}

pub fn run_with(rule: Box<dyn Rule>, src: &str, info: CrateInfo, settings: &Settings) -> Vec<Finding> {
    Engine::new(vec![rule]).scan_sources([("src/lib.rs", src)], info, settings).expect("scan").findings
}

pub fn run(rule: Box<dyn Rule>, src: &str) -> Vec<Finding> {
    run_with(rule, src, soroban_crate(Some(false)), &Settings::default())
}

/// `(line, function)` of each finding, for compact assertions.
pub fn lines(findings: &[Finding]) -> Vec<usize> {
    findings.iter().map(|f| f.location.start_line).collect()
}
