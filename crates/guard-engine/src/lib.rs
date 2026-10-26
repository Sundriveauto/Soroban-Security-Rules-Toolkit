//! The stellar-guard analysis engine.
//!
//! The engine loads a [`Project`](guard_parser::Project), builds the semantic
//! model, runs each enabled [`Rule`] over every file, then applies severity
//! configuration, confidence filtering and inline suppressions to produce a
//! deterministic [`ScanReport`].

pub mod config;
pub mod engine;
pub mod finding;
pub mod fingerprint;
pub mod rule;
pub mod suppress;

pub use config::{Config, ConfigError, RuleConfig, Settings, CONFIG_FILE_NAMES, DEFAULT_CONFIG_TOML};
pub use engine::{Engine, EngineError};
pub use finding::{Confidence, FailOn, Finding, Location, RuleInfo, ScanReport, Severity, Summary, ToolInfo};
pub use rule::{Diagnostic, Rule, RuleContext, RuleMeta, RuleOption, RuleOptions};

/// Base URL of the rule documentation.
pub const DOCS_BASE_URL: &str = "https://github.com/petermuazu/Soroban-Security-Rules-Toolkit/blob/main/docs/rules";

/// Statement printed with every report: a clean scan proves nothing.
pub const DISCLAIMER: &str = "stellar-guard reports potential issues found by source-level heuristics. \
Findings are not proof of a vulnerability, and a clean scan does not prove a contract is secure.";
