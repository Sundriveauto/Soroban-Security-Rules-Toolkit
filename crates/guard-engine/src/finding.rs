//! Findings and report types.

use std::fmt;
use std::str::FromStr;

use guard_parser::ParseFailure;
use serde::{Deserialize, Serialize};

/// How serious a finding is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Warning,
    Error,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Error => "error",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Severity {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "info" | "note" => Ok(Severity::Info),
            "warning" | "warn" => Ok(Severity::Warning),
            "error" => Ok(Severity::Error),
            other => Err(format!("unknown severity `{other}` (expected info, warning or error)")),
        }
    }
}

/// How likely a finding is to be a true positive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    pub fn as_str(self) -> &'static str {
        match self {
            Confidence::Low => "low",
            Confidence::Medium => "medium",
            Confidence::High => "high",
        }
    }
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for Confidence {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "low" => Ok(Confidence::Low),
            "medium" => Ok(Confidence::Medium),
            "high" => Ok(Confidence::High),
            other => Err(format!("unknown confidence `{other}` (expected low, medium or high)")),
        }
    }
}

/// The minimum severity that makes a scan fail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum FailOn {
    Info,
    #[default]
    Warning,
    Error,
    Never,
}

impl FailOn {
    /// `true` if a finding of `severity` should fail the run.
    pub fn fails(self, severity: Severity) -> bool {
        match self {
            FailOn::Never => false,
            FailOn::Info => true,
            FailOn::Warning => severity >= Severity::Warning,
            FailOn::Error => severity >= Severity::Error,
        }
    }
}

impl FromStr for FailOn {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "info" => Ok(FailOn::Info),
            "warning" | "warn" => Ok(FailOn::Warning),
            "error" => Ok(FailOn::Error),
            "never" | "none" | "off" => Ok(FailOn::Never),
            other => Err(format!("unknown fail-on level `{other}` (expected info, warning, error or never)")),
        }
    }
}

/// Where a finding is.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Location {
    pub file: String,
    pub start_line: usize,
    pub start_column: usize,
    pub end_line: usize,
    pub end_column: usize,
}

/// One reported issue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub rule_id: String,
    pub rule_name: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub message: String,
    pub help: String,
    pub location: Location,
    /// The source line the finding starts on (trailing whitespace removed).
    pub snippet: String,
    /// The enclosing function, when known.
    pub function: Option<String>,
    /// Stable identifier for tracking a finding across runs.
    pub fingerprint: String,
    pub help_uri: String,
}

/// Rule metadata as included in reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleInfo {
    pub id: String,
    pub name: String,
    pub summary: String,
    pub description: String,
    pub remediation: String,
    pub severity: Severity,
    pub tags: Vec<String>,
    pub help_uri: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolInfo {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Summary {
    pub files_scanned: usize,
    pub errors: usize,
    pub warnings: usize,
    pub infos: usize,
    pub suppressed: usize,
    pub parse_failures: usize,
}

/// The full result of a scan. Contains no timestamps or durations so that
/// identical inputs produce byte-identical reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanReport {
    pub tool: ToolInfo,
    pub summary: Summary,
    pub findings: Vec<Finding>,
    pub parse_failures: Vec<ParseFailure>,
    pub rules: Vec<RuleInfo>,
}

impl ScanReport {
    /// `true` if any finding meets the `fail_on` threshold.
    pub fn fails(&self, fail_on: FailOn) -> bool {
        self.findings.iter().any(|f| fail_on.fails(f.severity))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fail_on_thresholds() {
        assert!(FailOn::Warning.fails(Severity::Error));
        assert!(FailOn::Warning.fails(Severity::Warning));
        assert!(!FailOn::Warning.fails(Severity::Info));
        assert!(!FailOn::Error.fails(Severity::Warning));
        assert!(FailOn::Info.fails(Severity::Info));
        assert!(!FailOn::Never.fails(Severity::Error));
    }

    #[test]
    fn parse_levels() {
        assert_eq!("WARN".parse::<Severity>().unwrap(), Severity::Warning);
        assert_eq!("none".parse::<FailOn>().unwrap(), FailOn::Never);
        assert!("bogus".parse::<Confidence>().is_err());
        assert!(Confidence::High > Confidence::Low);
    }
}
