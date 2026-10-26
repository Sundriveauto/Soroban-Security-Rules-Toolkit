//! Report renderers.

use std::fmt;
use std::str::FromStr;

use guard_engine::ScanReport;

mod github;
mod json;
mod markdown;
mod sarif;
mod text;

pub use json::JSON_SCHEMA_VERSION;

/// Output format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Human-readable, compiler-style diagnostics.
    Text,
    /// Machine-readable JSON (see `docs/report-format.md`).
    Json,
    /// SARIF 2.1.0 for GitHub code scanning and other SARIF consumers.
    Sarif,
    /// GitHub Actions workflow commands (inline PR annotations).
    Github,
    /// Markdown summary (e.g. for `$GITHUB_STEP_SUMMARY` or PR comments).
    Markdown,
}

impl Format {
    pub const ALL: &'static [&'static str] = &["text", "json", "sarif", "github", "markdown"];
}

impl FromStr for Format {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "text" | "human" => Ok(Format::Text),
            "json" => Ok(Format::Json),
            "sarif" => Ok(Format::Sarif),
            "github" | "gha" => Ok(Format::Github),
            "markdown" | "md" => Ok(Format::Markdown),
            other => Err(format!("unknown format `{other}` (expected one of: {})", Format::ALL.join(", "))),
        }
    }
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Format::Text => "text",
            Format::Json => "json",
            Format::Sarif => "sarif",
            Format::Github => "github",
            Format::Markdown => "markdown",
        })
    }
}

/// Rendering options.
#[derive(Debug, Clone, Default)]
pub struct RenderOptions {
    /// Use ANSI colors (text format only).
    pub color: bool,
}

/// Renders `report` in `format`. Output always ends with a newline.
pub fn render(report: &ScanReport, format: Format, opts: &RenderOptions) -> String {
    let mut s = match format {
        Format::Text => text::render(report, opts.color),
        Format::Json => json::render(report),
        Format::Sarif => sarif::render(report),
        Format::Github => github::render(report),
        Format::Markdown => markdown::render(report),
    };
    if !s.ends_with('\n') {
        s.push('\n');
    }
    s
}

#[cfg(test)]
pub(crate) mod fixtures {
    use guard_engine::*;

    pub fn report() -> ScanReport {
        let rule = RuleInfo {
            id: "SG-001".into(),
            name: "missing-authorization".into(),
            summary: "Potential missing authorization check".into(),
            description: "desc".into(),
            remediation: "Review whether this operation requires `address.require_auth()`.".into(),
            severity: Severity::Warning,
            tags: vec!["security".into()],
            help_uri: "https://example.com/SG-001.md".into(),
        };
        let finding = Finding {
            rule_id: "SG-001".into(),
            rule_name: "missing-authorization".into(),
            severity: Severity::Warning,
            confidence: Confidence::High,
            message: "Exported function `withdraw` transfers tokens out of the contract without an authorization check"
                .into(),
            help: rule.remediation.clone(),
            location: Location {
                file: "src/my lib.rs".into(),
                start_line: 42,
                start_column: 16,
                end_line: 42,
                end_column: 24,
            },
            snippet: "        client.transfer(&env.current_contract_address(), &to, &amount);".into(),
            function: Some("withdraw".into()),
            fingerprint: "0123456789abcdef".into(),
            help_uri: rule.help_uri.clone(),
        };
        ScanReport {
            tool: ToolInfo { name: "stellar-guard".into(), version: "0.1.0".into() },
            summary: Summary { files_scanned: 3, warnings: 1, suppressed: 2, ..Default::default() },
            findings: vec![finding],
            parse_failures: vec![guard_parser::ParseFailure {
                file: "src/broken.rs".into(),
                line: Some(3),
                column: Some(1),
                message: "expected `;`".into(),
            }],
            rules: vec![rule],
        }
    }

    pub fn empty() -> ScanReport {
        let mut r = report();
        r.findings.clear();
        r.parse_failures.clear();
        r.summary = Summary { files_scanned: 3, ..Default::default() };
        r
    }
}
