use std::fmt::Write;

use guard_engine::{ScanReport, Severity, DISCLAIMER};

fn cell(s: &str) -> String {
    s.replace('|', "\\|").replace('\n', " ")
}

pub fn render(report: &ScanReport) -> String {
    let s = &report.summary;
    let mut out = String::new();
    let _ = writeln!(out, "## stellar-guard results\n");
    let _ = writeln!(
        out,
        "**{}** files scanned · **{}** errors · **{}** warnings · **{}** infos · {} suppressed\n",
        s.files_scanned, s.errors, s.warnings, s.infos, s.suppressed
    );
    if report.findings.is_empty() {
        let _ = writeln!(out, "No findings.\n");
    } else {
        let _ = writeln!(out, "| Severity | Rule | Location | Message | Confidence |");
        let _ = writeln!(out, "|---|---|---|---|---|");
        for f in &report.findings {
            let icon = match f.severity {
                Severity::Error => "🔴 error",
                Severity::Warning => "🟠 warning",
                Severity::Info => "🔵 info",
            };
            let _ = writeln!(
                out,
                "| {icon} | [{}]({}) | `{}:{}` | {} | {} |",
                f.rule_id,
                f.help_uri,
                cell(&f.location.file),
                f.location.start_line,
                cell(&f.message),
                f.confidence
            );
        }
        out.push('\n');
    }
    if !report.parse_failures.is_empty() {
        let _ = writeln!(out, "**Files that could not be parsed:**\n");
        for p in &report.parse_failures {
            let _ = writeln!(out, "- `{}`: {}", p.file, cell(&p.message));
        }
        out.push('\n');
    }
    let _ = writeln!(out, "> {DISCLAIMER}");
    out
}

#[cfg(test)]
mod tests {
    use crate::fixtures;

    #[test]
    fn markdown_table() {
        let s = super::render(&fixtures::report());
        assert!(s.contains("| 🟠 warning | [SG-001](https://example.com/SG-001.md) | `src/my lib.rs:42` |"));
        assert!(super::render(&fixtures::empty()).contains("No findings."));
    }
}
