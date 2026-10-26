//! GitHub Actions workflow commands: `::warning file=..,line=..::message`.

use std::fmt::Write;

use guard_engine::{ScanReport, Severity};

fn escape_data(s: &str) -> String {
    s.replace('%', "%25").replace('\r', "%0D").replace('\n', "%0A")
}

fn escape_prop(s: &str) -> String {
    escape_data(s).replace(':', "%3A").replace(',', "%2C")
}

pub fn render(report: &ScanReport) -> String {
    let mut out = String::new();
    for f in &report.findings {
        let level = match f.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Info => "notice",
        };
        let l = &f.location;
        let _ = writeln!(
            out,
            "::{level} file={},line={},col={},endLine={},endColumn={},title={}::{}",
            escape_prop(&l.file),
            l.start_line,
            l.start_column,
            l.end_line,
            l.end_column,
            escape_prop(&format!("{} {}", f.rule_id, f.rule_name)),
            escape_data(&format!("{}\n{}\n{}", f.message, f.help, f.help_uri)),
        );
    }
    for p in &report.parse_failures {
        let _ = writeln!(
            out,
            "::warning file={},line={},title=stellar-guard parse failure::{}",
            escape_prop(&p.file),
            p.line.unwrap_or(1),
            escape_data(&p.message)
        );
    }
    out
}

#[cfg(test)]
mod tests {
    use crate::fixtures;

    #[test]
    fn workflow_commands() {
        let s = super::render(&fixtures::report());
        let first = s.lines().next().unwrap();
        assert!(first.starts_with(
            "::warning file=src/my lib.rs,line=42,col=16,endLine=42,endColumn=24,title=SG-001 missing-authorization::"
        ));
        assert!(first.contains("%0AReview whether"));
        assert!(s.contains("::warning file=src/broken.rs,line=3,title=stellar-guard parse failure::expected `;`"));
        assert_eq!(super::escape_prop("a:b,c%"), "a%3Ab%2Cc%25");
    }
}
