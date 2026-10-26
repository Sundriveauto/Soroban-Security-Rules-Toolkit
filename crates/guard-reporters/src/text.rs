use std::fmt::Write;

use guard_engine::{Finding, ScanReport, Severity, DISCLAIMER};

struct Style {
    on: bool,
}

impl Style {
    fn paint(&self, code: &str, s: &str) -> String {
        if self.on {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
    fn severity(&self, sev: Severity) -> String {
        let code = match sev {
            Severity::Error => "1;31",
            Severity::Warning => "1;33",
            Severity::Info => "1;36",
        };
        self.paint(code, sev.as_str())
    }
    fn bold(&self, s: &str) -> String {
        self.paint("1", s)
    }
    fn dim(&self, s: &str) -> String {
        self.paint("2", s)
    }
    fn blue(&self, s: &str) -> String {
        self.paint("1;34", s)
    }
}

fn write_finding(out: &mut String, f: &Finding, st: &Style) {
    let loc = &f.location;
    let gutter = loc.start_line.to_string().len();
    let pad = " ".repeat(gutter);
    let _ =
        writeln!(out, "{}{}: {}", st.severity(f.severity), st.bold(&format!("[{}]", f.rule_id)), st.bold(&f.message));
    let _ = writeln!(out, "{pad}{} {}:{}:{}", st.blue("-->"), loc.file, loc.start_line, loc.start_column);
    if !f.snippet.is_empty() {
        let _ = writeln!(out, "{pad} {}", st.blue("|"));
        let _ = writeln!(out, "{} {} {}", st.blue(&loc.start_line.to_string()), st.blue("|"), f.snippet);
        let start = loc.start_column.saturating_sub(1);
        let width = if loc.end_line == loc.start_line && loc.end_column > loc.start_column {
            loc.end_column - loc.start_column
        } else {
            1
        };
        // Preserve tabs so the caret lines up with the snippet.
        let lead: String = f.snippet.chars().take(start).map(|c| if c == '\t' { '\t' } else { ' ' }).collect();
        let caret = "^".repeat(width.min(120));
        let _ = writeln!(out, "{pad} {} {lead}{}", st.blue("|"), st.severity_caret(f.severity, &caret));
    }
    let _ = writeln!(out, "{pad} {}", st.blue("|"));
    let mut meta = format!("{} ({}), confidence: {}", f.rule_name, f.rule_id, f.confidence);
    if let Some(func) = &f.function {
        let _ = write!(meta, ", function: `{func}`");
    }
    let _ = writeln!(out, "{pad} {} {}", st.blue("="), st.dim(&meta));
    let _ = writeln!(out, "{pad} {} {} {}", st.blue("="), st.bold("help:"), f.help);
    let _ = writeln!(out, "{pad} {} {} {}", st.blue("="), st.bold("docs:"), f.help_uri);
    out.push('\n');
}

impl Style {
    fn severity_caret(&self, sev: Severity, caret: &str) -> String {
        let code = match sev {
            Severity::Error => "1;31",
            Severity::Warning => "1;33",
            Severity::Info => "1;36",
        };
        self.paint(code, caret)
    }
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{n} {}", if n == 1 { one } else { many })
}

pub fn render(report: &ScanReport, color: bool) -> String {
    let st = Style { on: color };
    let mut out = String::new();
    for f in &report.findings {
        write_finding(&mut out, f, &st);
    }
    for p in &report.parse_failures {
        let loc = match (p.line, p.column) {
            (Some(l), Some(c)) => format!("{}:{l}:{c}", p.file),
            _ => p.file.clone(),
        };
        let _ = writeln!(out, "{}: could not analyze {loc}: {}", st.severity(Severity::Warning), p.message);
    }
    if !report.parse_failures.is_empty() {
        out.push('\n');
    }
    let s = &report.summary;
    let counts = format!(
        "{}, {}, {}",
        plural(s.errors, "error", "errors"),
        plural(s.warnings, "warning", "warnings"),
        plural(s.infos, "info", "infos"),
    );
    let mut line = format!(
        "{} scanned {} with {} rules: {}",
        report.tool.name,
        plural(s.files_scanned, "file", "files"),
        report.rules.len(),
        counts
    );
    if s.suppressed > 0 {
        let _ = write!(line, " ({} suppressed)", s.suppressed);
    }
    if s.parse_failures > 0 {
        let _ = write!(line, ", {} could not be parsed", plural(s.parse_failures, "file", "files"));
    }
    let _ = writeln!(out, "{}", st.bold(&line));
    let _ = writeln!(out, "{}", st.dim(&format!("note: {DISCLAIMER}")));
    out
}

#[cfg(test)]
mod tests {
    use crate::fixtures;

    #[test]
    fn renders_compiler_style() {
        let s = super::render(&fixtures::report(), false);
        assert!(s.contains("warning[SG-001]: Exported function `withdraw`"));
        assert!(s.contains("  --> src/my lib.rs:42:16"));
        assert!(s.contains("42 |         client.transfer("));
        assert!(s.contains("   |                ^^^^^^^^\n"), "{s}");
        assert!(s.contains("help: Review whether this operation requires `address.require_auth()`."));
        assert!(s.contains("1 warning"));
        assert!(s.contains("(2 suppressed)"));
        assert!(s.contains("could not analyze src/broken.rs:3:1"));
        assert!(s.contains("does not prove a contract is secure"));
        assert!(!s.contains('\x1b'));
    }

    #[test]
    fn color_is_optional() {
        assert!(super::render(&fixtures::report(), true).contains("\x1b[1;33m"));
    }

    #[test]
    fn clean_summary() {
        let s = super::render(&fixtures::empty(), false);
        assert!(s.contains("scanned 3 files with 1 rules: 0 errors, 0 warnings, 0 infos"));
    }
}
