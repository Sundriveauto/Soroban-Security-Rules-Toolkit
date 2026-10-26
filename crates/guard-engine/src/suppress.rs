//! Inline suppression comments.
//!
//! ```text
//! // stellar-guard-ignore SG-001 -- admin is checked by the caller
//! env.storage().instance().set(&DataKey::Admin, &new_admin);
//!
//! let total = a + b; // stellar-guard-ignore: SG-003
//!
//! // stellar-guard-ignore-file SG-004
//! ```
//!
//! A directive with no rule IDs suppresses every rule. A directive on its own
//! line applies to the next statement (attributes and comments in between are
//! skipped; a statement ends at a line ending in `;`, `{` or `}`).

use std::collections::HashMap;

const LINE_DIRECTIVE: &str = "stellar-guard-ignore";
const FILE_DIRECTIVE: &str = "stellar-guard-ignore-file";

/// `None` means "all rules".
type RuleSet = Option<Vec<String>>;

#[derive(Debug, Default, Clone)]
pub struct Suppressions {
    file: Vec<RuleSet>,
    lines: HashMap<usize, Vec<RuleSet>>,
}

fn parse_ids(rest: &str) -> RuleSet {
    let rest = rest.split("--").next().unwrap_or("");
    let rest = rest.trim_start_matches(':');
    let ids: Vec<String> = rest
        .split(|c: char| c == ',' || c.is_whitespace())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_uppercase())
        .collect();
    if ids.is_empty() {
        None
    } else {
        Some(ids)
    }
}

fn comment_part(line: &str) -> Option<(usize, &str)> {
    line.find("//").map(|i| (i, &line[i + 2..]))
}

impl Suppressions {
    pub fn parse(text: &str) -> Self {
        let lines: Vec<&str> = text.lines().collect();
        let mut s = Suppressions::default();
        for (idx, raw) in lines.iter().enumerate() {
            let Some((pos, comment)) = comment_part(raw) else { continue };
            let comment = comment.trim_start_matches(['/', '!']).trim();
            if let Some(rest) = comment.strip_prefix(FILE_DIRECTIVE) {
                s.file.push(parse_ids(rest));
                continue;
            }
            let Some(rest) = comment.strip_prefix(LINE_DIRECTIVE) else { continue };
            if !(rest.is_empty() || rest.starts_with([' ', ':', '\t'])) {
                continue;
            }
            let ids = parse_ids(rest);
            let line_no = idx + 1;
            if !raw[..pos].trim().is_empty() {
                // Trailing comment: applies to this line.
                s.lines.entry(line_no).or_default().push(ids);
                continue;
            }
            // Own-line comment: find the next statement.
            let mut j = idx + 1;
            while j < lines.len() {
                let t = lines[j].trim();
                if t.starts_with("//") || t.starts_with("#[") || t.starts_with("#![") {
                    j += 1;
                    continue;
                }
                break;
            }
            while j < lines.len() {
                let t = lines[j].trim();
                if t.is_empty() {
                    break;
                }
                s.lines.entry(j + 1).or_default().push(ids.clone());
                let code = comment_part(t).map(|(p, _)| &t[..p]).unwrap_or(t).trim_end();
                if code.ends_with(';') || code.ends_with('{') || code.ends_with('}') {
                    break;
                }
                j += 1;
            }
        }
        s
    }

    fn matches(set: &RuleSet, rule_id: &str) -> bool {
        match set {
            None => true,
            Some(ids) => ids.iter().any(|i| i.eq_ignore_ascii_case(rule_id)),
        }
    }

    /// `true` if `rule_id` is suppressed at 1-based `line`.
    pub fn is_suppressed(&self, rule_id: &str, line: usize) -> bool {
        self.file.iter().any(|s| Self::matches(s, rule_id))
            || self.lines.get(&line).is_some_and(|sets| sets.iter().any(|s| Self::matches(s, rule_id)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trailing_and_preceding_comments() {
        let src = "\
let a = x + y; // stellar-guard-ignore: SG-003
// stellar-guard-ignore SG-001, SG-002 -- reviewed
#[allow(unused)]
env.storage()
    .persistent()
    .set(&k, &v);
next_line();
";
        let s = Suppressions::parse(src);
        assert!(s.is_suppressed("SG-003", 1));
        assert!(!s.is_suppressed("SG-001", 1));
        assert!(s.is_suppressed("SG-001", 4));
        assert!(s.is_suppressed("sg-002", 6));
        assert!(!s.is_suppressed("SG-001", 7));
    }

    #[test]
    fn all_rules_and_file_level() {
        let s = Suppressions::parse("// stellar-guard-ignore\nfoo();\nbar();\n");
        assert!(s.is_suppressed("SG-999", 2));
        assert!(!s.is_suppressed("SG-999", 3));
        let s = Suppressions::parse("//! stellar-guard-ignore-file SG-004\nfn x() {}\n");
        assert!(s.is_suppressed("SG-004", 100));
        assert!(!s.is_suppressed("SG-001", 100));
    }

    #[test]
    fn ignores_similar_words() {
        let s = Suppressions::parse("// stellar-guard-ignored SG-001\nfoo();\n");
        assert!(!s.is_suppressed("SG-001", 2));
    }
}
