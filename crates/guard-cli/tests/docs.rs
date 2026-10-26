//! Every rule must be documented, and the docs must agree with the rule metadata.

use std::fs;
use std::path::Path;

#[test]
fn every_rule_has_a_docs_page() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let index = fs::read_to_string(root.join("docs/rules/README.md")).unwrap();
    let readme = fs::read_to_string(root.join("README.md")).unwrap();
    for rule in guard_rules::all() {
        let m = rule.meta();
        let page = root.join("docs/rules").join(format!("{}.md", m.id));
        let text = fs::read_to_string(&page).unwrap_or_else(|_| panic!("missing {}", page.display()));
        assert!(text.starts_with(&format!("# {} — {}", m.id, m.summary)), "{}: title must match summary", m.id);
        assert!(text.contains(&format!("`{}`", m.name)), "{}: page must mention name", m.id);
        assert!(
            text.contains(&format!("**Default severity** | {}", m.default_severity)),
            "{}: default severity mismatch",
            m.id
        );
        for opt in m.options {
            assert!(text.contains(opt.name), "{}: option `{}` undocumented", m.id, opt.name);
        }
        for section in ["## What it detects", "## Why it matters", "## Known limitations", "## Fixtures"] {
            assert!(text.contains(section), "{}: missing section {section}", m.id);
        }
        assert!(index.contains(&format!("[{}]({}.md)", m.id, m.id)), "{} missing from rules index", m.id);
        assert!(readme.contains(&format!("[{}](docs/rules/{}.md)", m.id, m.id)), "{} missing from README", m.id);
    }
}
