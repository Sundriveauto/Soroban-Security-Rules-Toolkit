//! The [`Rule`] trait implemented by every detector.

use guard_parser::{CrateInfo, CrateModel, Project, SourceFile, Span};

use crate::finding::{Confidence, RuleInfo, Severity};
use crate::DOCS_BASE_URL;

/// A configurable option a rule accepts under `[rules.<ID>.options]`.
#[derive(Debug, Clone, Copy)]
pub struct RuleOption {
    pub name: &'static str,
    pub description: &'static str,
    pub default: &'static str,
}

/// Static description of a rule.
#[derive(Debug, Clone, Copy)]
pub struct RuleMeta {
    /// Stable identifier, e.g. `SG-001`.
    pub id: &'static str,
    /// Short kebab-case name, e.g. `missing-authorization`.
    pub name: &'static str,
    /// One-line summary shown as the finding title.
    pub summary: &'static str,
    /// What the rule looks for and why it matters.
    pub description: &'static str,
    /// How to fix or suppress a finding.
    pub remediation: &'static str,
    pub default_severity: Severity,
    pub tags: &'static [&'static str],
    pub options: &'static [RuleOption],
}

impl RuleMeta {
    pub fn help_uri(&self) -> String {
        format!("{DOCS_BASE_URL}/{}.md", self.id)
    }

    pub fn info(&self, severity: Severity) -> RuleInfo {
        RuleInfo {
            id: self.id.to_string(),
            name: self.name.to_string(),
            summary: self.summary.to_string(),
            description: self.description.to_string(),
            remediation: self.remediation.to_string(),
            severity,
            tags: self.tags.iter().map(|t| t.to_string()).collect(),
            help_uri: self.help_uri(),
        }
    }
}

/// A potential issue reported by a rule, before engine post-processing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub span: Span,
    pub message: String,
    pub confidence: Confidence,
    /// Overrides the rule's default severity unless the user configured one.
    pub severity: Option<Severity>,
    pub function: Option<String>,
    /// Finding-specific remediation hint; defaults to the rule's remediation.
    pub help: Option<String>,
}

impl Diagnostic {
    pub fn new(span: Span, message: impl Into<String>, confidence: Confidence) -> Self {
        Self { span, message: message.into(), confidence, severity: None, function: None, help: None }
    }

    pub fn in_function(mut self, name: impl Into<String>) -> Self {
        self.function = Some(name.into());
        self
    }

    pub fn with_severity(mut self, severity: Severity) -> Self {
        self.severity = Some(severity);
        self
    }

    pub fn with_help(mut self, help: impl Into<String>) -> Self {
        self.help = Some(help.into());
        self
    }
}

/// Typed access to a rule's `[rules.<ID>.options]` table.
#[derive(Debug, Clone, Default)]
pub struct RuleOptions {
    table: toml::Table,
}

impl RuleOptions {
    pub fn new(table: toml::Table) -> Self {
        Self { table }
    }

    /// A list of strings (missing → empty).
    pub fn string_list(&self, key: &str) -> Vec<String> {
        self.table
            .get(key)
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
            .unwrap_or_default()
    }

    pub fn bool(&self, key: &str) -> Option<bool> {
        self.table.get(key).and_then(|v| v.as_bool())
    }

    pub fn keys(&self) -> impl Iterator<Item = &str> {
        self.table.keys().map(String::as_str)
    }

    pub fn raw(&self, key: &str) -> Option<&toml::Value> {
        self.table.get(key)
    }
}

/// Everything a rule may inspect while checking one file.
pub struct RuleContext<'a> {
    pub project: &'a Project,
    pub file_idx: usize,
    pub file: &'a SourceFile,
    pub model: &'a CrateModel<'a>,
    pub crate_info: &'a CrateInfo,
    pub options: &'a RuleOptions,
}

impl RuleContext<'_> {
    /// `true` if this file belongs to a Soroban contract crate (or, when no
    /// manifest was found, references `soroban_sdk` itself).
    pub fn is_soroban(&self) -> bool {
        self.crate_info.depends_on_soroban || self.file.mentions_soroban()
    }
}

/// A detector. Implementations must be deterministic: the same input must
/// always yield the same diagnostics in the same order.
pub trait Rule: Send + Sync {
    fn meta(&self) -> &'static RuleMeta;

    /// Inspects `cx.file` and appends any diagnostics to `out`.
    fn check(&self, cx: &RuleContext<'_>, out: &mut Vec<Diagnostic>);

    /// Validates the rule's options. The default accepts only the keys listed in
    /// [`RuleMeta::options`] and requires list-of-strings values.
    fn validate_options(&self, options: &RuleOptions) -> Result<(), String> {
        let meta = self.meta();
        for key in options.keys() {
            if !meta.options.iter().any(|o| o.name == key) {
                let known: Vec<_> = meta.options.iter().map(|o| o.name).collect();
                return Err(format!(
                    "unknown option `{key}` for rule {} (known options: {})",
                    meta.id,
                    if known.is_empty() { "none".to_string() } else { known.join(", ") }
                ));
            }
            let ok = options.raw(key).and_then(|v| v.as_array()).is_some_and(|a| a.iter().all(|v| v.is_str()));
            if !ok {
                return Err(format!("option `{key}` for rule {} must be a list of strings", meta.id));
            }
        }
        Ok(())
    }
}
