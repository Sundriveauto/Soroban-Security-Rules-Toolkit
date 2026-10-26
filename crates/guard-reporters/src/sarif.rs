//! SARIF 2.1.0 output, compatible with GitHub code scanning.

use guard_engine::{Confidence, ScanReport, Severity, DISCLAIMER};
use serde_json::{json, Value};

const SARIF_SCHEMA: &str = "https://json.schemastore.org/sarif-2.1.0.json";
const INFORMATION_URI: &str = "https://github.com/petermuazu/Soroban-Security-Rules-Toolkit";

fn level(sev: Severity) -> &'static str {
    match sev {
        Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Info => "note",
    }
}

/// GitHub's `security-severity` (CVSS-like 0–10) used to rank alerts.
fn security_severity(sev: Severity) -> &'static str {
    match sev {
        Severity::Error => "8.0",
        Severity::Warning => "5.5",
        Severity::Info => "2.0",
    }
}

fn precision(c: Confidence) -> &'static str {
    match c {
        Confidence::High => "high",
        Confidence::Medium => "medium",
        Confidence::Low => "low",
    }
}

/// Percent-encodes a relative path for use as a SARIF artifact URI.
fn encode_uri(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for b in path.bytes() {
        let keep = b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~' | b'/');
        if keep {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub fn render(report: &ScanReport) -> String {
    let rules: Vec<Value> = report
        .rules
        .iter()
        .map(|r| {
            json!({
                "id": r.id,
                "name": r.name,
                "shortDescription": { "text": r.summary },
                "fullDescription": { "text": r.description },
                "help": {
                    "text": r.remediation,
                    "markdown": format!("{}\n\n[Rule documentation]({})", r.remediation, r.help_uri),
                },
                "helpUri": r.help_uri,
                "defaultConfiguration": { "level": level(r.severity) },
                "properties": {
                    "tags": r.tags,
                    "security-severity": security_severity(r.severity),
                },
            })
        })
        .collect();

    let results: Vec<Value> = report
        .findings
        .iter()
        .map(|f| {
            let rule_index = report.rules.iter().position(|r| r.id == f.rule_id);
            let l = &f.location;
            let mut region = json!({
                "startLine": l.start_line,
                "startColumn": l.start_column,
                "endLine": l.end_line,
                "endColumn": l.end_column,
            });
            if !f.snippet.is_empty() {
                region["snippet"] = json!({ "text": f.snippet });
            }
            let mut result = json!({
                "ruleId": f.rule_id,
                "level": level(f.severity),
                "message": { "text": format!("{}. {}", f.message, f.help) },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": { "uri": encode_uri(&l.file), "uriBaseId": "%SRCROOT%" },
                        "region": region,
                    }
                }],
                "partialFingerprints": { "stellarGuardFingerprint/v1": f.fingerprint },
                "properties": {
                    "confidence": precision(f.confidence),
                    "security-severity": security_severity(f.severity),
                },
            });
            if let Some(i) = rule_index {
                result["ruleIndex"] = json!(i);
            }
            if let Some(func) = &f.function {
                result["locations"][0]["logicalLocations"] = json!([{ "name": func, "kind": "function" }]);
            }
            result
        })
        .collect();

    let notifications: Vec<Value> = report
        .parse_failures
        .iter()
        .map(|p| {
            let mut loc = json!({
                "physicalLocation": {
                    "artifactLocation": { "uri": encode_uri(&p.file), "uriBaseId": "%SRCROOT%" }
                }
            });
            if let Some(line) = p.line {
                loc["physicalLocation"]["region"] = json!({ "startLine": line });
            }
            json!({
                "level": "warning",
                "message": { "text": format!("Could not parse file: {}", p.message) },
                "locations": [loc],
            })
        })
        .collect();

    let doc = json!({
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": report.tool.name,
                    "version": report.tool.version,
                    "semanticVersion": report.tool.version,
                    "informationUri": INFORMATION_URI,
                    "rules": rules,
                }
            },
            "columnKind": "unicodeCodePoints",
            "invocations": [{
                "executionSuccessful": true,
                "toolExecutionNotifications": notifications,
            }],
            "results": results,
            "properties": { "disclaimer": DISCLAIMER },
        }]
    });
    serde_json::to_string_pretty(&doc).expect("sarif serializes")
}

#[cfg(test)]
mod tests {
    use crate::fixtures;
    use serde_json::Value;

    #[test]
    fn valid_sarif_shape() {
        let s = super::render(&fixtures::report());
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["version"], "2.1.0");
        let run = &v["runs"][0];
        assert_eq!(run["tool"]["driver"]["name"], "stellar-guard");
        assert_eq!(run["tool"]["driver"]["rules"][0]["id"], "SG-001");
        assert_eq!(run["tool"]["driver"]["rules"][0]["defaultConfiguration"]["level"], "warning");
        let res = &run["results"][0];
        assert_eq!(res["ruleId"], "SG-001");
        assert_eq!(res["ruleIndex"], 0);
        assert_eq!(res["level"], "warning");
        let loc = &res["locations"][0]["physicalLocation"];
        assert_eq!(loc["artifactLocation"]["uri"], "src/my%20lib.rs");
        assert_eq!(loc["region"]["startLine"], 42);
        assert_eq!(loc["region"]["startColumn"], 16);
        assert_eq!(res["partialFingerprints"]["stellarGuardFingerprint/v1"], "0123456789abcdef");
        assert_eq!(
            run["invocations"][0]["toolExecutionNotifications"][0]["locations"][0]["physicalLocation"]["region"]
                ["startLine"],
            3
        );
    }

    #[test]
    fn empty_report_has_empty_results() {
        let v: Value = serde_json::from_str(&super::render(&fixtures::empty())).unwrap();
        assert_eq!(v["runs"][0]["results"].as_array().unwrap().len(), 0);
    }
}
