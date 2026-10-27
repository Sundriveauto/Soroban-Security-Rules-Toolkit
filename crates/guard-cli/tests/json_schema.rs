//! The JSON report matches `docs/report.schema.json`.
//!
//! A small validator for the subset of JSON Schema the file uses (`type`,
//! `required`, `properties`, `items`, `enum`, `const`, `minimum`, `pattern`,
//! local `$ref`), so the schema cannot drift from the output.

use std::fs;
use std::path::{Path, PathBuf};

use guard_engine::{Engine, Settings};
use guard_reporters::{render, Format, RenderOptions};
use serde_json::Value;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn schema() -> Value {
    serde_json::from_str(&fs::read_to_string(root().join("docs/report.schema.json")).unwrap()).unwrap()
}

fn type_matches(ty: &str, v: &Value) -> bool {
    match ty {
        "object" => v.is_object(),
        "array" => v.is_array(),
        "string" => v.is_string(),
        "integer" => v.is_u64() || v.is_i64(),
        "number" => v.is_number(),
        "boolean" => v.is_boolean(),
        "null" => v.is_null(),
        other => panic!("unsupported type {other}"),
    }
}

fn validate(root: &Value, schema: &Value, v: &Value, path: &str, errors: &mut Vec<String>) {
    let s = schema.as_object().expect("schema object");
    if let Some(r) = s.get("$ref").and_then(Value::as_str) {
        let target = r.strip_prefix("#/").expect("local $ref").split('/').fold(root, |node, seg| &node[seg]);
        validate(root, target, v, path, errors);
    }
    if let Some(ty) = s.get("type") {
        let ok = match ty {
            Value::String(t) => type_matches(t, v),
            Value::Array(ts) => ts.iter().any(|t| type_matches(t.as_str().unwrap(), v)),
            _ => panic!("bad type"),
        };
        if !ok {
            errors.push(format!("{path}: expected type {ty}, got {v}"));
            return;
        }
    }
    if let Some(c) = s.get("const") {
        if c != v {
            errors.push(format!("{path}: expected {c}, got {v}"));
        }
    }
    if let Some(Value::Array(options)) = s.get("enum") {
        if !options.contains(v) {
            errors.push(format!("{path}: {v} not in {options:?}"));
        }
    }
    if let (Some(min), Some(n)) = (s.get("minimum").and_then(Value::as_f64), v.as_f64()) {
        if n < min {
            errors.push(format!("{path}: {n} < {min}"));
        }
    }
    if let (Some(p), Some(text)) = (s.get("pattern").and_then(Value::as_str), v.as_str()) {
        if !regex::Regex::new(p).unwrap().is_match(text) {
            errors.push(format!("{path}: {text:?} does not match {p}"));
        }
    }
    if let Some(obj) = v.as_object() {
        for req in s.get("required").and_then(Value::as_array).into_iter().flatten() {
            if !obj.contains_key(req.as_str().unwrap()) {
                errors.push(format!("{path}: missing {req}"));
            }
        }
        if let Some(Value::Object(props)) = s.get("properties") {
            for (k, sub) in props {
                if let Some(child) = obj.get(k) {
                    validate(root, sub, child, &format!("{path}.{k}"), errors);
                }
            }
        }
    }
    if let (Some(items), Some(arr)) = (s.get("items"), v.as_array()) {
        for (i, item) in arr.iter().enumerate() {
            validate(root, items, item, &format!("{path}[{i}]"), errors);
        }
    }
}

fn assert_valid(doc: &Value) {
    let schema = schema();
    let mut errors = Vec::new();
    validate(&schema, &schema, doc, "$", &mut errors);
    assert!(errors.is_empty(), "report does not match docs/report.schema.json:\n{}", errors.join("\n"));
}

fn json_report(paths: &[PathBuf]) -> Value {
    let report = Engine::new(guard_rules::all()).scan(paths, &Settings::default()).expect("scan succeeds");
    serde_json::from_str(&render(&report, Format::Json, &RenderOptions { color: false })).unwrap()
}

#[test]
fn every_fixture_report_matches_the_schema() {
    let doc = json_report(&[root().join("fixtures")]);
    assert!(doc["findings"].as_array().unwrap().len() > 10);
    assert_valid(&doc);
}

#[test]
fn parse_failures_match_the_schema() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("ok.rs"), "fn a() {}\n").unwrap();
    fs::write(dir.path().join("broken.rs"), "fn b( {\n").unwrap();
    let doc = json_report(&[dir.path().to_path_buf()]);
    assert_eq!(doc["parse_failures"].as_array().unwrap().len(), 1);
    assert_valid(&doc);
}

#[test]
fn validator_rejects_bad_reports() {
    let mut doc = json_report(&[root().join("fixtures/vulnerable-examples/missing-auth")]);
    doc["findings"][0]["severity"] = "critical".into();
    doc["findings"][0]["fingerprint"] = "xyz".into();
    doc["summary"].as_object_mut().unwrap().remove("errors");
    let schema = schema();
    let mut errors = Vec::new();
    validate(&schema, &schema, &doc, "$", &mut errors);
    assert_eq!(errors.len(), 3, "{errors:#?}");
}
