use guard_engine::{ScanReport, DISCLAIMER};
use serde::Serialize;

/// Version of the JSON report schema. Bumped on breaking changes.
pub const JSON_SCHEMA_VERSION: &str = "1.0";

#[derive(Serialize)]
struct JsonReport<'a> {
    schema_version: &'static str,
    disclaimer: &'static str,
    #[serde(flatten)]
    report: &'a ScanReport,
}

pub fn render(report: &ScanReport) -> String {
    let doc = JsonReport { schema_version: JSON_SCHEMA_VERSION, disclaimer: DISCLAIMER, report };
    serde_json::to_string_pretty(&doc).expect("report serializes")
}

#[cfg(test)]
mod tests {
    use crate::fixtures;

    #[test]
    fn json_round_trips() {
        let s = super::render(&fixtures::report());
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["schema_version"], "1.0");
        assert_eq!(v["findings"][0]["rule_id"], "SG-001");
        assert_eq!(v["findings"][0]["location"]["start_line"], 42);
        assert_eq!(v["findings"][0]["severity"], "warning");
        assert_eq!(v["summary"]["files_scanned"], 3);
        let back: guard_engine::ScanReport = serde_json::from_value(v).unwrap();
        assert_eq!(back, fixtures::report());
    }
}
