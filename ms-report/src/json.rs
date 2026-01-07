//! JSON reporter — upstream-parity `modelscan` JSON schema.
//!
//! Builds a [`serde_json::Value`] by hand (rather than `#[derive(Serialize)]`
//! on the report types) so the wire shape stays decoupled from the internal
//! structs and matches upstream key names / nesting exactly. Output is
//! deterministic: `by_severity` yields a fixed tier set and issues/files are
//! rendered in their stored order.

use serde_json::{json, Value};

use crate::ScanReport;

/// Render `report` as the upstream-parity JSON document. `pretty` selects
/// `to_string_pretty` vs compact `to_string`.
pub fn render(report: &ScanReport, pretty: bool) -> String {
    let meta = &report.meta;

    // Severity tiers come back from `by_severity` with every tier present, so
    // the summary map always carries LOW/MEDIUM/HIGH/CRITICAL keys.
    let counts = report.by_severity();
    let mut by_severity = serde_json::Map::new();
    for (sev, n) in &counts {
        by_severity.insert(sev.as_str().to_string(), json!(n));
    }

    let scanned_files: Vec<Value> = report
        .scanned_files
        .iter()
        .map(|p| json!(p))
        .collect();

    let skipped_files: Vec<Value> = report
        .skipped_files
        .iter()
        .map(|s| {
            json!({
                "source": s.source,
                "category": s.category,
                "message": s.message,
            })
        })
        .collect();

    let issues: Vec<Value> = report
        .issues
        .iter()
        .map(|i| {
            // Upstream surfaces the logical sub-source when present, otherwise
            // the containing file path.
            let source = i.source.clone().unwrap_or_else(|| i.file_path.clone());
            json!({
                "id": i.id,
                "description": i.message,
                "operator": i.operator,
                "module": i.module,
                "name": i.name,
                "source": source,
                "scanner": i.detector,
                "severity": i.severity.as_str(),
                "offset": i.offset,
            })
        })
        .collect();

    let errors: Vec<Value> = report
        .errors
        .iter()
        .map(|e| {
            json!({
                "source": e.source,
                "category": e.category,
                "message": e.message,
            })
        })
        .collect();

    let doc = json!({
        "summary": {
            "total_issues_by_severity": Value::Object(by_severity),
            "total_issues": report.total_issues(),
            "input_path": meta.input_path,
            "absolute_path": meta.absolute_path,
            "modelscan_version": meta.tool_version,
            "timestamp": meta.timestamp,
            "scanned": {
                "total_scanned": report.scanned_files.len(),
                "scanned_files": scanned_files,
            },
            "skipped": {
                "total_skipped": report.skipped_files.len(),
                "skipped_files": skipped_files,
            },
        },
        "issues": issues,
        "errors": errors,
    });

    if pretty {
        // Infallible for a value we constructed; fall back to compact on the
        // theoretical error rather than panicking in a reporter.
        serde_json::to_string_pretty(&doc).unwrap_or_else(|_| doc.to_string())
    } else {
        doc.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ReportMeta, ScanReport};
    use ms_detectors::{Issue, Severity};

    fn meta() -> ReportMeta {
        ReportMeta {
            tool: "lancer-modelscan".to_string(),
            tool_version: "0.1.0".to_string(),
            schema_version: "1".to_string(),
            timestamp: "2026-05-31T00:00:00.000Z".to_string(),
            input_path: "model.pkl".to_string(),
            absolute_path: "/abs/model.pkl".to_string(),
            elapsed_ms: 7,
            git_commit: None,
        }
    }

    fn critical_issue() -> Issue {
        Issue {
            id: "MS-dead-beef".to_string(),
            severity: Severity::Critical,
            detector: "risky_call".to_string(),
            file_path: "model.pkl".to_string(),
            source: None,
            offset: 42,
            operator: Some("REDUCE".to_string()),
            module: Some("os".to_string()),
            name: Some("system".to_string()),
            message: "os.system invoked".to_string(),
        }
    }

    #[test]
    fn render_one_critical_issue() {
        let report = ScanReport {
            meta: meta(),
            issues: vec![critical_issue()],
            scanned_files: vec!["model.pkl".to_string()],
            skipped_files: vec![],
            errors: vec![],
            allowlist_hits: vec![],
        };

        let out = render(&report, true);
        let v: Value = serde_json::from_str(&out).expect("valid JSON");

        assert_eq!(v["summary"]["total_issues"], 1);
        assert_eq!(v["issues"][0]["severity"], "CRITICAL");

        // Severity map carries every tier; the critical bucket is the only hit.
        let by_sev = &v["summary"]["total_issues_by_severity"];
        assert_eq!(by_sev["CRITICAL"], 1);
        assert_eq!(by_sev["LOW"], 0);
        assert_eq!(by_sev["MEDIUM"], 0);
        assert_eq!(by_sev["HIGH"], 0);

        // Source falls back to the file path when no sub-source is set.
        assert_eq!(v["issues"][0]["source"], "model.pkl");
        assert_eq!(v["issues"][0]["scanner"], "risky_call");
        assert_eq!(v["issues"][0]["description"], "os.system invoked");
        assert_eq!(v["summary"]["scanned"]["total_scanned"], 1);
    }

    #[test]
    fn compact_and_pretty_parse_equal() {
        let report = ScanReport {
            meta: meta(),
            issues: vec![critical_issue()],
            scanned_files: vec![],
            skipped_files: vec![],
            errors: vec![],
            allowlist_hits: vec![],
        };

        let pretty: Value = serde_json::from_str(&render(&report, true)).unwrap();
        let compact: Value = serde_json::from_str(&render(&report, false)).unwrap();
        assert_eq!(pretty, compact);
    }
}
