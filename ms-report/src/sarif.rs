//! SARIF 2.1.0 report emitter.
//!
//! Emits a [Static Analysis Results Interchange Format][sarif] document so
//! findings can be ingested by CI dashboards (GitHub code scanning, etc.).
//! Built directly with `serde_json` and pretty-printed.
//!
//! [sarif]: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

use crate::ScanReport;
use ms_detectors::Severity;

/// Render `report` as pretty-printed SARIF 2.1.0 JSON.
pub fn render(report: &ScanReport) -> String {
    serde_json::to_string_pretty(&build_value(report))
        // `serde_json::Value` always serializes; the fallback is unreachable in
        // practice but keeps this infallible for the `render` contract.
        .unwrap_or_else(|_| "{}".to_string())
}

/// Map a [`Severity`] to a SARIF `result.level`.
///
/// `critical`/`high` -> `error`, `medium` -> `warning`, everything else
/// (`low`/`none`) -> `note`.
fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low | Severity::None => "note",
    }
}

fn build_value(report: &ScanReport) -> serde_json::Value {
    // Unique detector ids, in first-seen order (deterministic).
    let mut seen: Vec<&str> = Vec::new();
    for issue in &report.issues {
        if !seen.iter().any(|d| *d == issue.detector.as_str()) {
            seen.push(issue.detector.as_str());
        }
    }
    let rules: Vec<serde_json::Value> = seen
        .iter()
        .map(|id| serde_json::json!({ "id": id }))
        .collect();

    let results: Vec<serde_json::Value> = report
        .issues
        .iter()
        .map(|i| {
            serde_json::json!({
                "ruleId": i.detector,
                "level": sarif_level(i.severity),
                "message": { "text": i.message },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": { "uri": i.file_path },
                            "region": { "byteOffset": i.offset }
                        }
                    }
                ],
                "properties": {
                    "severity": i.severity.as_str(),
                    "module": i.module,
                    "name": i.name,
                    "id": i.id
                }
            })
        })
        .collect();

    serde_json::json!({
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "lancer-modelscan",
                        "version": report.meta.tool_version,
                        "informationUri": "https://github.com/NHTanvir/lancer-modelscan",
                        "rules": rules
                    }
                },
                "results": results
            }
        ]
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ReportMeta, ScanReport};
    use ms_detectors::{Issue, Severity};

    fn sample_meta() -> ReportMeta {
        ReportMeta {
            tool: "lancer-modelscan".to_string(),
            tool_version: "0.1.0".to_string(),
            schema_version: "1".to_string(),
            timestamp: "2026-05-31T12:00:00.000Z".to_string(),
            input_path: "model.pkl".to_string(),
            absolute_path: "/abs/model.pkl".to_string(),
            elapsed_ms: 5,
            git_commit: None,
        }
    }

    fn issue(detector: &str, severity: Severity) -> Issue {
        Issue {
            id: "MS-dead-beef".to_string(),
            severity,
            detector: detector.to_string(),
            file_path: "model.pkl".to_string(),
            source: None,
            offset: 42,
            operator: Some("REDUCE".to_string()),
            module: Some("os".to_string()),
            name: Some("system".to_string()),
            message: "calls os.system".to_string(),
        }
    }

    fn report_with(issues: Vec<Issue>) -> ScanReport {
        ScanReport {
            meta: sample_meta(),
            issues,
            scanned_files: vec!["model.pkl".to_string()],
            skipped_files: vec![],
            errors: vec![],
            allowlist_hits: vec![],
        }
    }

    #[test]
    fn output_is_valid_sarif_json() {
        let report = report_with(vec![
            issue("risky_call", Severity::Critical),
            issue("risky_call", Severity::Medium),
            issue("global_ref", Severity::Low),
        ]);
        let out = render(&report);

        let v: serde_json::Value = serde_json::from_str(&out).expect("must parse as JSON");
        assert_eq!(v["version"], "2.1.0");
        assert_eq!(v["runs"][0]["tool"]["driver"]["name"], "lancer-modelscan");
        assert_eq!(v["runs"][0]["tool"]["driver"]["version"], "0.1.0");

        // Duplicate detector ids are collapsed to one rule, in first-seen order.
        let rules = v["runs"][0]["tool"]["driver"]["rules"].as_array().unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0]["id"], "risky_call");
        assert_eq!(rules[1]["id"], "global_ref");

        // One result per issue, with the expected level mapping.
        let results = v["runs"][0]["results"].as_array().unwrap();
        assert_eq!(results.len(), 3);
        assert_eq!(results[0]["level"], "error"); // Critical
        assert_eq!(results[1]["level"], "warning"); // Medium
        assert_eq!(results[2]["level"], "note"); // Low
        assert_eq!(results[0]["ruleId"], "risky_call");
        assert_eq!(
            results[0]["locations"][0]["physicalLocation"]["region"]["byteOffset"],
            42
        );
        assert_eq!(results[0]["properties"]["severity"], "CRITICAL");
        assert_eq!(results[0]["properties"]["module"], "os");
    }

    #[test]
    fn empty_report_has_no_results_or_rules() {
        let out = render(&report_with(vec![]));
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["runs"][0]["tool"]["driver"]["name"], "lancer-modelscan");
        assert!(v["runs"][0]["results"].as_array().unwrap().is_empty());
        assert!(v["runs"][0]["tool"]["driver"]["rules"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn high_maps_to_error() {
        assert_eq!(sarif_level(Severity::High), "error");
        assert_eq!(sarif_level(Severity::None), "note");
    }
}
