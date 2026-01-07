//! Human-readable console reporter.
//!
//! Renders a [`ScanReport`] in the spirit of upstream modelscan's terminal
//! output: a metadata header, a one-line severity summary, the findings grouped
//! by severity (Critical first), then a scanned/skipped tally and an optional
//! allowlist hit-count section. ANSI color is opt-in via `color` so that piped
//! / redirected output (and the unit tests) stay escape-free.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::{ScanReport, Severity};

/// ANSI reset.
const RESET: &str = "\x1b[0m";
/// ANSI bold.
const BOLD: &str = "\x1b[1m";

/// Severity tiers in descending order — the order findings are grouped in.
const TIERS: [Severity; 4] = [
    Severity::Critical,
    Severity::High,
    Severity::Medium,
    Severity::Low,
];

/// The foreground color escape for a severity, or `""` when color is disabled.
fn sev_color(sev: Severity, color: bool) -> &'static str {
    if !color {
        return "";
    }
    match sev {
        Severity::Critical => "\x1b[31m", // red
        Severity::High => "\x1b[35m",     // magenta
        Severity::Medium => "\x1b[33m",   // yellow
        Severity::Low => "\x1b[36m",      // cyan
        Severity::None => "",
    }
}

/// Wrap `text` in `escape`/RESET when color is on, otherwise return it bare.
fn paint(out: &mut String, escape: &str, text: &str, color: bool) {
    if color && !escape.is_empty() {
        let _ = write!(out, "{escape}{text}{RESET}");
    } else {
        out.push_str(text);
    }
}

/// Render the console report. `color` toggles ANSI escapes; with `color==false`
/// the output is guaranteed to contain no `\x1b` sequences. Output is
/// deterministic: issues are emitted in their given order within each tier.
pub fn render(report: &ScanReport, color: bool) -> String {
    let mut out = String::new();
    let meta = &report.meta;

    // --- header ------------------------------------------------------------
    let title = format!("{} v{}", meta.tool, meta.tool_version);
    paint(&mut out, BOLD, &title, color);
    out.push('\n');
    let _ = writeln!(out, "Input:     {}", meta.input_path);
    if meta.absolute_path != meta.input_path && !meta.absolute_path.is_empty() {
        let _ = writeln!(out, "Path:      {}", meta.absolute_path);
    }
    let _ = writeln!(out, "Timestamp: {}", meta.timestamp);
    let _ = writeln!(out, "Scan time: {} ms", meta.elapsed_ms);
    out.push('\n');

    // --- summary -----------------------------------------------------------
    let counts: BTreeMap<Severity, usize> = report.by_severity();
    let get = |s: Severity| counts.get(&s).copied().unwrap_or(0);
    let _ = write!(out, "Summary: Total {}", report.total_issues());
    for tier in TIERS {
        out.push_str(" | ");
        let label = format!("{}: {}", tier.as_str(), get(tier));
        paint(&mut out, sev_color(tier, color), &label, color);
    }
    out.push('\n');
    out.push('\n');

    // --- issues, grouped by severity descending ----------------------------
    if report.issues.is_empty() {
        out.push_str("No issues found.\n");
    } else {
        for tier in TIERS {
            // Preserve given order within the tier (deterministic output).
            let mut first = true;
            for issue in report.issues.iter().filter(|i| i.severity == tier) {
                if first {
                    let header = format!("[{}]", tier.as_str());
                    paint(&mut out, sev_color(tier, color), &header, color);
                    out.push('\n');
                    first = false;
                }
                render_issue(&mut out, issue, color);
            }
            if !first {
                out.push('\n');
            }
        }
    }

    // --- scanned / skipped tally ------------------------------------------
    let _ = writeln!(
        out,
        "Scanned {} files, skipped {} files",
        report.scanned_files.len(),
        report.skipped_files.len()
    );

    // --- non-fatal scan errors --------------------------------------------
    if !report.errors.is_empty() {
        let _ = writeln!(out, "Errors ({}):", report.errors.len());
        for err in &report.errors {
            let _ = writeln!(
                out,
                "  {} [{}] {}",
                err.source, err.category, err.message
            );
        }
    }

    // --- allowlist hits ----------------------------------------------------
    if !report.allowlist_hits.is_empty() {
        out.push('\n');
        out.push_str("Allowlist hits:\n");
        for (entry, count) in &report.allowlist_hits {
            let _ = writeln!(out, "  {entry}: {count}");
        }
    }

    out
}

/// Render a single issue line block:
///   - severity tag + id + detector
///   - location (file_path, source if Some, offset)
///   - the `module.name (operator)` qualifier when present
///   - the message
fn render_issue(out: &mut String, issue: &crate::Issue, color: bool) {
    let tag = format!("{}", issue.severity.as_str());
    out.push_str("  ");
    paint(out, sev_color(issue.severity, color), &tag, color);
    let _ = writeln!(out, " {} ({})", issue.id, issue.detector);

    // Location: file path, optional sub-source, byte offset.
    out.push_str("    at ");
    out.push_str(&issue.file_path);
    if let Some(src) = &issue.source {
        let _ = write!(out, " :: {src}");
    }
    let _ = writeln!(out, " (offset {})", issue.offset);

    // module.name (operator) qualifier.
    let qualified = issue.qualified().or_else(|| issue.module.clone().or_else(|| issue.name.clone()));
    if let Some(q) = qualified {
        match &issue.operator {
            Some(op) => {
                let _ = writeln!(out, "    {q} ({op})");
            }
            None => {
                let _ = writeln!(out, "    {q}");
            }
        }
    } else if let Some(op) = &issue.operator {
        let _ = writeln!(out, "    ({op})");
    }

    // Message.
    let _ = writeln!(out, "    {}", issue.message);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Issue, ReportMeta, ScanReport};
    use ms_detectors::Severity;

    fn meta() -> ReportMeta {
        ReportMeta {
            tool: "modelscan".to_string(),
            tool_version: "0.1.0".to_string(),
            schema_version: "1".to_string(),
            timestamp: "2026-05-31T12:00:00.000Z".to_string(),
            input_path: "model.pkl".to_string(),
            absolute_path: "/models/model.pkl".to_string(),
            elapsed_ms: 42,
            git_commit: None,
        }
    }

    fn empty_report() -> ScanReport {
        ScanReport {
            meta: meta(),
            issues: vec![],
            scanned_files: vec!["model.pkl".to_string()],
            skipped_files: vec![],
            errors: vec![],
            allowlist_hits: vec![],
        }
    }

    fn critical_issue() -> Issue {
        Issue {
            id: "MS-dead-beef".to_string(),
            severity: Severity::Critical,
            detector: "risky_call".to_string(),
            file_path: "model.pkl".to_string(),
            source: None,
            offset: 128,
            operator: Some("REDUCE".to_string()),
            module: Some("os".to_string()),
            name: Some("system".to_string()),
            message: "Unsafe global `os.system` referenced via REDUCE.".to_string(),
        }
    }

    #[test]
    fn empty_report_no_issues() {
        let r = empty_report();
        let plain = render(&r, false);
        assert!(plain.contains("modelscan v0.1.0"));
        assert!(plain.contains("No issues found."));
        assert!(plain.contains("Summary: Total 0"));
        assert!(plain.contains("Scanned 1 files, skipped 0 files"));
        // color=false must produce no ANSI escapes.
        assert!(!plain.contains('\x1b'));
    }

    #[test]
    fn single_critical_issue() {
        let mut r = empty_report();
        r.issues.push(critical_issue());
        let plain = render(&r, false);
        assert!(plain.contains("Summary: Total 1"));
        assert!(plain.contains("CRITICAL: 1"));
        assert!(plain.contains("[CRITICAL]"));
        assert!(plain.contains("MS-dead-beef"));
        assert!(plain.contains("risky_call"));
        assert!(plain.contains("os.system"));
        assert!(plain.contains("(REDUCE)"));
        assert!(plain.contains("offset 128"));
        assert!(plain.contains("Unsafe global `os.system`"));
        // No escapes when color is disabled.
        assert!(!plain.contains('\x1b'));
    }

    #[test]
    fn color_enables_ansi_escapes() {
        let mut r = empty_report();
        r.issues.push(critical_issue());
        let colored = render(&r, true);
        assert!(colored.contains('\x1b'));
        assert!(colored.contains("\x1b[31m")); // CRITICAL red
        assert!(colored.contains(RESET));
        // Substance is still present.
        assert!(colored.contains("os.system"));
    }

    #[test]
    fn source_shown_when_present() {
        let mut r = empty_report();
        let mut issue = critical_issue();
        issue.source = Some("archive.zip/data.pkl".to_string());
        r.issues.push(issue);
        let plain = render(&r, false);
        assert!(plain.contains("archive.zip/data.pkl"));
    }
}
