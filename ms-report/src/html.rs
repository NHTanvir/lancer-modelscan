//! HTML report emitter.
//!
//! Renders a [`ScanReport`] into a single self-contained, styled HTML page via
//! a [Tera](tera) one-off template. `ScanReport` isn't `Serialize`, so we hand
//! Tera a `serde_json::Value` (built deterministically) under the key `r`.

use crate::ScanReport;

/// Render `report` as a standalone HTML document.
///
/// Tera failures are mapped to [`crate::ReportError::Template`].
pub fn render(report: &ScanReport) -> Result<String, crate::ReportError> {
    let value = build_value(report);

    let mut ctx = tera::Context::new();
    ctx.insert("r", &value);

    tera::Tera::one_off(TEMPLATE, &ctx, true)
        .map_err(|e| crate::ReportError::Template(e.to_string()))
}

/// Build the JSON view model the template consumes. Iteration order over
/// issues and severity tiers is deterministic (issues keep their slice order;
/// `by_severity` is a `BTreeMap`).
fn build_value(report: &ScanReport) -> serde_json::Value {
    let by_severity: Vec<serde_json::Value> = report
        .by_severity()
        .into_iter()
        .map(|(sev, count)| {
            serde_json::json!({
                "severity": sev.as_str(),
                "severity_lower": sev.as_str().to_ascii_lowercase(),
                "count": count,
            })
        })
        .collect();

    let issues: Vec<serde_json::Value> = report
        .issues
        .iter()
        .map(|i| {
            serde_json::json!({
                "id": i.id,
                "severity": i.severity.as_str(),
                "severity_lower": i.severity.as_str().to_ascii_lowercase(),
                "detector": i.detector,
                "file": i.file_path,
                "source": i.source,
                "offset": i.offset,
                "module": i.module,
                "name": i.name,
                "message": i.message,
            })
        })
        .collect();

    serde_json::json!({
        "tool": report.meta.tool,
        "version": report.meta.tool_version,
        "timestamp": report.meta.timestamp,
        "input_path": report.meta.input_path,
        "total": report.total_issues(),
        "counts": by_severity,
        "issues": issues,
        "scanned_count": report.scanned_files.len(),
        "skipped_count": report.skipped_files.len(),
    })
}

/// Self-contained HTML template. Inline `<style>` keeps the report portable
/// (no external assets). The issues table carries `data-*` attributes and a
/// tiny vanilla-JS sorter so columns are clickable without dependencies.
const TEMPLATE: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ r.tool }} report — {{ r.input_path }}</title>
<style>
  :root {
    --bg: #0f1117; --panel: #1a1d27; --panel-2: #232733; --border: #2c3140;
    --fg: #e6e8ee; --muted: #9aa3b2; --accent: #6ea8fe;
    --crit: #d9342b; --high: #e8590c; --medium: #d9a406; --low: #2f9e44; --none: #6c757d;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; background: var(--bg); color: var(--fg);
    font: 14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }
  .wrap { max-width: 1100px; margin: 0 auto; padding: 32px 20px 64px; }
  header h1 { margin: 0 0 4px; font-size: 22px; letter-spacing: .2px; }
  header .meta { color: var(--muted); font-size: 13px; }
  header .meta code { color: var(--fg); }
  .cards { display: flex; flex-wrap: wrap; gap: 12px; margin: 24px 0; }
  .card {
    background: var(--panel); border: 1px solid var(--border); border-radius: 10px;
    padding: 14px 16px; min-width: 120px; flex: 1 1 120px;
  }
  .card .num { font-size: 26px; font-weight: 700; }
  .card .label { color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .6px; }
  .card.sev-critical { border-left: 4px solid var(--crit); }
  .card.sev-high { border-left: 4px solid var(--high); }
  .card.sev-medium { border-left: 4px solid var(--medium); }
  .card.sev-low { border-left: 4px solid var(--low); }
  .card.sev-none { border-left: 4px solid var(--none); }
  .badge {
    display: inline-block; padding: 2px 9px; border-radius: 999px;
    font-size: 11px; font-weight: 700; letter-spacing: .5px; color: #fff;
  }
  .badge.sev-critical { background: var(--crit); }
  .badge.sev-high { background: var(--high); }
  .badge.sev-medium { background: var(--medium); color: #1a1d27; }
  .badge.sev-low { background: var(--low); }
  .badge.sev-none { background: var(--none); }
  table { width: 100%; border-collapse: collapse; margin-top: 8px; background: var(--panel); border-radius: 10px; overflow: hidden; }
  thead th {
    text-align: left; padding: 10px 12px; font-size: 12px; text-transform: uppercase;
    letter-spacing: .5px; color: var(--muted); background: var(--panel-2);
    border-bottom: 1px solid var(--border); cursor: pointer; user-select: none; white-space: nowrap;
  }
  thead th:hover { color: var(--fg); }
  tbody td { padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }
  tbody tr:last-child td { border-bottom: none; }
  tbody tr:hover { background: var(--panel-2); }
  code, .mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; }
  .muted { color: var(--muted); }
  .empty { padding: 28px; text-align: center; color: var(--muted); }
  footer { margin-top: 28px; color: var(--muted); font-size: 12px; }
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>{{ r.tool }} <span class="muted">v{{ r.version }}</span></h1>
    <div class="meta">
      Scanned <code>{{ r.input_path }}</code> &middot; {{ r.timestamp }}<br>
      {{ r.scanned_count }} file(s) scanned &middot; {{ r.skipped_count }} skipped &middot; {{ r.total }} issue(s) found
    </div>
  </header>

  <section class="cards">
    <div class="card">
      <div class="num">{{ r.total }}</div>
      <div class="label">Total</div>
    </div>
    {% for c in r.counts %}
    <div class="card sev-{{ c.severity_lower }}">
      <div class="num">{{ c.count }}</div>
      <div class="label">{{ c.severity }}</div>
    </div>
    {% endfor %}
  </section>

  {% if r.issues | length > 0 %}
  <table id="issues">
    <thead>
      <tr>
        <th data-col="0">Severity</th>
        <th data-col="1">Detector</th>
        <th data-col="2">File</th>
        <th data-col="3">Target</th>
        <th data-col="4">Offset</th>
        <th data-col="5">Message</th>
        <th data-col="6">ID</th>
      </tr>
    </thead>
    <tbody>
      {% for i in r.issues %}
      <tr>
        <td><span class="badge sev-{{ i.severity_lower }}">{{ i.severity }}</span></td>
        <td class="mono">{{ i.detector }}</td>
        <td class="mono">{{ i.file }}{% if i.source %} <span class="muted">[{{ i.source }}]</span>{% endif %}</td>
        <td class="mono">{% if i.module %}{{ i.module }}{% if i.name %}.{{ i.name }}{% endif %}{% elif i.name %}{{ i.name }}{% else %}<span class="muted">&mdash;</span>{% endif %}</td>
        <td class="mono">{{ i.offset }}</td>
        <td>{{ i.message }}</td>
        <td class="mono muted">{{ i.id }}</td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% else %}
  <div class="empty">No issues found.</div>
  {% endif %}

  <footer>Generated by {{ r.tool }} v{{ r.version }}.</footer>
</div>

<script>
// Minimal dependency-free column sorter for the issues table.
(function () {
  var table = document.getElementById("issues");
  if (!table) return;
  var headers = table.tHead.rows[0].cells;
  for (var h = 0; h < headers.length; h++) {
    (function (idx) {
      headers[idx].addEventListener("click", function () {
        var body = table.tBodies[0];
        var rows = Array.prototype.slice.call(body.rows);
        var asc = this.getAttribute("data-asc") !== "true";
        rows.sort(function (a, b) {
          var x = a.cells[idx].innerText.trim();
          var y = b.cells[idx].innerText.trim();
          var nx = parseFloat(x), ny = parseFloat(y);
          if (!isNaN(nx) && !isNaN(ny)) return asc ? nx - ny : ny - nx;
          return asc ? x.localeCompare(y) : y.localeCompare(x);
        });
        for (var r = 0; r < rows.length; r++) body.appendChild(rows[r]);
        this.setAttribute("data-asc", asc);
      });
    })(h);
  }
})();
</script>
</body>
</html>
"#;

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

    fn sample_issue() -> Issue {
        Issue {
            id: "MS-dead-beef".to_string(),
            severity: Severity::Critical,
            detector: "risky_call".to_string(),
            file_path: "model.pkl".to_string(),
            source: Some("archive/data.pkl".to_string()),
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
    fn renders_issue_table() {
        let html = render(&report_with(vec![sample_issue()])).unwrap();
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("lancer-modelscan"));
        assert!(html.contains("MS-dead-beef"));
        assert!(html.contains("risky_call"));
        assert!(html.contains("os.system"));
        assert!(html.contains("calls os.system"));
        // Critical badge class is present and total card reflects one issue.
        assert!(html.contains("badge sev-critical"));
        assert!(html.contains("CRITICAL"));
    }

    #[test]
    fn renders_empty_report() {
        let html = render(&report_with(vec![])).unwrap();
        assert!(html.contains("No issues found."));
        // All four severity cards are always present, even at zero.
        assert!(html.contains(">LOW<"));
        assert!(html.contains(">CRITICAL<"));
    }

    #[test]
    fn escapes_html_in_messages() {
        let mut issue = sample_issue();
        issue.message = "<script>alert(1)</script>".to_string();
        let html = render(&report_with(vec![issue])).unwrap();
        // autoescape=true means the raw tag must not appear verbatim.
        assert!(!html.contains("<script>alert(1)</script>"));
        assert!(html.contains("&lt;script&gt;"));
    }
}
