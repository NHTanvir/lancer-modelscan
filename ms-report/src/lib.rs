//! `ms-report` — report emitters (console / JSON / HTML / SARIF).
//!
//! This crate depends only on `ms-detectors` (for [`Issue`]/[`Severity`]) so it
//! sits *below* `ms-core` in the dependency graph and can be unit-tested in
//! isolation. `ms-core` builds a [`ScanReport`] from its internal scan result
//! and hands it here for rendering.

use std::collections::BTreeMap;

pub use ms_detectors::{Issue, Severity};

pub mod console;
pub mod json;
pub mod html;
pub mod sarif;

/// Output format selector. Mirrors upstream `-r/--reporting-format`
/// (`console`/`json`/`custom`) plus Lancer extensions (`html`, `sarif`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReportFormat {
    Console,
    Json,
    Html,
    Sarif,
    /// Upstream `custom`: a `modelscan.reporting.*` module path from settings.
    /// In Rust we resolve it to a builtin emitter by name where possible.
    Custom(String),
}

impl ReportFormat {
    pub fn parse(s: &str) -> ReportFormat {
        match s.trim().to_ascii_lowercase().as_str() {
            "console" | "text" | "" => ReportFormat::Console,
            "json" => ReportFormat::Json,
            "html" => ReportFormat::Html,
            "sarif" => ReportFormat::Sarif,
            "custom" => ReportFormat::Custom(String::new()),
            other => ReportFormat::Custom(other.to_string()),
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            ReportFormat::Console => "console",
            ReportFormat::Json => "json",
            ReportFormat::Html => "html",
            ReportFormat::Sarif => "sarif",
            ReportFormat::Custom(_) => "custom",
        }
    }
}

/// A file that was skipped, with the reason category.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SkippedFile {
    pub source: String,
    /// e.g. `"SCAN_NOT_SUPPORTED"`, `"FILTERED_BY_GLOB"`, `"DEPTH_EXCEEDED"`.
    pub category: String,
    pub message: String,
}

/// A non-fatal error encountered while scanning a particular file.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ScanErrorEntry {
    pub source: String,
    pub category: String,
    pub message: String,
}

/// Metadata header for a report (tool/version/time/input).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ReportMeta {
    pub tool: String,
    pub tool_version: String,
    /// Stable schema version for the JSON output (independent of tool version).
    pub schema_version: String,
    /// RFC3339 UTC timestamp.
    pub timestamp: String,
    pub input_path: String,
    pub absolute_path: String,
    pub elapsed_ms: u128,
    /// Git commit of the scanner build, if embedded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_commit: Option<String>,
}

/// Everything a reporter needs to render a scan.
#[derive(Debug, Clone)]
pub struct ScanReport {
    pub meta: ReportMeta,
    pub issues: Vec<Issue>,
    pub scanned_files: Vec<String>,
    pub skipped_files: Vec<SkippedFile>,
    pub errors: Vec<ScanErrorEntry>,
    /// Per-allowlist-entry hit counts (for `--show-skipped`).
    pub allowlist_hits: Vec<(String, u64)>,
}

impl ScanReport {
    /// Count of issues per severity (every tier present, even if 0).
    pub fn by_severity(&self) -> BTreeMap<Severity, usize> {
        let mut m = BTreeMap::new();
        for s in [
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ] {
            m.insert(s, 0);
        }
        for issue in &self.issues {
            *m.entry(issue.severity).or_insert(0) += 1;
        }
        m
    }

    pub fn total_issues(&self) -> usize {
        self.issues.len()
    }

    pub fn max_severity(&self) -> Severity {
        self.issues
            .iter()
            .map(|i| i.severity)
            .max()
            .unwrap_or(Severity::None)
    }

    /// Render in the requested format. `color` only affects `Console`.
    pub fn render(&self, format: &ReportFormat, color: bool) -> Result<String, ReportError> {
        match format {
            ReportFormat::Console => Ok(console::render(self, color)),
            ReportFormat::Json => Ok(json::render(self, true)),
            ReportFormat::Html => html::render(self),
            ReportFormat::Sarif => Ok(sarif::render(self)),
            ReportFormat::Custom(name) => match name.to_ascii_lowercase().as_str() {
                "" | "console" | "text" => Ok(console::render(self, color)),
                "json" => Ok(json::render(self, true)),
                "html" => html::render(self),
                "sarif" => Ok(sarif::render(self)),
                other => Err(ReportError::UnknownCustom(other.to_string())),
            },
        }
    }
}

/// Current wall-clock time as an RFC3339 / ISO-8601 UTC string, e.g.
/// `2026-05-31T12:34:56.789Z`. Used for report headers.
pub fn now_rfc3339() -> String {
    chrono::Utc::now()
        .to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

#[derive(Debug, thiserror::Error)]
pub enum ReportError {
    #[error("template render failed: {0}")]
    Template(String),
    #[error("unknown custom reporting module '{0}' (no Rust equivalent; \
             use console/json/html/sarif)")]
    UnknownCustom(String),
}
