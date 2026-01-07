//! `ms-core` — the GUI-agnostic scan engine.
//!
//! Both the CLI and the GUI call into [`ModelScan`]. It enumerates files,
//! sniffs formats, dispatches to a [`Parser`](ms_formats::Parser), runs the
//! [`Detector`](ms_detectors::Detector) registry, suppresses allowlisted
//! findings, and produces a deterministic [`ScanResult`].
//!
//! The Rust API mirrors upstream's Python `ModelScan`:
//!
//! ```no_run
//! use ms_core::{ModelScan, Settings};
//! let mut scanner = ModelScan::new(Settings::default());
//! let result = scanner.scan("model.pkl").unwrap();
//! let _ = result.max_severity();
//! let _ = result.group_by_severity();
//! let _report = scanner.generate_report(&ms_report::ReportFormat::Json, false).unwrap();
//! ```

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub mod ctx;
pub mod error;
pub mod exitcode;
pub mod scan;
pub mod settings;
pub mod sniff;
pub mod walker;

pub use ctx::ScanContext;
pub use error::CoreError;
pub use settings::{Settings, DEFAULT_SETTINGS_TOML};

// Re-export the key downstream types so consumers only need `ms_core`.
pub use ms_detectors::{Issue, Severity};
pub use ms_report::{ReportFormat, ScanReport};

/// Knobs that affect a single scan invocation (CLI flags / GUI form).
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Include globs (`*.pkl,*.pt`). Empty = use the settings' supported set.
    pub include: Vec<String>,
    /// Exclude globs (`tests/**`).
    pub exclude: Vec<String>,
    /// Recursive walk depth cap. `None` = use settings default (10).
    pub max_depth: Option<usize>,
    /// Follow symlinks during the walk.
    pub follow_symlinks: bool,
    /// Strict upstream-parity mode: omit Lancer-only LOW findings from output.
    pub strict_parity: bool,
    /// Baseline allowlist generated from a known-clean scan.
    pub baseline: Option<PathBuf>,
    /// Record skipped files (for `--show-skipped`).
    pub show_skipped: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        ScanOptions {
            include: Vec::new(),
            exclude: Vec::new(),
            max_depth: None,
            follow_symlinks: false,
            strict_parity: false,
            baseline: None,
            show_skipped: false,
        }
    }
}

/// A file (or container member) that was skipped, with reason category.
#[derive(Debug, Clone)]
pub struct SkippedFile {
    pub source: String,
    pub category: SkipCategory,
    pub message: String,
}

/// Why a file was skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipCategory {
    /// No parser claimed it (unsupported extension/magic).
    NotSupported,
    /// Filtered out by include/exclude globs.
    FilteredByGlob,
    /// Beyond `--max-depth`.
    DepthExceeded,
    /// Known-safe baseline format (safetensors / gguf).
    SafeFormat,
}

impl SkipCategory {
    pub fn as_str(self) -> &'static str {
        match self {
            SkipCategory::NotSupported => "SCAN_NOT_SUPPORTED",
            SkipCategory::FilteredByGlob => "FILTERED_BY_GLOB",
            SkipCategory::DepthExceeded => "DEPTH_EXCEEDED",
            SkipCategory::SafeFormat => "SAFE_FORMAT",
        }
    }
}

/// A non-fatal error scanning one file (bad zip, truncated pickle, etc.).
#[derive(Debug, Clone)]
pub struct ScanFileError {
    pub source: String,
    pub category: String,
    pub message: String,
}

/// Result of a scan. Mirrors upstream's `ModelScan.issues` + summary surface.
#[derive(Debug, Clone)]
pub struct ScanResult {
    pub issues: Vec<Issue>,
    pub scanned: Vec<String>,
    pub skipped: Vec<SkippedFile>,
    pub errors: Vec<ScanFileError>,
    pub elapsed_ms: u128,
    pub input_path: String,
    pub absolute_path: String,
    pub allowlist_hits: Vec<(String, u64)>,
    /// True if at least one file matched a supported format.
    pub found_supported: bool,
}

impl ScanResult {
    /// All issues (already deterministically sorted).
    pub fn all_issues(&self) -> &[Issue] {
        &self.issues
    }

    /// Issues grouped by severity (descending iteration via `BTreeMap` rev).
    pub fn group_by_severity(&self) -> BTreeMap<Severity, Vec<&Issue>> {
        let mut m: BTreeMap<Severity, Vec<&Issue>> = BTreeMap::new();
        for issue in &self.issues {
            m.entry(issue.severity).or_default().push(issue);
        }
        m
    }

    pub fn max_severity(&self) -> Severity {
        self.issues
            .iter()
            .map(|i| i.severity)
            .max()
            .unwrap_or(Severity::None)
    }

    pub fn has_issues(&self) -> bool {
        !self.issues.is_empty()
    }

    /// Build a renderable [`ScanReport`] (adds tool/version/time metadata).
    pub fn to_report(&self) -> ScanReport {
        let by_cat = |files: &[SkippedFile]| {
            files
                .iter()
                .map(|s| ms_report::SkippedFile {
                    source: s.source.clone(),
                    category: s.category.as_str().to_string(),
                    message: s.message.clone(),
                })
                .collect::<Vec<_>>()
        };
        ScanReport {
            meta: ms_report::ReportMeta {
                tool: "lancer-modelscan".to_string(),
                tool_version: env!("CARGO_PKG_VERSION").to_string(),
                schema_version: "1.0".to_string(),
                timestamp: ms_report::now_rfc3339(),
                input_path: self.input_path.clone(),
                absolute_path: self.absolute_path.clone(),
                elapsed_ms: self.elapsed_ms,
                git_commit: option_env!("LANCER_GIT_COMMIT").map(|s| s.to_string()),
            },
            issues: self.issues.clone(),
            scanned_files: self.scanned.clone(),
            skipped_files: by_cat(&self.skipped),
            errors: self
                .errors
                .iter()
                .map(|e| ms_report::ScanErrorEntry {
                    source: e.source.clone(),
                    category: e.category.clone(),
                    message: e.message.clone(),
                })
                .collect(),
            allowlist_hits: self.allowlist_hits.clone(),
        }
    }
}

/// The scanner. Holds settings + the built scan context, and caches the last
/// result so `issues()` / `generate_report()` work after `scan()`.
pub struct ModelScan {
    ctx: ScanContext,
    options: ScanOptions,
    result: Option<ScanResult>,
}

impl ModelScan {
    /// Construct with explicit settings (mirrors `ModelScan(settings=...)`).
    pub fn new(settings: Settings) -> Self {
        ModelScan {
            ctx: ScanContext::from_settings(settings),
            options: ScanOptions::default(),
            result: None,
        }
    }

    /// Construct with `DEFAULT_SETTINGS`.
    pub fn with_defaults() -> Self {
        ModelScan::new(Settings::default())
    }

    /// Replace scan options (include/exclude/depth/etc.).
    pub fn set_options(&mut self, options: ScanOptions) {
        self.options = options;
    }

    pub fn options(&self) -> &ScanOptions {
        &self.options
    }

    pub fn settings(&self) -> &Settings {
        &self.ctx.settings
    }

    pub fn context(&self) -> &ScanContext {
        &self.ctx
    }

    /// Scan a file or directory. Returns a reference to the cached result.
    pub fn scan(&mut self, path: impl AsRef<Path>) -> Result<&ScanResult, CoreError> {
        let result = scan::run(&self.ctx, path.as_ref(), &self.options)?;
        self.result = Some(result);
        Ok(self.result.as_ref().unwrap())
    }

    /// Issues from the last scan (empty before any scan).
    pub fn issues(&self) -> &[Issue] {
        self.result.as_ref().map(|r| r.all_issues()).unwrap_or(&[])
    }

    pub fn result(&self) -> Option<&ScanResult> {
        self.result.as_ref()
    }

    /// Render the last scan in `format`. `color` only affects console output.
    pub fn generate_report(
        &self,
        format: &ReportFormat,
        color: bool,
    ) -> Result<String, CoreError> {
        let result = self
            .result
            .as_ref()
            .ok_or_else(|| CoreError::Config("no scan has been run yet".into()))?;
        result
            .to_report()
            .render(format, color)
            .map_err(CoreError::Report)
    }
}
