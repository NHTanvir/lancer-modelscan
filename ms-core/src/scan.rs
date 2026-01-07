//! The scan pipeline: enumerate → sniff → parse → detect → suppress → sort.
//!
//! Files are processed in parallel with `rayon`; events within a file are
//! processed sequentially to keep offsets ordered. Issues are then sorted
//! deterministically so CI diffs are stable across runs (plan §7).

use crate::ctx::ScanContext;
use crate::error::CoreError;
use crate::{ScanFileError, ScanOptions, ScanResult, SkipCategory, SkippedFile};
use ms_detectors::{Allowlist, Issue, Severity};
use ms_formats::{Event, Limits, ParseError, Parser};
use rayon::prelude::*;
use std::path::Path;
use std::time::Instant;

struct FileOutcome {
    issues: Vec<Issue>,
    scanned: Option<String>,
    skipped: Vec<SkippedFile>,
    errors: Vec<ScanFileError>,
}

/// Run a full scan of `root`.
pub fn run(ctx: &ScanContext, root: &Path, opts: &ScanOptions) -> Result<ScanResult, CoreError> {
    let start = Instant::now();
    let limits = Limits::default();

    // 1) Allowlist (+ baseline harvest, if requested). Built mutably here, then
    //    shared immutably across the parallel phase.
    let mut allowlist = ctx.build_allowlist();
    if let Some(baseline) = &opts.baseline {
        let extra = collect_baseline_calls(ctx, baseline, opts, &limits);
        allowlist.calls.extend(extra);
    }
    let allowlist = allowlist;

    // 2) Enumerate files.
    let enumeration = crate::walker::enumerate(root, opts, &ctx.settings);
    let mut skipped = enumeration.skipped;

    // 3) Parser registry (shared, immutable).
    let parsers = crate::sniff::parsers();
    let excluded = &allowlist.excluded_detectors;

    // 4) Process files in parallel.
    let outcomes: Vec<FileOutcome> = enumeration
        .files
        .par_iter()
        .map(|path| process_file(path, &parsers, &allowlist, ctx, excluded, &limits))
        .collect();

    // 5) Reduce.
    let mut issues = Vec::new();
    let mut scanned = Vec::new();
    let mut errors = Vec::new();
    for o in outcomes {
        issues.extend(o.issues);
        if let Some(s) = o.scanned {
            scanned.push(s);
        }
        skipped.extend(o.skipped);
        errors.extend(o.errors);
    }

    // 6) Strict-parity: drop Lancer-only LOW findings.
    if opts.strict_parity {
        issues.retain(|i| i.severity != Severity::Low);
    }

    // 7) Deterministic ordering + dedup by id.
    issues.sort_by(|a, b| {
        a.file_path
            .cmp(&b.file_path)
            .then_with(|| a.source.cmp(&b.source))
            .then_with(|| a.offset.cmp(&b.offset))
            .then_with(|| a.detector.cmp(&b.detector))
            .then_with(|| a.module.cmp(&b.module))
            .then_with(|| a.name.cmp(&b.name))
    });
    issues.dedup_by(|a, b| a.id == b.id);

    scanned.sort();
    scanned.dedup();

    let found_supported = !scanned.is_empty();
    let absolute_path = std::fs::canonicalize(root)
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| root.to_string_lossy().to_string());

    Ok(ScanResult {
        issues,
        scanned,
        skipped,
        errors,
        elapsed_ms: start.elapsed().as_millis(),
        input_path: root.to_string_lossy().to_string(),
        absolute_path,
        allowlist_hits: allowlist.hit_counts(),
        found_supported,
    })
}

fn process_file(
    path: &Path,
    parsers: &[Box<dyn Parser>],
    allowlist: &Allowlist,
    ctx: &ScanContext,
    excluded: &std::collections::HashSet<String>,
    limits: &Limits,
) -> FileOutcome {
    let path_str = path.to_string_lossy().replace('\\', "/");
    let magic = crate::sniff::read_file_magic(path);
    let parser = match crate::sniff::select_with_magic(parsers, path, &magic) {
        Some(p) => p,
        None => {
            return FileOutcome {
                issues: Vec::new(),
                scanned: None,
                skipped: vec![SkippedFile {
                    source: path_str,
                    category: SkipCategory::NotSupported,
                    message: "no parser claims this file (unsupported format)".to_string(),
                }],
                errors: Vec::new(),
            }
        }
    };

    match parser.parse_path(path, limits) {
        Ok(events) => {
            let issues = detect(&events, allowlist, ctx, excluded, &path_str);
            FileOutcome {
                issues,
                scanned: Some(path_str),
                skipped: Vec::new(),
                errors: Vec::new(),
            }
        }
        Err(ParseError::Limit(msg)) => FileOutcome {
            issues: vec![resource_limit_issue(&path_str, &msg)],
            scanned: Some(path_str),
            skipped: Vec::new(),
            errors: Vec::new(),
        },
        Err(e) => FileOutcome {
            issues: Vec::new(),
            scanned: Some(path_str.clone()),
            skipped: Vec::new(),
            errors: vec![ScanFileError {
                source: path_str,
                category: format!("{}_PARSER", parser.id().to_ascii_uppercase()),
                message: e.to_string(),
            }],
        },
    }
}

/// Run every enabled detector over an event stream, applying issue-id
/// suppression. Bomb events are turned into a synthetic HIGH issue.
fn detect(
    events: &[Event],
    allowlist: &Allowlist,
    ctx: &ScanContext,
    excluded: &std::collections::HashSet<String>,
    path_str: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for event in events {
        if let Some(note) = &event.note {
            if note.contains("bomb") {
                issues.push(resource_limit_issue(path_str, note));
                continue;
            }
        }
        for detector in ctx.registry.iter_enabled(excluded) {
            if let Some(issue) = detector.evaluate(event, allowlist, path_str) {
                if !allowlist.is_allowed_issue(&issue.id) {
                    issues.push(issue);
                }
            }
        }
    }
    issues
}

fn resource_limit_issue(path_str: &str, message: &str) -> Issue {
    let id = Issue::make_id(path_str, None, 0, "resource_limit", None, Some(message));
    Issue {
        id,
        severity: Severity::High,
        detector: "resource_limit".to_string(),
        file_path: path_str.to_string(),
        source: None,
        offset: 0,
        operator: None,
        module: None,
        name: None,
        message: format!(
            "Resource limit hit while parsing (possible decompression/opcode bomb): {message}"
        ),
    }
}

/// Baseline mode: parse a known-clean tree and return every observed
/// `module.name` call, so the caller can allowlist them — only *new* findings
/// then break the build (plan §10).
fn collect_baseline_calls(
    ctx: &ScanContext,
    baseline: &Path,
    opts: &ScanOptions,
    limits: &Limits,
) -> std::collections::HashSet<String> {
    let mut base_opts = opts.clone();
    base_opts.baseline = None;
    base_opts.show_skipped = false;
    let enumeration = crate::walker::enumerate(baseline, &base_opts, &ctx.settings);
    let parsers = crate::sniff::parsers();
    let mut calls = std::collections::HashSet::new();
    for path in &enumeration.files {
        if let Some(parser) = crate::sniff::select(&parsers, path) {
            if let Ok(events) = parser.parse_path(path, limits) {
                for e in &events {
                    if let Some(q) = e.qualified_target() {
                        calls.insert(q);
                    }
                }
            }
        }
    }
    calls
}
