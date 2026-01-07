//! File enumeration: recursive directory walk with include/exclude globs,
//! depth cap, and symlink policy. Powered by the `ignore` + `globset` crates
//! (the same machinery `ripgrep` uses).

use crate::settings::Settings;
use crate::{ScanOptions, SkipCategory, SkippedFile};
use globset::{Glob, GlobSet, GlobSetBuilder};
use ignore::WalkBuilder;
use std::path::{Path, PathBuf};

/// Result of enumerating a scan root.
pub struct Enumeration {
    pub files: Vec<PathBuf>,
    pub skipped: Vec<SkippedFile>,
}

fn build_globset(patterns: &[String]) -> Option<GlobSet> {
    if patterns.is_empty() {
        return None;
    }
    let mut b = GlobSetBuilder::new();
    for p in patterns {
        if let Ok(g) = Glob::new(p) {
            b.add(g);
        }
    }
    b.build().ok()
}

fn norm(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

/// Enumerate scannable files under `root` (a file or directory).
pub fn enumerate(root: &Path, opts: &ScanOptions, settings: &Settings) -> Enumeration {
    let include = build_globset(&opts.include);
    let exclude = build_globset(&opts.exclude);
    let max_depth = opts.max_depth.unwrap_or(settings.max_depth);
    let follow = opts.follow_symlinks || settings.follow_symlinks;

    let mut files = Vec::new();
    let mut skipped = Vec::new();

    let mut consider = |path: &Path, files: &mut Vec<PathBuf>, skipped: &mut Vec<SkippedFile>| {
        let s = norm(path);
        if let Some(inc) = &include {
            if !inc.is_match(&s) {
                if opts.show_skipped {
                    skipped.push(SkippedFile {
                        source: s.clone(),
                        category: SkipCategory::FilteredByGlob,
                        message: "did not match any --include glob".to_string(),
                    });
                }
                return;
            }
        }
        if let Some(exc) = &exclude {
            if exc.is_match(&s) {
                if opts.show_skipped {
                    skipped.push(SkippedFile {
                        source: s.clone(),
                        category: SkipCategory::FilteredByGlob,
                        message: "matched an --exclude glob".to_string(),
                    });
                }
                return;
            }
        }
        files.push(path.to_path_buf());
    };

    if root.is_file() {
        consider(root, &mut files, &mut skipped);
        return Enumeration { files, skipped };
    }

    let walker = WalkBuilder::new(root)
        .standard_filters(false) // scan everything; security scan ignores .gitignore
        .hidden(false)
        .follow_links(follow)
        .max_depth(Some(max_depth))
        .build();

    for entry in walker {
        match entry {
            Ok(e) => {
                if e.file_type().map(|t| t.is_file()).unwrap_or(false) {
                    consider(e.path(), &mut files, &mut skipped);
                }
            }
            Err(_) => continue,
        }
    }

    files.sort();
    Enumeration { files, skipped }
}
