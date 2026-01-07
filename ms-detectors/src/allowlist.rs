//! Allowlist: per-call / per-issue / per-file permits, plus detector exclusions.
//!
//! Built by `ms-core` from `modelscan-settings.toml` (`[allowlist]`, `[[files]]`,
//! `[detectors] exclude = [...]`) merged with `--allow-list` files. Detectors
//! consult it to suppress known-safe findings. Hit counts are tracked so
//! `--show-skipped` can report which entries actually fired (and which are dead).

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

/// A per-file override: extra permitted calls for files whose path matches `glob`.
#[derive(Debug, Clone)]
pub struct FileOverride {
    pub glob: String,
    pub calls: HashSet<String>,
}

/// The merged allowlist consulted by every detector.
#[derive(Debug, Default)]
pub struct Allowlist {
    /// Globally-permitted `module.name` calls (known-safe rebuild functions etc.).
    pub calls: HashSet<String>,
    /// Manually-triaged issue ids to suppress.
    pub issue_ids: HashSet<String>,
    /// Per-file extra permits.
    pub files: Vec<FileOverride>,
    /// Detector ids to disable entirely.
    pub excluded_detectors: HashSet<String>,
    /// Hit counter per allowlist key (for `--show-skipped` / dead-entry pruning).
    hits: Mutex<HashMap<String, u64>>,
}

impl Clone for Allowlist {
    fn clone(&self) -> Self {
        Allowlist {
            calls: self.calls.clone(),
            issue_ids: self.issue_ids.clone(),
            files: self.files.clone(),
            excluded_detectors: self.excluded_detectors.clone(),
            hits: Mutex::new(self.hits.lock().map(|m| m.clone()).unwrap_or_default()),
        }
    }
}

impl Allowlist {
    pub fn new() -> Self {
        Allowlist::default()
    }

    /// Add a permitted `module.name` call.
    pub fn allow_call(&mut self, call: impl Into<String>) {
        self.calls.insert(call.into());
    }

    fn record_hit(&self, key: &str) {
        if let Ok(mut m) = self.hits.lock() {
            *m.entry(key.to_string()).or_insert(0) += 1;
        }
    }

    /// Is this `module.name` permitted for `file_path` (global or per-file)?
    /// Records a hit on the matching key when it suppresses a finding.
    pub fn is_allowed_call(&self, module: &str, name: &str, file_path: &str) -> bool {
        let qualified = format!("{module}.{name}");
        if self.calls.contains(&qualified) {
            self.record_hit(&qualified);
            return true;
        }
        // A bare module entry ("torch") permits any member of that module.
        if self.calls.contains(module) {
            self.record_hit(module);
            return true;
        }
        for ov in &self.files {
            if glob_match(&ov.glob, file_path)
                && (ov.calls.contains(&qualified) || ov.calls.contains(module))
            {
                self.record_hit(&format!("{}::{}", ov.glob, qualified));
                return true;
            }
        }
        false
    }

    /// Is this issue id manually suppressed?
    pub fn is_allowed_issue(&self, id: &str) -> bool {
        if self.issue_ids.contains(id) {
            self.record_hit(id);
            true
        } else {
            false
        }
    }

    /// Is this detector disabled?
    pub fn is_detector_excluded(&self, detector_id: &str) -> bool {
        self.excluded_detectors.contains(detector_id)
    }

    /// Snapshot of `(allowlist_key, hit_count)` for reporting.
    pub fn hit_counts(&self) -> Vec<(String, u64)> {
        let mut v: Vec<(String, u64)> = self
            .hits
            .lock()
            .map(|m| m.iter().map(|(k, c)| (k.clone(), *c)).collect())
            .unwrap_or_default();
        v.sort();
        v
    }

    /// Allowlist entries that never fired (candidates for pruning).
    pub fn dead_entries(&self) -> Vec<String> {
        let hits = self.hits.lock().map(|m| m.clone()).unwrap_or_default();
        let mut dead: Vec<String> = self
            .calls
            .iter()
            .filter(|c| hits.get(*c).copied().unwrap_or(0) == 0)
            .cloned()
            .collect();
        dead.sort();
        dead
    }
}

/// Minimal glob matcher for allowlist file patterns.
///
/// Supports `*` (any run, including `/`), `**` (treated as `*`), and `?`
/// (a single character). Paths are normalized to forward slashes first. This
/// is intentionally permissive — allowlists err toward matching.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let pat = pattern.replace('\\', "/").replace("**", "*");
    let txt = text.replace('\\', "/");
    wildcard(pat.as_bytes(), txt.as_bytes())
}

fn wildcard(pat: &[u8], txt: &[u8]) -> bool {
    // Iterative wildcard match with backtracking on `*`.
    let (mut p, mut t) = (0usize, 0usize);
    let (mut star, mut mark): (Option<usize>, usize) = (None, 0);
    while t < txt.len() {
        if p < pat.len() && (pat[p] == b'?' || pat[p] == txt[t]) {
            p += 1;
            t += 1;
        } else if p < pat.len() && pat[p] == b'*' {
            star = Some(p);
            mark = t;
            p += 1;
        } else if let Some(sp) = star {
            p = sp + 1;
            mark += 1;
            t = mark;
        } else {
            return false;
        }
    }
    while p < pat.len() && pat[p] == b'*' {
        p += 1;
    }
    p == pat.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_basics() {
        assert!(glob_match("models/legacy/*.pkl", "models/legacy/old.pkl"));
        assert!(glob_match("models/**/*.pkl", "models/a/b/c.pkl"));
        assert!(glob_match("*.pkl", "x.pkl"));
        assert!(!glob_match("*.pkl", "x.pt"));
        assert!(glob_match("a?c", "abc"));
        assert!(!glob_match("a?c", "ac"));
    }

    #[test]
    fn allow_call_and_module() {
        let mut a = Allowlist::new();
        a.allow_call("numpy.ndarray");
        a.allow_call("torch");
        assert!(a.is_allowed_call("numpy", "ndarray", "x.pkl"));
        assert!(a.is_allowed_call("torch", "anything", "x.pkl"));
        assert!(!a.is_allowed_call("os", "system", "x.pkl"));
    }
}
