//! Settings model — mirrors `modelscan-settings.toml`.
//!
//! Loaded via `--settings-file`; written by the `create-settings-file`
//! subcommand. The default settings ship the known-safe rebuild allowlist
//! (so legit numpy/torch/sklearn pickles don't fire) and enable every scanner.

use ms_detectors::defaults;
use ms_detectors::Allowlist;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

/// Default recursive walk depth.
pub const DEFAULT_MAX_DEPTH: usize = 10;

/// Top-level settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Recursive directory walk depth cap.
    pub max_depth: usize,
    /// Follow symlinks during the walk.
    pub follow_symlinks: bool,
    /// Extensions considered scannable (lowercase, no dot). Empty = sniff all.
    pub supported_extensions: Vec<String>,
    /// Global allowlist (`[allowlist]`).
    pub allowlist: AllowlistConfig,
    /// Per-file overrides (`[[files]]`).
    pub files: Vec<FileOverrideConfig>,
    /// Detector controls (`[detectors]`).
    pub detectors: DetectorConfig,
    /// Reporting defaults (`[reporting]`).
    pub reporting: ReportingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct AllowlistConfig {
    /// Permitted `module.name` calls (or bare `module` to permit all members).
    pub calls: Vec<String>,
    /// Manually-triaged issue ids to suppress.
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct FileOverrideConfig {
    /// Glob the override applies to.
    pub path: String,
    /// Extra permitted calls for matching files.
    pub calls: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct DetectorConfig {
    /// Detector ids to disable.
    pub exclude: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ReportingConfig {
    /// Default output format (`console`/`json`/`html`/`sarif`).
    pub format: String,
    /// Include "safe" / informational entries in the report.
    pub include_safe: bool,
}

impl Default for ReportingConfig {
    fn default() -> Self {
        ReportingConfig {
            format: "console".to_string(),
            include_safe: false,
        }
    }
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            max_depth: DEFAULT_MAX_DEPTH,
            follow_symlinks: false,
            supported_extensions: default_extensions(),
            allowlist: AllowlistConfig {
                calls: defaults::SAFE_REBUILD_CALLS
                    .iter()
                    .map(|s| s.to_string())
                    .collect(),
                issues: Vec::new(),
            },
            files: Vec::new(),
            detectors: DetectorConfig::default(),
            reporting: ReportingConfig::default(),
        }
    }
}

/// Extensions the walker treats as scannable by default.
pub fn default_extensions() -> Vec<String> {
    [
        "pkl", "pickle", "pck", "pk", "joblib", "dill", "dl", "npy", "npz", "bin", "dat", "model",
        "ckpt", "pt", "pth", "pt2", "h5", "hdf5", "keras", "pb", "onnx", "safetensors", "gguf",
        "ggml", "zip", "tar",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

impl Settings {
    /// Parse from a TOML string.
    pub fn from_toml_str(s: &str) -> Result<Settings, toml::de::Error> {
        toml::from_str(s)
    }

    /// Load from a settings file.
    pub fn from_file(path: &Path) -> std::io::Result<Result<Settings, toml::de::Error>> {
        let text = std::fs::read_to_string(path)?;
        Ok(Settings::from_toml_str(&text))
    }

    /// Serialize back to TOML.
    pub fn to_toml(&self) -> String {
        toml::to_string_pretty(self).unwrap_or_default()
    }

    /// Build the runtime [`Allowlist`] from these settings.
    pub fn build_allowlist(&self) -> Allowlist {
        let mut a = Allowlist::new();
        for c in &self.allowlist.calls {
            a.calls.insert(c.clone());
        }
        for i in &self.allowlist.issues {
            a.issue_ids.insert(i.clone());
        }
        for f in &self.files {
            a.files.push(ms_detectors::FileOverride {
                glob: f.path.clone(),
                calls: f.calls.iter().cloned().collect(),
            });
        }
        for d in &self.detectors.exclude {
            a.excluded_detectors.insert(d.clone());
        }
        a
    }

    /// Merge extra allowlist entries (e.g. from a `--allow-list` file). The file
    /// may be a full settings TOML or just an `[allowlist]` / `[[files]]`
    /// fragment (all other keys default).
    pub fn merge_allowlist_toml(&mut self, toml_text: &str) -> Result<(), toml::de::Error> {
        let extra: Settings = toml::from_str(toml_text)?;
        let mut seen: HashSet<String> = self.allowlist.calls.iter().cloned().collect();
        for c in extra.allowlist.calls {
            if seen.insert(c.clone()) {
                self.allowlist.calls.push(c);
            }
        }
        for i in extra.allowlist.issues {
            if !self.allowlist.issues.contains(&i) {
                self.allowlist.issues.push(i);
            }
        }
        self.files.extend(extra.files);
        Ok(())
    }
}

/// The default `modelscan-settings.toml` written by `create-settings-file`.
pub const DEFAULT_SETTINGS_TOML: &str = r#"# modelscan-settings.toml — lancer-modelscan configuration
#
# Generated by `lancer-modelscan create-settings-file`. Edit to tune the scan.
# All keys are optional; omitted keys fall back to built-in defaults.

# Recursive directory walk depth.
max_depth = 10
# Follow symbolic links while walking.
follow_symlinks = false

# File extensions treated as scannable (lowercase, no leading dot).
supported_extensions = [
    "pkl", "pickle", "pck", "joblib", "dill", "npy", "npz", "bin", "dat",
    "model", "ckpt", "pt", "pth", "h5", "hdf5", "keras", "pb", "onnx",
    "safetensors", "gguf",
]

[allowlist]
# Known-safe rebuild / reconstruct functions. Calls listed here never fire.
# A bare module name (e.g. "torch") permits any member of that module.
calls = [
    "numpy.core.multiarray._reconstruct",
    "numpy.ndarray",
    "numpy.dtype",
    "collections.OrderedDict",
    "torch._utils._rebuild_tensor_v2",
    "torch._utils._rebuild_parameter",
    "torch.nn.parameter.Parameter",
    "sklearn.tree._tree.Tree",
]
# Issue ids (MS-xxxx-yyyy) to suppress after manual triage.
issues = []

# Per-file overrides: extra permitted calls for files matching `path`.
# [[files]]
# path = "models/legacy/*.pkl"
# calls = ["custom.legacy.Loader"]

[detectors]
# Detector ids to disable entirely.
# Available: risky_call, suspicious_reduce, unknown_import, obfuscated_module,
#            tf_custom_op, onnx_custom_domain, keras_lambda_layer
exclude = []

[reporting]
# Default output format: console | json | html | sarif
format = "console"
# Include informational "safe" entries in the report.
include_safe = false
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_settings_seed_safe_calls() {
        let s = Settings::default();
        assert!(s.allowlist.calls.iter().any(|c| c == "numpy.ndarray"));
        assert_eq!(s.max_depth, DEFAULT_MAX_DEPTH);
    }

    #[test]
    fn default_template_parses() {
        let s = Settings::from_toml_str(DEFAULT_SETTINGS_TOML).expect("template parses");
        assert_eq!(s.max_depth, 10);
        assert!(s.allowlist.calls.iter().any(|c| c.starts_with("torch.")));
    }

    #[test]
    fn build_allowlist_from_settings() {
        let s = Settings::default();
        let a = s.build_allowlist();
        assert!(a.is_allowed_call("numpy", "ndarray", "x.pkl"));
    }
}
