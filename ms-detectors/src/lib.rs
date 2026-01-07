//! `ms-detectors` — turns parser [`Event`](ms_formats::Event)s into scored
//! [`Issue`]s.
//!
//! A [`Detector`] inspects one event plus the active [`Allowlist`] and either
//! suppresses it (returns `None`) or emits an `Issue` with a [`Severity`]. The
//! default detector set and the upstream-parity `unsafe_globals` table live in
//! [`defaults`].

use ms_formats::Event;

pub mod allowlist;
pub mod defaults;
pub mod detectors;
pub mod registry;

pub use allowlist::{Allowlist, FileOverride};
pub use registry::{default_detectors, DetectorRegistry};

/// Finding severity. Ordering is meaningful: `Critical` is the greatest, so
/// `max_severity` and `--fail-on` threshold comparisons use the derived `Ord`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::None => "NONE",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }

    /// Parse a severity name case-insensitively (for `--fail-on`, config).
    pub fn parse(s: &str) -> Option<Severity> {
        match s.trim().to_ascii_uppercase().as_str() {
            "NONE" => Some(Severity::None),
            "LOW" => Some(Severity::Low),
            "MEDIUM" => Some(Severity::Medium),
            "HIGH" => Some(Severity::High),
            "CRITICAL" => Some(Severity::Critical),
            _ => None,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single security finding.
///
/// `id` is a deterministic `MS-xxxx-yyyy` token derived from
/// `(file_path, source, offset, detector, module, name)` so the same finding
/// gets the same id across runs (stable allowlisting + CI diffs).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Issue {
    pub id: String,
    pub severity: Severity,
    /// Id of the detector that produced this issue.
    pub detector: String,
    /// File the issue was found in (absolute or as-scanned path).
    pub file_path: String,
    /// Logical sub-source within the file (zip member / dataset path), if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Byte offset within the parsed stream.
    pub offset: u64,
    /// Pickle opcode name, if applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
    /// Bound module (`os`) or graph domain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    /// Bound name (`system`) or graph op.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Human-readable description of why this was flagged.
    pub message: String,
}

impl Issue {
    /// Deterministic `MS-xxxx-yyyy` id from the issue's identity fields.
    pub fn make_id(
        file_path: &str,
        source: Option<&str>,
        offset: u64,
        detector: &str,
        module: Option<&str>,
        name: Option<&str>,
    ) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(file_path.as_bytes());
        h.update([0]);
        h.update(source.unwrap_or("").as_bytes());
        h.update([0]);
        h.update(offset.to_le_bytes());
        h.update(detector.as_bytes());
        h.update([0]);
        h.update(module.unwrap_or("").as_bytes());
        h.update([0]);
        h.update(name.unwrap_or("").as_bytes());
        let digest = h.finalize();
        // 8 hex chars split as MS-xxxx-xxxx
        let hex: String = digest.iter().take(4).map(|b| format!("{b:02x}")).collect();
        format!("MS-{}-{}", &hex[0..4], &hex[4..8])
    }

    /// The `module.name` pair, if both present.
    pub fn qualified(&self) -> Option<String> {
        match (&self.module, &self.name) {
            (Some(m), Some(n)) => Some(format!("{m}.{n}")),
            _ => None,
        }
    }
}

/// Outcome of a detector evaluating an event.
pub enum Verdict {
    /// Not interesting to this detector.
    Ignore,
    /// A finding (will still be allowlist-suppressed downstream if permitted).
    Flag(Issue),
}

/// A detector scores a single event against the allowlist.
///
/// Detectors must be pure & `Send + Sync` so `ms-core` can run them across
/// files in parallel. They never do I/O.
pub trait Detector: Send + Sync {
    /// Stable detector id (e.g. `"risky_call"`).
    fn id(&self) -> &str;

    /// Evaluate one event. `file_path`/`source` are passed so the detector can
    /// build a stable issue id and honor per-file allowlist overrides.
    fn evaluate(
        &self,
        event: &Event,
        allowlist: &Allowlist,
        file_path: &str,
    ) -> Option<Issue>;
}
