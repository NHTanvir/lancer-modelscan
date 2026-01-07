//! Shared scan context: settings + the detector registry. Built once per
//! [`ModelScan`](crate::ModelScan); a fresh [`Allowlist`](ms_detectors::Allowlist)
//! is derived per scan so hit counts are per-run.

use crate::settings::Settings;
use ms_detectors::{Allowlist, DetectorRegistry};

/// Everything the scan pipeline needs that's stable across files.
pub struct ScanContext {
    pub settings: Settings,
    pub registry: DetectorRegistry,
}

impl ScanContext {
    pub fn from_settings(settings: Settings) -> Self {
        ScanContext {
            settings,
            registry: DetectorRegistry::defaults(),
        }
    }

    /// Build a fresh allowlist from the current settings.
    pub fn build_allowlist(&self) -> Allowlist {
        self.settings.build_allowlist()
    }
}
