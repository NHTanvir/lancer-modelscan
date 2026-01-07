//! PyO3 bindings for `lancer-modelscan`.
//!
//! This module mirrors upstream's `modelscan.modelscan.ModelScan` Python API so
//! existing modelscan callers can swap in the Rust engine with minimal churn.
//! The heavy lifting lives in [`ms_core::ModelScan`]; this crate is a thin,
//! parse-only adapter that translates between Python `str` arguments and the
//! Rust scan engine, surfacing [`ms_core::CoreError`] as `ValueError`.
//!
//! Typical usage from Python:
//!
//! ```python
//! from lancer_modelscan import ModelScan, scan_file
//!
//! scanner = ModelScan()
//! report_json = scanner.scan("model.pkl")     # JSON report string
//! issues_json = scanner.issues_json()         # JSON array of issues
//! html = scanner.generate_report("html")      # re-render the last scan
//!
//! # convenience one-shot:
//! report_json = scan_file("model.pkl")
//! ```

use ms_core::{ModelScan as CoreModelScan, ReportFormat, Settings};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyModule;

/// Convert any [`ms_core::CoreError`] into a Python `ValueError`.
fn to_py_err(err: ms_core::CoreError) -> PyErr {
    PyValueError::new_err(err.to_string())
}

/// Build a [`Settings`] from an optional TOML string, defaulting when absent.
///
/// A malformed TOML string is reported as a Python `ValueError`.
fn settings_from_opt(settings_toml: Option<String>) -> PyResult<Settings> {
    match settings_toml {
        Some(toml) => Settings::from_toml_str(&toml)
            .map_err(|e| PyValueError::new_err(format!("invalid settings TOML: {e}"))),
        None => Ok(Settings::default()),
    }
}

/// Python-facing scanner mirroring `modelscan.modelscan.ModelScan`.
///
/// Wraps an [`ms_core::ModelScan`] and caches its last scan so
/// [`ModelScan::generate_report`] and [`ModelScan::issues_json`] work after a
/// call to [`ModelScan::scan`].
#[pyclass]
struct ModelScan {
    inner: CoreModelScan,
}

#[pymethods]
impl ModelScan {
    /// Construct a scanner.
    ///
    /// `settings_toml` is an optional `modelscan-settings.toml` document; when
    /// omitted the built-in defaults (with the known-safe rebuild allowlist)
    /// are used.
    #[new]
    #[pyo3(signature = (settings_toml=None))]
    fn new(settings_toml: Option<String>) -> PyResult<Self> {
        let settings = settings_from_opt(settings_toml)?;
        Ok(ModelScan {
            inner: CoreModelScan::new(settings),
        })
    }

    /// Scan a file or directory and return the JSON report string.
    ///
    /// Mirrors upstream `ModelScan.scan(path)`; the result is cached so later
    /// calls to [`generate_report`](Self::generate_report) and
    /// [`issues_json`](Self::issues_json) reflect this scan.
    fn scan(&mut self, path: String) -> PyResult<String> {
        self.inner.scan(&path).map_err(to_py_err)?;
        self.inner
            .generate_report(&ReportFormat::Json, false)
            .map_err(to_py_err)
    }

    /// Re-render the most recent scan in the requested `format`.
    ///
    /// `format` is one of `console`/`json`/`html`/`sarif` (case-insensitive);
    /// when omitted, `console` is used. Errors (including "no scan has been run
    /// yet") are raised as `ValueError`.
    #[pyo3(signature = (format=None))]
    fn generate_report(&self, format: Option<String>) -> PyResult<String> {
        let fmt = ReportFormat::parse(format.as_deref().unwrap_or("console"));
        self.inner.generate_report(&fmt, false).map_err(to_py_err)
    }

    /// Return the issues from the most recent scan as a JSON array string.
    ///
    /// Equivalent to `json.dumps(scanner.issues)` upstream; returns `[]` before
    /// any scan has been run.
    fn issues_json(&self) -> PyResult<String> {
        serde_json::to_string(self.inner.issues())
            .map_err(|e| PyValueError::new_err(format!("failed to serialize issues: {e}")))
    }
}

/// Convenience one-shot: scan `path` with default settings and return the JSON
/// report string. Equivalent to `ModelScan().scan(path)`.
#[pyfunction]
fn scan_file(path: String) -> PyResult<String> {
    let mut scanner = CoreModelScan::with_defaults();
    scanner.scan(&path).map_err(to_py_err)?;
    scanner
        .generate_report(&ReportFormat::Json, false)
        .map_err(to_py_err)
}

/// Python module entry point.
///
/// Mirrors `modelscan.modelscan.ModelScan`: exposes the [`ModelScan`] class and
/// the [`scan_file`] convenience function, both backed by the Rust `ms-core`
/// engine. The scanner is parse-only — it never executes model content.
#[pymodule]
fn lancer_modelscan(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<ModelScan>()?;
    m.add_function(wrap_pyfunction!(scan_file, m)?)?;
    m.add("__doc__", "Rust-backed bindings mirroring modelscan.modelscan.ModelScan.")?;
    Ok(())
}
