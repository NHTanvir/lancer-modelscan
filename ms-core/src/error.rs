//! Engine-level error type.

/// Errors from the scan engine. These map to the operational exit codes in
/// [`crate::exitcode`] — they are distinct from *findings*, which are never errors.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("configuration error: {0}")]
    Config(String),
    #[error("report error: {0}")]
    Report(#[from] ms_report::ReportError),
    #[error("walk error: {0}")]
    Walk(String),
    #[error("settings parse error: {0}")]
    Settings(String),
}

impl CoreError {
    /// Operational exit code class for this error (see plan exit-code table):
    /// I/O → 5, parse → 6, config → 7. Anything else → generic internal (2).
    pub fn exit_code(&self) -> i32 {
        match self {
            CoreError::Io(_) | CoreError::Walk(_) => 5,
            CoreError::Settings(_) => 6,
            CoreError::Config(_) => 7,
            CoreError::Report(_) => 2,
        }
    }
}
