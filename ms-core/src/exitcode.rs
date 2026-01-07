//! Exit-code mapping.
//!
//! Two distinct schemes, chosen by CLI mode:
//!
//! * **Upstream parity** (default / `--cli`): binary `0` (clean) / `1` (issues)
//!   plus operational codes `2` (internal error), `3` (no supported files),
//!   `4` (invalid usage). Mirrors `protectai/modelscan` exactly.
//! * **Lancer CI** (`--ci` / `--fail-on`): severity-mapped — `None→0, Low→1,
//!   Medium→2, High→3, Critical→4` — with internal errors `5` (I/O), `6`
//!   (parse), `7` (config).

use ms_detectors::Severity;

// ----- Upstream parity codes -----
pub const OK: i32 = 0;
pub const ISSUES_FOUND: i32 = 1;
pub const INTERNAL_ERROR: i32 = 2;
pub const NO_SUPPORTED_FILES: i32 = 3;
pub const INVALID_USAGE: i32 = 4;

/// Upstream-parity exit code for a completed scan.
pub fn upstream_code(found_supported: bool, has_issues: bool) -> i32 {
    if !found_supported {
        NO_SUPPORTED_FILES
    } else if has_issues {
        ISSUES_FOUND
    } else {
        OK
    }
}

/// Lancer severity → exit code.
pub fn severity_code(sev: Severity) -> i32 {
    match sev {
        Severity::None => 0,
        Severity::Low => 1,
        Severity::Medium => 2,
        Severity::High => 3,
        Severity::Critical => 4,
    }
}

/// Lancer CI mode: if `max_severity >= fail_on`, exit with the severity code;
/// otherwise `0`. `fail_on == None` means "any finding fails".
pub fn ci_code(max_severity: Severity, fail_on: Severity) -> i32 {
    if max_severity == Severity::None {
        return 0;
    }
    let threshold = if fail_on == Severity::None {
        Severity::Low
    } else {
        fail_on
    };
    if max_severity >= threshold {
        severity_code(max_severity)
    } else {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_mapping() {
        assert_eq!(upstream_code(true, false), OK);
        assert_eq!(upstream_code(true, true), ISSUES_FOUND);
        assert_eq!(upstream_code(false, false), NO_SUPPORTED_FILES);
    }

    #[test]
    fn ci_threshold() {
        assert_eq!(ci_code(Severity::Critical, Severity::High), 4);
        assert_eq!(ci_code(Severity::Low, Severity::High), 0);
        assert_eq!(ci_code(Severity::High, Severity::High), 3);
        assert_eq!(ci_code(Severity::None, Severity::Low), 0);
    }
}
