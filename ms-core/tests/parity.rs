//! End-to-end parity tests for the `ms-core` scan engine.
//!
//! Each test crafts its own fixture as a byte buffer written into a fresh
//! [`tempfile::tempdir`], so nothing binary is committed to the repo. Fixtures
//! are *parse-only* by construction — we only ever read/walk bytes; no model
//! content is executed.

use std::fs;
use std::path::Path;

use ms_core::{ModelScan, ReportFormat, Severity};

// ---------------------------------------------------------------------------
// fixture crafting helpers (local to this test file)

/// `GLOBAL os system` + BINUNICODE arg + TUPLE1 + REDUCE + STOP, protocol 2.
///
/// This mirrors `ms-formats`' pickle test helper: the classic
/// `os.system("...")` arbitrary-code-execution payload.
fn os_system_pickle() -> Vec<u8> {
    let mut p = vec![0x80, 0x02]; // PROTO 2
    p.extend_from_slice(b"cos\nsystem\n"); // GLOBAL os.system
    p.extend_from_slice(&[b'q', 0x00]); // BINPUT 0
    let arg = b"echo pwned";
    p.push(b'X'); // BINUNICODE
    p.extend_from_slice(&(arg.len() as u32).to_le_bytes());
    p.extend_from_slice(arg);
    p.push(0x85); // TUPLE1
    p.push(b'R'); // REDUCE
    p.push(b'.'); // STOP
    p
}

/// `GLOBAL numpy.core.multiarray _reconstruct` + STOP, protocol 2.
///
/// `numpy.core.multiarray._reconstruct` is in the default safe-rebuild
/// allowlist, so a clean numpy array pickle must produce no findings.
fn numpy_rebuild_pickle() -> Vec<u8> {
    let mut p = vec![0x80, 0x02]; // PROTO 2
    p.extend_from_slice(b"cnumpy.core.multiarray\n_reconstruct\n"); // GLOBAL
    p.extend_from_slice(&[b'q', 0x00]); // BINPUT 0
    p.push(b'.'); // STOP
    p
}

/// Minimal safetensors file: 8-byte LE header length + a small JSON object.
fn minimal_safetensors(header_json: &str) -> Vec<u8> {
    let header = header_json.as_bytes();
    let mut out = Vec::new();
    out.extend_from_slice(&(header.len() as u64).to_le_bytes());
    out.extend_from_slice(header);
    out
}

/// Write `bytes` to `dir/name` and return the path.
fn write_fixture(dir: &Path, name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let path = dir.join(name);
    fs::write(&path, bytes).expect("write fixture");
    path
}

// ---------------------------------------------------------------------------
// tests

#[test]
fn malicious_pickle_is_critical() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = write_fixture(tmp.path(), "evil.pkl", &os_system_pickle());

    let mut scanner = ModelScan::with_defaults();
    let result = scanner.scan(&path).expect("scan");

    assert!(result.has_issues(), "malicious pickle should produce issues");
    assert_eq!(result.max_severity(), Severity::Critical);

    let hit = result
        .all_issues()
        .iter()
        .find(|i| i.module.as_deref() == Some("os") && i.name.as_deref() == Some("system"))
        .expect("expected an os.system issue");
    assert_eq!(hit.severity, Severity::Critical);
    assert_eq!(hit.module.as_deref(), Some("os"));
    assert_eq!(hit.name.as_deref(), Some("system"));
}

#[test]
fn numpy_rebuild_is_allowlisted() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = write_fixture(tmp.path(), "weights.pkl", &numpy_rebuild_pickle());

    let mut scanner = ModelScan::with_defaults();
    let result = scanner.scan(&path).expect("scan");

    assert!(
        !result.has_issues(),
        "numpy._reconstruct is allowlisted by default; got {:?}",
        result.all_issues()
    );
    assert_eq!(result.max_severity(), Severity::None);
    // The file was still recognized and parsed.
    assert!(result.found_supported);
}

#[test]
fn safetensors_is_clean() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let bytes = minimal_safetensors(r#"{"__metadata__":{}}"#);
    let path = write_fixture(tmp.path(), "model.safetensors", &bytes);

    let mut scanner = ModelScan::with_defaults();
    let result = scanner.scan(&path).expect("scan");

    assert_eq!(
        result.all_issues().len(),
        0,
        "safetensors is safe-by-construction; got {:?}",
        result.all_issues()
    );
    assert!(
        result.found_supported,
        "the safetensors parser should have claimed the file"
    );
}

#[test]
fn exit_codes() {
    use ms_core::exitcode;

    assert_eq!(exitcode::upstream_code(true, false), 0);
    assert_eq!(exitcode::upstream_code(true, true), 1);
    assert_eq!(exitcode::upstream_code(false, false), 3);

    assert_eq!(exitcode::ci_code(Severity::Critical, Severity::High), 4);
}

#[test]
fn json_report_roundtrips() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = write_fixture(tmp.path(), "evil.pkl", &os_system_pickle());

    let mut scanner = ModelScan::with_defaults();
    let _ = scanner.scan(&path).expect("scan");

    let json = scanner
        .generate_report(&ReportFormat::Json, false)
        .expect("render json report");

    let v: serde_json::Value = serde_json::from_str(&json).expect("report is valid JSON");
    let total = v["summary"]["total_issues"]
        .as_u64()
        .expect("summary.total_issues is a number");
    assert!(
        total >= 1,
        "expected at least one issue in the JSON summary, got {total}"
    );
}
