//! The default detector set.
//!
//! Each detector inspects one [`Event`] plus the [`Allowlist`] and emits an
//! [`Issue`] or nothing. Severity assignment follows the plan's taxonomy:
//!
//! * `risky_call`        — a global in the unsafe table (CRITICAL/HIGH). Core
//!   upstream behavior.
//! * `suspicious_reduce` — a REDUCE/NEWOBJ/BUILD bound to a `__main__` or
//!   dynamically-constructed callable (MEDIUM).
//! * `unknown_import`    — a GLOBAL referencing a module neither known-safe nor
//!   known-dangerous (LOW, Lancer extension — dropped in `--strict-parity`).
//! * `obfuscated_module` — module/name/string that looks constructed via
//!   `chr()`/escapes (LOW, Lancer extension).
//! * `tf_custom_op`      — TensorFlow PyFunc / file ops / unknown custom op.
//! * `onnx_custom_domain`— ONNX node outside the builtin domains (MEDIUM).
//! * `keras_lambda_layer`— a Keras `Lambda` layer body (MEDIUM, or CRITICAL via
//!   `risky_call` if the marshal walk surfaced a dangerous global).

use crate::defaults;
use crate::{Allowlist, Detector, Issue, Severity};
use ms_formats::{Event, PickleOpcode};

/// Build an [`Issue`] with a deterministic id.
fn issue(
    severity: Severity,
    detector: &str,
    event: &Event,
    file_path: &str,
    message: String,
) -> Issue {
    let module = event.target_module.clone().or_else(|| event.graph_domain.clone());
    let name = event.target_name.clone().or_else(|| event.graph_op.clone());
    let operator = event.opcode.map(|o| o.name().to_string());
    let id = Issue::make_id(
        file_path,
        event.source.as_deref(),
        event.offset,
        detector,
        module.as_deref(),
        name.as_deref(),
    );
    Issue {
        id,
        severity,
        detector: detector.to_string(),
        file_path: file_path.to_string(),
        source: event.source.clone(),
        offset: event.offset,
        operator,
        module,
        name,
        message,
    }
}

/// Does a string look obfuscated (constructed at runtime rather than a literal
/// dotted identifier)?
fn looks_obfuscated(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let constructs = ["chr(", "\\x", "getattr(", "+chr", "base64", "fromhex", "decode("];
    if constructs.iter().any(|c| s.contains(c)) {
        return true;
    }
    // A module/name that is not a clean dotted identifier is suspicious.
    !s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
}

// ----------------------------------------------------------------------------

/// CRITICAL/HIGH globals from the unsafe table.
pub struct RiskyCall;

impl Detector for RiskyCall {
    fn id(&self) -> &str {
        "risky_call"
    }

    fn evaluate(&self, event: &Event, allowlist: &Allowlist, file_path: &str) -> Option<Issue> {
        let module = event.target_module.as_deref()?;
        let name = event.target_name.as_deref()?;
        let severity = defaults::severity_for(module, name)?;
        if allowlist.is_allowed_call(module, name, file_path) {
            return None;
        }
        let op = event
            .opcode
            .map(|o| o.name())
            .unwrap_or("GLOBAL");
        let message = format!(
            "Unsafe global `{module}.{name}` referenced via {op}: can {} on load.",
            match severity {
                Severity::Critical => "execute arbitrary code",
                _ => "perform file/network I/O for exfiltration",
            }
        );
        Some(issue(severity, self.id(), event, file_path, message))
    }
}

/// REDUCE/NEWOBJ/BUILD bound to a `__main__` or dynamically-defined callable.
pub struct SuspiciousReduce;

impl Detector for SuspiciousReduce {
    fn id(&self) -> &str {
        "suspicious_reduce"
    }

    fn evaluate(&self, event: &Event, allowlist: &Allowlist, file_path: &str) -> Option<Issue> {
        // Fires on any global reference (GLOBAL/STACK_GLOBAL/INST/OBJ) — the
        // pickle walker emits one event per global, so we don't depend on
        // tracking the REDUCE consumption separately.
        let opcode = event.opcode?;
        let module = event.target_module.as_deref()?;
        let name = event.target_name.as_deref()?;
        // Known-dangerous is handled by risky_call; known-safe by the allowlist.
        if defaults::severity_for(module, name).is_some() {
            return None;
        }
        if allowlist.is_allowed_call(module, name, file_path) {
            return None;
        }
        // The classic backdoor pattern: a callable living in __main__ or built
        // dynamically, bound to a code-triggering global reference.
        let suspicious = module == "__main__"
            || module.is_empty()
            || module.starts_with("__main__.")
            || looks_obfuscated(module)
            || looks_obfuscated(name);
        if suspicious {
            let message = format!(
                "{} bound to non-standard callable `{module}.{name}` \
                 (not a known-safe rebuild function).",
                opcode.name()
            );
            Some(issue(Severity::Medium, self.id(), event, file_path, message))
        } else {
            None
        }
    }
}

/// A GLOBAL referencing a module neither known-safe nor known-dangerous.
/// Lancer LOW extension — suppressed in `--strict-parity`.
pub struct UnknownImport;

impl Detector for UnknownImport {
    fn id(&self) -> &str {
        "unknown_import"
    }

    fn evaluate(&self, event: &Event, allowlist: &Allowlist, file_path: &str) -> Option<Issue> {
        let opcode = event.opcode?;
        if !matches!(opcode, PickleOpcode::Global | PickleOpcode::StackGlobal) {
            return None;
        }
        let module = event.target_module.as_deref()?;
        let name = event.target_name.as_deref()?;
        if defaults::severity_for(module, name).is_some() {
            return None; // dangerous → risky_call
        }
        if allowlist.is_allowed_call(module, name, file_path) {
            return None; // known-safe
        }
        let message = format!(
            "Unlisted global import `{module}.{name}` (not in the known-safe \
             allowlist). Review and allowlist if expected."
        );
        Some(issue(Severity::Low, self.id(), event, file_path, message))
    }
}

/// Module/name/string constructed via chr()/escape obfuscation.
pub struct ObfuscatedModule;

impl Detector for ObfuscatedModule {
    fn id(&self) -> &str {
        "obfuscated_module"
    }

    fn evaluate(&self, event: &Event, allowlist: &Allowlist, file_path: &str) -> Option<Issue> {
        // Check the bound module/name and any raw embedded string.
        let candidates: Vec<&str> = [
            event.target_module.as_deref(),
            event.target_name.as_deref(),
            event.raw_string.as_deref(),
        ]
        .into_iter()
        .flatten()
        .collect();
        let hit = candidates.iter().find(|s| looks_obfuscated(s))?;
        if let (Some(m), Some(n)) = (&event.target_module, &event.target_name) {
            if allowlist.is_allowed_call(m, n, file_path) {
                return None;
            }
        }
        let message = format!(
            "Possible obfuscation detected in `{hit}` — name appears constructed \
             at runtime rather than a literal identifier."
        );
        Some(issue(Severity::Low, self.id(), event, file_path, message))
    }
}

/// TensorFlow custom op: PyFunc / file ops (severity from table) or an unknown
/// non-builtin op (MEDIUM).
pub struct TfCustomOp;

impl Detector for TfCustomOp {
    fn id(&self) -> &str {
        "tf_custom_op"
    }

    fn evaluate(&self, event: &Event, _allowlist: &Allowlist, file_path: &str) -> Option<Issue> {
        // Only graph-op events without a pickle opcode and without an ONNX domain.
        let op = event.graph_op.as_deref()?;
        if event.opcode.is_some() {
            return None;
        }
        if event.graph_domain.is_some() {
            return None; // ONNX path
        }
        if let Some(sev) = defaults::tf_op_severity(op) {
            let message = format!(
                "TensorFlow op `{op}` embeds Python / performs I/O and can run \
                 arbitrary code on graph load."
            );
            return Some(issue(sev, self.id(), event, file_path, message));
        }
        if !defaults::is_tf_known_op(op) {
            let message = format!(
                "Unknown TensorFlow custom op `{op}` outside the known-safe op set."
            );
            return Some(issue(Severity::Medium, self.id(), event, file_path, message));
        }
        None
    }
}

/// ONNX node in a non-builtin domain.
pub struct OnnxCustomDomain;

impl Detector for OnnxCustomDomain {
    fn id(&self) -> &str {
        "onnx_custom_domain"
    }

    fn evaluate(&self, event: &Event, _allowlist: &Allowlist, file_path: &str) -> Option<Issue> {
        let domain = event.graph_domain.as_deref()?;
        if defaults::is_onnx_builtin_domain(domain) {
            return None;
        }
        let op = event.graph_op.as_deref().unwrap_or("<op>");
        let message = format!(
            "ONNX node `{op}` declares custom domain `{domain}` — a custom \
             runtime may execute domain-specific ops."
        );
        Some(issue(Severity::Medium, self.id(), event, file_path, message))
    }
}

/// A Keras `Lambda` layer body (arbitrary code surface).
pub struct KerasLambdaLayer;

impl Detector for KerasLambdaLayer {
    fn id(&self) -> &str {
        "keras_lambda_layer"
    }

    fn evaluate(&self, event: &Event, _allowlist: &Allowlist, file_path: &str) -> Option<Issue> {
        // The Keras/HDF5 parser emits a raw_string event for each Lambda body
        // and tags note = "keras_lambda". A dangerous global found inside the
        // marshalled code is emitted separately (handled by risky_call).
        let raw = event.raw_string.as_deref()?;
        if event.opcode.is_some() || event.graph_op.is_some() {
            return None;
        }
        let is_lambda = event
            .note
            .as_deref()
            .map(|n| n.contains("lambda"))
            .unwrap_or(true);
        if !is_lambda {
            return None;
        }
        let preview: String = raw.chars().take(80).collect();
        let message = format!(
            "Keras Lambda layer carries an embedded function body \
             (arbitrary code surface): `{preview}`"
        );
        Some(issue(Severity::Medium, self.id(), event, file_path, message))
    }
}
