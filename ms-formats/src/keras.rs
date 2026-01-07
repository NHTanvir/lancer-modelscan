//! Best-effort Keras model scanner — focuses on the `Lambda` layer (plan §3).
//!
//! Keras serializes models either as a `.keras` zip archive (config JSON + weight
//! shards) or as a legacy `.h5`/HDF5 file with the model config stored as a JSON
//! string. A `Lambda` layer carries an *arbitrary Python function*: in modern
//! Keras `config.function` is plain source text, but historically it has been a
//! `[base64(marshalled __code__), defaults, closure]` triple. Either form lets a
//! model run code at load time, which is exactly what we want to surface.
//!
//! This parser is **heuristic / best-effort**, not a faithful HDF5 or Keras
//! deserializer (a full pure-Rust HDF5 parser is out of scope). For HDF5 we
//! locate the embedded `model_config` JSON by scanning raw bytes; we never
//! decode the HDF5 structure. We parse JSON leniently and, on any failure, fall
//! back to a substring scan for `Lambda`. Marshalled `__code__` is inspected via
//! [`crate::marshal::scan`], which decodes the byte stream symbolically —
//! **nothing is ever executed, imported, or unmarshalled into live objects.**

use std::io::Read;
use std::path::Path;

use base64::Engine;
use serde_json::Value;

use crate::{Event, Limits, ParseError, Parser};

/// Magic for a ZIP container (`.keras` archives are zips).
const ZIP_MAGIC: [u8; 4] = [b'P', b'K', 0x03, 0x04];

/// Extensions Keras files use.
const KERAS_EXTENSIONS: &[&str] = &["keras", "h5", "hdf5"];

/// Candidate config members inside a `.keras` zip, in priority order.
const CONFIG_MEMBERS: &[&str] = &["config.json", "model.json", "metadata.json"];

/// Max length of a Lambda `function` preview we keep in an event.
const PREVIEW_MAX: usize = 256;

/// Modules whose presence in a Lambda's `co_names` signals danger.
const DANGEROUS_MODULES: &[&str] = &[
    "os",
    "subprocess",
    "sys",
    "posix",
    "nt",
    "socket",
    "builtins",
    "importlib",
    "pty",
    "commands",
    "shutil",
    "ctypes",
];

/// Callable names whose presence signals danger.
const DANGEROUS_NAMES: &[&str] = &[
    "system",
    "popen",
    "exec",
    "eval",
    "compile",
    "spawn",
    "spawnl",
    "Popen",
    "run",
    "call",
    "check_output",
    "getoutput",
    "fromhex",
];

/// Builtin names that are critical on their own (code-eval primitives).
const BUILTIN_CRITICAL: &[&str] = &["exec", "eval", "compile"];

/// Parse-only, heuristic Keras `Lambda` scanner.
pub struct KerasParser;

impl Parser for KerasParser {
    fn id(&self) -> &str {
        "keras"
    }

    fn can_handle(&self, path: &Path, magic: &[u8]) -> bool {
        if magic.starts_with(&crate::hdf5::HDF5_MAGIC) {
            return true;
        }
        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.to_ascii_lowercase());
        if let Some(ext) = ext.as_deref() {
            // A bare zip only counts as Keras when it carries the .keras ext.
            if magic.starts_with(&ZIP_MAGIC) && ext == "keras" {
                return true;
            }
            return KERAS_EXTENSIONS.contains(&ext);
        }
        false
    }

    fn parse_path(&self, path: &Path, limits: &Limits) -> Result<Vec<Event>, ParseError> {
        // (a) Obtain the model config JSON text.
        let config = read_config_text(path, limits)?;
        let config = match config {
            Some(c) => c,
            None => return Ok(Vec::new()),
        };
        Ok(scan_config(&config, limits))
    }
}

/// Read the model config JSON text from either a `.keras` zip or an HDF5 file.
fn read_config_text(path: &Path, limits: &Limits) -> Result<Option<String>, ParseError> {
    let magic = read_magic_bytes(path, 8)?;
    if magic.starts_with(&ZIP_MAGIC) {
        return read_zip_config(path);
    }
    // HDF5 (or anything else): read capped bytes and locate the JSON blob.
    let bytes = read_capped(path, limits.max_member_bytes)?;
    Ok(extract_embedded_config(&bytes))
}

/// Read the first `n` bytes of a file (best effort).
fn read_magic_bytes(path: &Path, n: usize) -> Result<Vec<u8>, ParseError> {
    let mut f = std::fs::File::open(path)?;
    crate::read_magic(&mut f, n).map_err(ParseError::from)
}

/// Read up to `cap` bytes from a file. Only raw bytes are inspected.
fn read_capped(path: &Path, cap: u64) -> Result<Vec<u8>, ParseError> {
    let f = std::fs::File::open(path)?;
    let mut limited = f.take(cap);
    let mut buf = Vec::new();
    limited.read_to_end(&mut buf)?;
    Ok(buf)
}

/// Open a `.keras` zip and read the first available config member.
fn read_zip_config(path: &Path) -> Result<Option<String>, ParseError> {
    let f = std::fs::File::open(path)?;
    let mut archive = zip::ZipArchive::new(f).map_err(|e| ParseError::Zip(e.to_string()))?;
    for member in CONFIG_MEMBERS {
        // A missing member is fine — try the next candidate. Only surface a
        // genuine read failure on a member that does exist.
        match archive.by_name(member) {
            Ok(mut entry) => {
                let mut s = String::new();
                entry.read_to_string(&mut s)?;
                return Ok(Some(s));
            }
            Err(_) => continue,
        }
    }
    Ok(None)
}

/// Locate an embedded `model_config` JSON object inside raw HDF5 bytes by
/// finding a `"class_name"` marker and extracting the smallest enclosing
/// balanced-brace region. Best-effort: returns `None` if nothing plausible.
fn extract_embedded_config(bytes: &[u8]) -> Option<String> {
    let marker = b"\"class_name\"";
    let at = find_ascii(bytes, marker)?;
    // Walk backwards to the nearest `{` that opens a region enclosing `at`.
    let open = find_enclosing_open(bytes, at)?;
    let close = match_closing(bytes, open)?;
    let region = &bytes[open..=close];
    Some(String::from_utf8_lossy(region).into_owned())
}

/// First index of `needle` within `hay`.
fn find_ascii(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Find an opening `{` at or before `at` whose matching `}` lies at or after
/// `at`. We scan backward, and for each candidate `{` test that it balances
/// past `at` — yielding the smallest enclosing object.
fn find_enclosing_open(bytes: &[u8], at: usize) -> Option<usize> {
    let mut i = at;
    loop {
        if bytes[i] == b'{' {
            if let Some(close) = match_closing(bytes, i) {
                if close >= at {
                    return Some(i);
                }
            }
        }
        if i == 0 {
            return None;
        }
        i -= 1;
    }
}

/// Given an opening-brace index, return the index of its matching `}`, honoring
/// JSON string literals (so braces inside strings don't count). `None` if the
/// braces never balance within the buffer.
fn match_closing(bytes: &[u8], open: usize) -> Option<usize> {
    let mut depth = 0i64;
    let mut in_str = false;
    let mut escaped = false;
    let mut i = open;
    while i < bytes.len() {
        let b = bytes[i];
        if in_str {
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_str = false;
            }
        } else {
            match b {
                b'"' => in_str = true,
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(i);
                    }
                }
                _ => {}
            }
        }
        i += 1;
    }
    None
}

/// Scan a model config: parse JSON and walk for `Lambda` layers; fall back to a
/// substring scan if the JSON does not parse.
fn scan_config(config: &str, limits: &Limits) -> Vec<Event> {
    let mut events = Vec::new();
    match serde_json::from_str::<Value>(config) {
        Ok(value) => walk_for_lambda(&value, limits, &mut events),
        Err(_) => {
            // Lenient fallback: if we cannot parse, at least flag a present
            // Lambda layer so the file is not silently cleared.
            if find_ascii(config.as_bytes(), b"Lambda").is_some() {
                let mut ev = Event::source_string(
                    truncate("Lambda layer present (config JSON unparsable)"),
                    0,
                );
                ev.note = Some("keras_lambda".to_string());
                ev.source = Some("keras_lambda".to_string());
                events.push(ev);
            }
        }
    }
    events
}

/// Recursively walk a JSON value, handling every object whose
/// `"class_name" == "Lambda"`.
fn walk_for_lambda(value: &Value, limits: &Limits, events: &mut Vec<Event>) {
    match value {
        Value::Object(map) => {
            if map.get("class_name").and_then(Value::as_str) == Some("Lambda") {
                let config = map.get("config");
                handle_lambda(config, limits, events);
            }
            for v in map.values() {
                walk_for_lambda(v, limits, events);
            }
        }
        Value::Array(items) => {
            for v in items {
                walk_for_lambda(v, limits, events);
            }
        }
        _ => {}
    }
}

/// Emit the source_string preview event for a Lambda and, if its `function`
/// field carries base64 marshalled code, decode + harvest dangerous targets.
fn handle_lambda(config: Option<&Value>, limits: &Limits, events: &mut Vec<Event>) {
    let function = config.and_then(|c| c.get("function"));

    // (c) Always emit one source_string event describing the function field.
    let preview = match function {
        Some(f) => truncate(&stringify_function(f)),
        None => truncate("Lambda layer (no function field)"),
    };
    let mut ev = Event::source_string(preview, 0);
    ev.note = Some("keras_lambda".to_string());
    ev.source = Some("keras_lambda".to_string());
    events.push(ev);

    // Gather candidate base64 strings: the function may be a JSON string, or an
    // array whose first element is a base64 marshalled __code__ blob.
    let mut candidates: Vec<String> = Vec::new();
    match function {
        Some(Value::String(s)) => candidates.push(s.clone()),
        Some(Value::Array(items)) => {
            for item in items {
                if let Value::String(s) = item {
                    candidates.push(s.clone());
                }
            }
        }
        _ => {}
    }

    for cand in &candidates {
        if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(cand.as_bytes()) {
            if decoded.is_empty() {
                continue;
            }
            let scan = crate::marshal::scan(&decoded, limits);
            escalate_from_names(&scan.names, events);
        }
    }
}

/// Pair harvested marshal `co_names` into dangerous `module.name` targets and
/// emit risky-call events for the detector layer to escalate.
fn escalate_from_names(names: &[String], events: &mut Vec<Event>) {
    let module = names.iter().find(|n| DANGEROUS_MODULES.contains(&n.as_str()));
    let name = names.iter().find(|n| DANGEROUS_NAMES.contains(&n.as_str()));

    if let (Some(module), Some(name)) = (module, name) {
        events.push(risky_call(module, name));
    }

    // A code-eval builtin (exec/eval/compile) is dangerous on its own; attribute
    // it to `builtins` so the risky-call detector flags it even without a
    // separate dangerous module token.
    for n in names {
        if BUILTIN_CRITICAL.contains(&n.as_str()) {
            events.push(risky_call("builtins", n));
        }
    }
}

/// Build a risky-call event: a `module.name` target with no opcode and the
/// `keras_lambda` source tag, which the risky_call detector escalates.
fn risky_call(module: &str, name: &str) -> Event {
    Event {
        target_module: Some(module.to_string()),
        target_name: Some(name.to_string()),
        source: Some("keras_lambda".to_string()),
        ..Default::default()
    }
}

/// Render a `function` JSON field to a compact string for previews.
fn stringify_function(f: &Value) -> String {
    match f {
        Value::String(s) => s.clone(),
        other => serde_json::to_string(other).unwrap_or_else(|_| other.to_string()),
    }
}

/// Truncate a preview string to [`PREVIEW_MAX`] chars (char-boundary safe).
fn truncate(s: &str) -> String {
    if s.chars().count() <= PREVIEW_MAX {
        return s.to_string();
    }
    let mut out: String = s.chars().take(PREVIEW_MAX).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_string_lambda_emits_source_string() {
        let config = r#"{
            "class_name": "Sequential",
            "config": {
                "layers": [
                    {
                        "class_name": "Lambda",
                        "config": { "name": "lam", "function": "x: x+1" }
                    }
                ]
            }
        }"#;
        let events = scan_config(config, &Limits::default());
        assert!(
            events
                .iter()
                .any(|e| e.raw_string.is_some() && e.note.as_deref() == Some("keras_lambda")),
            "expected at least one keras_lambda source_string event, got {events:?}",
        );
    }

    #[test]
    fn unparsable_config_with_lambda_falls_back() {
        // Not valid JSON, but mentions Lambda.
        let config = "garbage { class_name: Lambda function: do_evil ";
        let events = scan_config(config, &Limits::default());
        assert!(events
            .iter()
            .any(|e| e.note.as_deref() == Some("keras_lambda")));
    }

    #[test]
    fn no_lambda_no_events() {
        let config = r#"{ "class_name": "Dense", "config": { "units": 10 } }"#;
        assert!(scan_config(config, &Limits::default()).is_empty());
    }

    #[test]
    fn dangerous_marshalled_names_escalate() {
        // Build a tiny marshal buffer carrying SHORT_ASCII_INTERNED "os" and
        // "system", base64-encode it, and feed it as the Lambda function array.
        let mut marshal = Vec::new();
        marshal.push(b'Z'); // TYPE_SHORT_ASCII_INTERNED
        marshal.push(2);
        marshal.extend_from_slice(b"os");
        marshal.push(b'Z');
        marshal.push(6);
        marshal.extend_from_slice(b"system");
        let b64 = base64::engine::general_purpose::STANDARD.encode(&marshal);

        let config = format!(
            r#"{{ "class_name": "Lambda",
                  "config": {{ "function": ["{b64}", null, null] }} }}"#
        );
        let events = scan_config(&config, &Limits::default());

        // One preview event plus one escalated os.system risky-call.
        assert!(events
            .iter()
            .any(|e| e.note.as_deref() == Some("keras_lambda")));
        assert!(
            events.iter().any(|e| {
                e.target_module.as_deref() == Some("os")
                    && e.target_name.as_deref() == Some("system")
                    && e.opcode.is_none()
                    && e.source.as_deref() == Some("keras_lambda")
            }),
            "expected an escalated os.system event, got {events:?}",
        );
    }

    #[test]
    fn builtin_critical_escalates() {
        let mut marshal = Vec::new();
        marshal.push(b'Z');
        marshal.push(4);
        marshal.extend_from_slice(b"exec");
        let b64 = base64::engine::general_purpose::STANDARD.encode(&marshal);
        let config = format!(
            r#"{{ "class_name": "Lambda", "config": {{ "function": "{b64}" }} }}"#
        );
        let events = scan_config(&config, &Limits::default());
        assert!(events.iter().any(|e| {
            e.target_module.as_deref() == Some("builtins")
                && e.target_name.as_deref() == Some("exec")
        }));
    }

    #[test]
    fn extract_embedded_config_balances_braces() {
        let bytes =
            br#"....prefix{"name":"net","layers":[{"class_name":"Lambda"}]}suffix...."#;
        let json = extract_embedded_config(bytes).expect("should find config");
        // Round-trips as valid JSON.
        let v: Value = serde_json::from_str(&json).expect("valid json");
        assert!(v.get("layers").is_some());
    }

    #[test]
    fn can_handle_keras_zip_and_h5() {
        let p = KerasParser;
        assert!(p.can_handle(Path::new("m.keras"), &ZIP_MAGIC));
        assert!(p.can_handle(Path::new("m.h5"), &crate::hdf5::HDF5_MAGIC));
        // Bare zip without .keras extension is not ours.
        assert!(!p.can_handle(Path::new("archive.zip"), &ZIP_MAGIC));
    }
}
