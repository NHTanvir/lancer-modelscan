//! `safetensors` — a SAFE-by-construction baseline parser.
//!
//! The safetensors format stores tensors as raw bytes prefixed by a JSON
//! header; it has no opcodes, no callables, and no embedded code. There is
//! nothing to execute on load, so this parser never produces an [`Event`]. It
//! exists so the scanner can *positively recognize* the format (and validate
//! that the header is well-formed) rather than falling through to a riskier
//! pickle/zip guess.
//!
//! Format reference: the first 8 bytes are a little-endian `u64` header length
//! `N`; the next `N` bytes are a UTF-8 JSON object describing each tensor. We
//! read only the header — never the tensor payload.

use std::fs::File;
use std::io::Read as _;
use std::path::Path;

use crate::{read_magic, Event, Limits, ParseError, Parser};

/// Upper bound on the JSON header length we trust as a safetensors signature.
/// Real headers are kilobytes; 100 MB is generous while still rejecting random
/// files whose first 8 bytes happen to decode to an absurd length.
const MAX_HEADER_LEN: u64 = 100_000_000;

/// The ASCII `{` that opens the JSON header object.
const JSON_OPEN_BRACE: u8 = 0x7b;

/// Parse-only parser for the safetensors format.
pub struct SafetensorsParser;

impl Parser for SafetensorsParser {
    fn id(&self) -> &str {
        "safetensors"
    }

    fn can_handle(&self, path: &Path, magic: &[u8]) -> bool {
        if has_extension(path, "safetensors") {
            return true;
        }
        // Headerless signature: 8-byte LE length in a sane range, immediately
        // followed by a JSON-opening brace at offset 8.
        if magic.len() >= 9 {
            let n = u64::from_le_bytes(magic[..8].try_into().expect("8 bytes"));
            if n > 0 && n < MAX_HEADER_LEN && magic[8] == JSON_OPEN_BRACE {
                return true;
            }
        }
        false
    }

    fn parse_path(&self, path: &Path, _limits: &Limits) -> Result<Vec<Event>, ParseError> {
        let mut file = File::open(path)?;

        // Read the 8-byte little-endian header length.
        let mut len_buf = [0u8; 8];
        file.read_exact(&mut len_buf)
            .map_err(|_| ParseError::malformed("safetensors", "truncated header length prefix"))?;
        let header_len = u64::from_le_bytes(len_buf);

        if header_len == 0 {
            return Err(ParseError::malformed("safetensors", "zero-length header"));
        }
        if header_len >= MAX_HEADER_LEN {
            return Err(ParseError::malformed(
                "safetensors",
                format!("header length {header_len} exceeds sane bound"),
            ));
        }

        // Read exactly the header bytes — never the tensor data that follows.
        let mut header = vec![0u8; header_len as usize];
        file.read_exact(&mut header).map_err(|_| {
            ParseError::malformed("safetensors", "header truncated before declared length")
        })?;

        // The header must be a JSON object.
        let value: serde_json::Value = serde_json::from_slice(&header)
            .map_err(|e| ParseError::malformed("safetensors", format!("invalid JSON header: {e}")))?;
        if !value.is_object() {
            return Err(ParseError::malformed(
                "safetensors",
                "JSON header is not an object",
            ));
        }

        // Valid header, nothing executable: SAFE by construction.
        Ok(Vec::new())
    }
}

/// Case-insensitive file-extension check.
fn has_extension(path: &Path, ext: &str) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case(ext))
        .unwrap_or(false)
}

/// Sniff the leading magic bytes of a reader for [`SafetensorsParser::can_handle`].
/// Exposed as a small helper so callers/tests can reuse the same logic the
/// scanner driver applies before dispatching.
pub fn sniff_magic<R: std::io::Read>(reader: &mut R) -> std::io::Result<Vec<u8>> {
    read_magic(reader, 9)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn write_temp(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("ms_safetensors_{name}_{}", std::process::id()));
        let mut f = File::create(&p).expect("create temp");
        f.write_all(bytes).expect("write temp");
        p
    }

    /// Build a minimal safetensors file: 8-byte LE length + `{}` JSON header.
    fn minimal_file(header_json: &str) -> Vec<u8> {
        let header = header_json.as_bytes();
        let mut out = Vec::new();
        out.extend_from_slice(&(header.len() as u64).to_le_bytes());
        out.extend_from_slice(header);
        out
    }

    #[test]
    fn id_is_safetensors() {
        assert_eq!(SafetensorsParser.id(), "safetensors");
    }

    #[test]
    fn valid_empty_header_yields_zero_events() {
        let bytes = minimal_file("{}");
        let path = write_temp("empty", &bytes);
        let events = SafetensorsParser
            .parse_path(&path, &Limits::default())
            .expect("valid header parses");
        assert!(events.is_empty(), "safetensors must never emit events");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn valid_populated_header_yields_zero_events() {
        // A realistic header object plus trailing "tensor data" we must ignore.
        let mut bytes = minimal_file(r#"{"weight":{"dtype":"F32","shape":[2],"data_offsets":[0,8]}}"#);
        bytes.extend_from_slice(&[0xAA; 8]); // fake tensor payload
        let path = write_temp("populated", &bytes);
        let events = SafetensorsParser
            .parse_path(&path, &Limits::default())
            .expect("valid header parses");
        assert!(events.is_empty());
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn can_handle_by_extension() {
        let p = Path::new("model.safetensors");
        assert!(SafetensorsParser.can_handle(p, &[]));
        assert!(SafetensorsParser.can_handle(Path::new("model.SAFETENSORS"), &[]));
    }

    #[test]
    fn can_handle_by_magic() {
        let bytes = minimal_file("{}");
        assert!(SafetensorsParser.can_handle(Path::new("model.bin"), &bytes));
    }

    #[test]
    fn rejects_non_brace_magic() {
        // Plausible length but byte 8 is not `{`.
        let mut bytes = 4u64.to_le_bytes().to_vec();
        bytes.push(b'x');
        assert!(!SafetensorsParser.can_handle(Path::new("model.bin"), &bytes));
    }

    #[test]
    fn malformed_json_header_errors() {
        let bytes = minimal_file("{not json");
        let path = write_temp("badjson", &bytes);
        let err = SafetensorsParser
            .parse_path(&path, &Limits::default())
            .unwrap_err();
        assert!(matches!(err, ParseError::Malformed { fmt: "safetensors", .. }));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn non_object_header_errors() {
        let bytes = minimal_file("[1,2,3]");
        let path = write_temp("array", &bytes);
        let err = SafetensorsParser
            .parse_path(&path, &Limits::default())
            .unwrap_err();
        assert!(matches!(err, ParseError::Malformed { fmt: "safetensors", .. }));
        let _ = std::fs::remove_file(&path);
    }
}
