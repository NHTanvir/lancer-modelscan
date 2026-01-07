//! `gguf` — a SAFE-by-construction baseline parser.
//!
//! GGUF (the llama.cpp model container) stores metadata key/value pairs and
//! raw tensor data behind a fixed binary header. Like safetensors it carries
//! no opcodes, callables, or embedded code, so this parser never produces an
//! [`Event`]. It only validates the 4-byte magic and reads the version word so
//! the scanner can positively recognize the format instead of guessing.
//!
//! Header layout: 4-byte ASCII magic `GGUF`, then a little-endian `u32`
//! version. We read only that prefix — never the metadata or tensor payload.

use std::fs::File;
use std::io::Read as _;
use std::path::Path;

use crate::{Event, Limits, ParseError, Parser};

/// The 4-byte ASCII magic that opens every GGUF file: `G G U F`.
const GGUF_MAGIC: [u8; 4] = [0x47, 0x47, 0x55, 0x46];

/// Parse-only parser for the GGUF (and legacy GGML) format.
pub struct GgufParser;

impl Parser for GgufParser {
    fn id(&self) -> &str {
        "gguf"
    }

    fn can_handle(&self, path: &Path, magic: &[u8]) -> bool {
        if has_extension(path, "gguf") || has_extension(path, "ggml") {
            return true;
        }
        magic.len() >= 4 && magic[..4] == GGUF_MAGIC
    }

    fn parse_path(&self, path: &Path, _limits: &Limits) -> Result<Vec<Event>, ParseError> {
        let mut file = File::open(path)?;

        // Verify the 4-byte magic.
        let mut magic = [0u8; 4];
        file.read_exact(&mut magic)
            .map_err(|_| ParseError::malformed("gguf", "truncated magic"))?;
        if magic != GGUF_MAGIC {
            return Err(ParseError::malformed(
                "gguf",
                format!("bad magic {magic:02x?}, expected GGUF"),
            ));
        }

        // Read the little-endian u32 version word (validated for presence only;
        // we do not act on its value — any version is a recognized SAFE file).
        let mut ver_buf = [0u8; 4];
        file.read_exact(&mut ver_buf)
            .map_err(|_| ParseError::malformed("gguf", "truncated version word"))?;
        let _version = u32::from_le_bytes(ver_buf);

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    fn write_temp(name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("ms_gguf_{name}_{}", std::process::id()));
        let mut f = File::create(&p).expect("create temp");
        f.write_all(bytes).expect("write temp");
        p
    }

    /// Build a minimal GGUF file: magic + LE u32 version (+ optional trailer).
    fn minimal_file(version: u32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&GGUF_MAGIC);
        out.extend_from_slice(&version.to_le_bytes());
        out
    }

    #[test]
    fn id_is_gguf() {
        assert_eq!(GgufParser.id(), "gguf");
    }

    #[test]
    fn valid_magic_and_version_yields_zero_events() {
        let mut bytes = minimal_file(3);
        bytes.extend_from_slice(&[0x00; 16]); // fake metadata/tensor region
        let path = write_temp("v3", &bytes);
        let events = GgufParser
            .parse_path(&path, &Limits::default())
            .expect("valid header parses");
        assert!(events.is_empty(), "gguf must never emit events");
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn can_handle_by_extension() {
        assert!(GgufParser.can_handle(Path::new("model.gguf"), &[]));
        assert!(GgufParser.can_handle(Path::new("model.GGUF"), &[]));
        assert!(GgufParser.can_handle(Path::new("model.ggml"), &[]));
    }

    #[test]
    fn can_handle_by_magic() {
        assert!(GgufParser.can_handle(Path::new("model.bin"), b"GGUF\x03\x00\x00\x00"));
    }

    #[test]
    fn rejects_other_magic() {
        assert!(!GgufParser.can_handle(Path::new("model.bin"), b"PK\x03\x04"));
    }

    #[test]
    fn bad_magic_errors() {
        let path = write_temp("badmagic", b"NOPE\x03\x00\x00\x00");
        let err = GgufParser
            .parse_path(&path, &Limits::default())
            .unwrap_err();
        assert!(matches!(err, ParseError::Malformed { fmt: "gguf", .. }));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn truncated_version_errors() {
        let path = write_temp("trunc", b"GGUF\x03"); // magic ok, version short
        let err = GgufParser
            .parse_path(&path, &Limits::default())
            .unwrap_err();
        assert!(matches!(err, ParseError::Malformed { fmt: "gguf", .. }));
        let _ = std::fs::remove_file(&path);
    }
}
