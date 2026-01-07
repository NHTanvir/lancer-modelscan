//! Parse-only parser for `joblib` model files.
//!
//! `joblib` serializes with the standard pickle opcode stream — it adds custom
//! reduction callables (e.g. `numpy` array reconstructors) rather than new
//! opcodes — so this is a thin wrapper that delegates to [`crate::pickle::walk`].
//!
//! `joblib` files may be transparently compressed (zlib / gzip / lz4 / xz). We
//! do **not** decompress here (no decompression crate is available for v0.1):
//! if the stream is compressed the walker hits an unknown opcode and stops
//! gracefully, which is acceptable.

use std::path::Path;

use crate::{Event, Limits, ParseError, Parser};

/// `Parser` for `joblib`-serialized files (raw, uncompressed pickle stream).
pub struct JoblibParser;

impl Parser for JoblibParser {
    fn id(&self) -> &str {
        "joblib"
    }

    fn can_handle(&self, path: &Path, _magic: &[u8]) -> bool {
        matches!(
            path.extension().and_then(|e| e.to_str()),
            Some(ext) if ext.eq_ignore_ascii_case("joblib")
        )
    }

    fn parse_path(&self, path: &Path, limits: &Limits) -> Result<Vec<Event>, ParseError> {
        let mut f = std::fs::File::open(path)?;
        crate::pickle::walk(&mut f, limits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn id_is_joblib() {
        assert_eq!(JoblibParser.id(), "joblib");
    }

    #[test]
    fn can_handle_joblib_extension() {
        let p = JoblibParser;
        assert!(p.can_handle(Path::new("model.joblib"), &[]));
        assert!(p.can_handle(Path::new("MODEL.JOBLIB"), &[]));
        assert!(!p.can_handle(Path::new("model.pkl"), &[]));
        assert!(!p.can_handle(Path::new("model"), &[]));
    }
}
