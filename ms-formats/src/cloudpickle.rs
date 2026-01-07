//! Parse-only parser for `cloudpickle` model files.
//!
//! `cloudpickle` (used heavily by Ray, Dask, MLflow, and Spark to ship
//! functions/closures by value) extends pickle with extra reduction callables
//! but reuses the same pickle opcode stream — no new byte opcodes. This parser
//! is a thin wrapper that delegates to [`crate::pickle::walk`]; the
//! `cloudpickle.*` globals it adds surface as ordinary `GLOBAL` /
//! `STACK_GLOBAL` events.

use std::path::Path;

use crate::{Event, Limits, ParseError, Parser};

/// File extensions commonly used for `cloudpickle`-serialized files
/// (lowercase, no dot).
pub const CLOUDPICKLE_EXTENSIONS: &[&str] = &["cloudpickle", "cpkl"];

/// `Parser` for `cloudpickle`-serialized files.
pub struct CloudpickleParser;

impl Parser for CloudpickleParser {
    fn id(&self) -> &str {
        "cloudpickle"
    }

    fn can_handle(&self, path: &Path, _magic: &[u8]) -> bool {
        match path.extension().and_then(|e| e.to_str()) {
            Some(ext) => CLOUDPICKLE_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()),
            None => false,
        }
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
    fn id_is_cloudpickle() {
        assert_eq!(CloudpickleParser.id(), "cloudpickle");
    }

    #[test]
    fn can_handle_cloudpickle_extensions() {
        let p = CloudpickleParser;
        assert!(p.can_handle(Path::new("model.cloudpickle"), &[]));
        assert!(p.can_handle(Path::new("model.cpkl"), &[]));
        assert!(p.can_handle(Path::new("MODEL.CLOUDPICKLE"), &[]));
        assert!(!p.can_handle(Path::new("model.pkl"), &[]));
        assert!(!p.can_handle(Path::new("model"), &[]));
    }
}
