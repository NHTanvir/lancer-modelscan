//! Parse-only parser for `dill` model files.
//!
//! `dill` extends pickle with extra reduction callables (for functions,
//! lambdas, closures, etc.) but reuses the same pickle opcode stream — it does
//! not introduce new byte opcodes. This parser is therefore a thin wrapper that
//! delegates to [`crate::pickle::walk`]; the dangerous `dill.*` globals it adds
//! surface as ordinary `GLOBAL` / `STACK_GLOBAL` events.

use std::path::Path;

use crate::{Event, Limits, ParseError, Parser};

/// File extensions commonly used for `dill`-serialized files (lowercase, no dot).
pub const DILL_EXTENSIONS: &[&str] = &["dill", "dl"];

/// `Parser` for `dill`-serialized files.
pub struct DillParser;

impl Parser for DillParser {
    fn id(&self) -> &str {
        "dill"
    }

    fn can_handle(&self, path: &Path, _magic: &[u8]) -> bool {
        match path.extension().and_then(|e| e.to_str()) {
            Some(ext) => DILL_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()),
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
    fn id_is_dill() {
        assert_eq!(DillParser.id(), "dill");
    }

    #[test]
    fn can_handle_dill_extensions() {
        let p = DillParser;
        assert!(p.can_handle(Path::new("model.dill"), &[]));
        assert!(p.can_handle(Path::new("model.dl"), &[]));
        assert!(p.can_handle(Path::new("MODEL.DILL"), &[]));
        assert!(!p.can_handle(Path::new("model.pkl"), &[]));
        assert!(!p.can_handle(Path::new("model"), &[]));
    }
}
