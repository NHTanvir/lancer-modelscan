//! PyTorch model parser (parse-only).
//!
//! Modern PyTorch checkpoints (`torch.save` since 1.6) are ZIP containers whose
//! payload lives in one or more pickle members (e.g. `archive/data.pkl`). Older
//! checkpoints — and `pytorch_model.bin` from the HuggingFace ecosystem — are a
//! single raw pickle stream. Either way the dangerous part is the pickle, so we
//! locate every `*.pkl` member and hand each one to [`crate::pickle::walk`],
//! tagging every emitted [`Event`] with the member name as its `source`. Raw
//! (non-zip) files delegate straight to the pickle walker. Nothing here ever
//! executes model content — we only walk container structure and pickle bytes.

use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::{Event, Limits, ParseError};

/// ZIP local-file header magic (`PK\x03\x04`). A `torch.save` archive always
/// starts with this; raw pickles start with the `PROTO` opcode (`0x80`) or are
/// protocol-0 ASCII.
const ZIP_MAGIC: [u8; 4] = [0x50, 0x4B, 0x03, 0x04];

/// File extensions a PyTorch archive may carry (lowercase, no dot).
const PYTORCH_EXTENSIONS: &[&str] = &["pt", "pth", "ckpt", "pt2", "bin", "zip"];

/// `Parser` for PyTorch checkpoints (zip-wrapped or raw pickle).
pub struct PytorchParser;

impl crate::Parser for PytorchParser {
    fn id(&self) -> &str {
        "pytorch"
    }

    fn can_handle(&self, path: &Path, magic: &[u8]) -> bool {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.to_ascii_lowercase());

        // `pytorch_model*.bin` is HuggingFace's raw-pickle convention; claim it
        // regardless of magic (older shards are not zip-wrapped).
        if let Some(name) = &name {
            if name.starts_with("pytorch_model") && name.ends_with(".bin") {
                return true;
            }
        }

        // Otherwise require the ZIP local-file header *and* a known extension so
        // we don't grab arbitrary zips (and never `.keras`, handled elsewhere).
        if magic.len() >= 4 && magic[..4] == ZIP_MAGIC {
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                let ext = ext.to_ascii_lowercase();
                if ext == "keras" {
                    return false;
                }
                return PYTORCH_EXTENSIONS.contains(&ext.as_str());
            }
        }

        false
    }

    fn parse_path(&self, path: &Path, limits: &Limits) -> Result<Vec<Event>, ParseError> {
        let mut f = File::open(path)?;

        // Sniff the first four bytes to decide zip vs. raw pickle. `read_magic`
        // is best-effort and leaves the cursor advanced, so we reopen below.
        let magic = crate::read_magic(&mut f, 4)?;
        let is_zip = magic.len() >= 4 && magic[..4] == ZIP_MAGIC;

        if !is_zip {
            // Older raw-pickle checkpoint (or `pytorch_model.bin`): walk directly.
            let mut f = File::open(path)?;
            return crate::pickle::walk(&mut f, limits);
        }

        let f = File::open(path)?;
        let mut archive = zip::ZipArchive::new(f).map_err(|e| ParseError::Zip(e.to_string()))?;

        // Collect member names up front: `by_name` needs `&mut archive`, which
        // would conflict with holding the `file_names()` borrow.
        let members: Vec<String> = archive
            .file_names()
            .filter(|n| n.ends_with(".pkl"))
            .map(|n| n.to_string())
            .collect();

        let mut events: Vec<Event> = Vec::new();
        for member in members {
            let mut zf = archive
                .by_name(&member)
                .map_err(|e| ParseError::Zip(e.to_string()))?;
            let reader: &mut dyn Read = &mut zf;
            let mut member_events = crate::pickle::walk(reader, limits)?;
            for ev in &mut member_events {
                ev.source = Some(member.clone());
            }
            events.append(&mut member_events);
        }

        // No pickle member => nothing to report (it's a structurally valid zip
        // with only tensors/metadata).
        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Parser;
    use std::io::Write;
    use std::path::PathBuf;

    /// Minimal protocol-2 pickle that references `os.system` via GLOBAL+REDUCE.
    fn os_system_pickle() -> Vec<u8> {
        let mut p = vec![0x80, 0x02];
        p.extend_from_slice(b"cos\nsystem\n");
        let arg = b"echo hi";
        p.push(b'X');
        p.extend_from_slice(&(arg.len() as u32).to_le_bytes());
        p.extend_from_slice(arg);
        p.push(0x85); // TUPLE1
        p.push(b'R'); // REDUCE
        p.push(b'.'); // STOP
        p
    }

    /// Build a one-member zip (`archive/data.pkl`) at a unique temp path.
    fn write_torch_zip() -> PathBuf {
        let mut path = std::env::temp_dir();
        let unique = format!(
            "ms_pytorch_test_{}_{}.pt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        path.push(unique);

        let file = File::create(&path).expect("create temp zip");
        let mut zw = zip::ZipWriter::new(file);
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        zw.start_file("archive/data.pkl", opts)
            .expect("start_file");
        zw.write_all(&os_system_pickle()).expect("write pickle");
        zw.finish().expect("finish zip");
        path
    }

    #[test]
    fn id_is_pytorch() {
        assert_eq!(PytorchParser.id(), "pytorch");
    }

    #[test]
    fn can_handle_zip_with_pt_extension() {
        let p = Path::new("model.pt");
        assert!(PytorchParser.can_handle(p, &ZIP_MAGIC));
    }

    #[test]
    fn can_handle_pytorch_model_bin_without_zip_magic() {
        // Raw-pickle HuggingFace shard: claimed by name even with PROTO magic.
        let p = Path::new("pytorch_model.bin");
        assert!(PytorchParser.can_handle(p, &[0x80, 0x02]));
    }

    #[test]
    fn rejects_keras_files() {
        let p = Path::new("model.keras");
        assert!(!PytorchParser.can_handle(p, &ZIP_MAGIC));
    }

    #[test]
    fn rejects_zip_with_unknown_extension() {
        let p = Path::new("archive.tar");
        assert!(!PytorchParser.can_handle(p, &ZIP_MAGIC));
    }

    #[test]
    fn rejects_non_zip_unknown_name() {
        let p = Path::new("notes.txt");
        assert!(!PytorchParser.can_handle(p, b"hello"));
    }

    #[test]
    fn scans_zip_member_for_os_system() {
        let path = write_torch_zip();
        let events = PytorchParser
            .parse_path(&path, &Limits::default())
            .expect("parse zip");
        let _ = std::fs::remove_file(&path);

        let g = events
            .iter()
            .find(|e| e.target_module.as_deref() == Some("os"))
            .expect("should find os global in zip member");
        assert_eq!(g.target_name.as_deref(), Some("system"));
        assert_eq!(g.source.as_deref(), Some("archive/data.pkl"));
    }
}
