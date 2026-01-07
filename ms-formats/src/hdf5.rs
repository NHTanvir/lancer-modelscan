//! Best-effort HDF5 "embedded code" scanner (plan §3, HDF5 family).
//!
//! HDF5 is a complex hierarchical container (superblock, B-tree object headers,
//! local/global heaps, chunked datasets). A full pure-Rust HDF5 parser is **out
//! of scope** for this crate — pulling in a libhdf5 binding would also defeat
//! the "parse-only, no native deps" goal. Instead this module is a deliberately
//! simple, **heuristic** byte scanner: it never decodes the HDF5 structure, it
//! only walks the raw bytes looking for ASCII substrings that betray embedded
//! Python source (the kind Keras stores for a `Lambda` layer, or that an
//! attacker might smuggle into an attribute / dataset).
//!
//! It can miss code that is compressed or otherwise not stored as readable
//! ASCII, and it can over-report on benign files that happen to contain these
//! tokens — severity is decided downstream by `ms-detectors`. Nothing here is
//! ever executed; we only read bytes.

use std::path::Path;

use crate::{Event, Limits, ParseError, Parser};

/// The 8-byte HDF5 format signature found at the start of (most) HDF5 files.
pub const HDF5_MAGIC: [u8; 8] = [0x89, 0x48, 0x44, 0x46, 0x0d, 0x0a, 0x1a, 0x0a];

/// File extensions we treat as HDF5.
const HDF5_EXTENSIONS: &[&str] = &["h5", "hdf5"];

/// ASCII needles that suggest embedded executable Python source.
const CODE_NEEDLES: &[&str] = &["lambda", "exec(", "eval(", "os.system", "subprocess"];

/// Bytes of context to show on either side of a hit in the preview.
const PREVIEW_PAD: usize = 24;

/// Parse-only, heuristic HDF5 embedded-code scanner.
pub struct Hdf5Parser;

impl Parser for Hdf5Parser {
    fn id(&self) -> &str {
        "hdf5"
    }

    fn can_handle(&self, path: &Path, magic: &[u8]) -> bool {
        if magic.starts_with(&HDF5_MAGIC) {
            return true;
        }
        match path.extension().and_then(|e| e.to_str()) {
            Some(ext) => HDF5_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()),
            None => false,
        }
    }

    fn parse_path(&self, path: &Path, limits: &Limits) -> Result<Vec<Event>, ParseError> {
        let bytes = read_capped(path, limits.max_member_bytes)?;
        Ok(scan_bytes(&bytes))
    }
}

/// Read up to `cap` bytes from `path`. We only ever look at raw bytes; nothing
/// is decoded or executed.
fn read_capped(path: &Path, cap: u64) -> Result<Vec<u8>, ParseError> {
    use std::io::Read;
    let f = std::fs::File::open(path)?;
    let mut limited = f.take(cap);
    let mut buf = Vec::new();
    limited.read_to_end(&mut buf)?;
    Ok(buf)
}

/// Scan raw bytes for embedded-code needles, emitting one event per distinct
/// needle that occurs (de-duplicated by needle, reported at its first hit).
fn scan_bytes(bytes: &[u8]) -> Vec<Event> {
    let mut events = Vec::new();
    for needle in CODE_NEEDLES {
        if let Some(at) = find_ascii(bytes, needle.as_bytes()) {
            let preview = preview_around(bytes, at, needle.len());
            let mut ev = Event::source_string(preview, at as u64);
            ev.note = Some("hdf5_embedded".to_string());
            events.push(ev);
        }
    }
    events
}

/// First index of `needle` within `hay` (plain byte search, never panics).
fn find_ascii(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

/// Build a short, printable preview of the bytes surrounding a hit.
fn preview_around(bytes: &[u8], at: usize, needle_len: usize) -> String {
    let start = at.saturating_sub(PREVIEW_PAD);
    let end = (at + needle_len + PREVIEW_PAD).min(bytes.len());
    let slice = &bytes[start..end];
    // Render as lossy UTF-8 and collapse control bytes so the preview stays
    // single-line and readable in reports.
    String::from_utf8_lossy(slice)
        .chars()
        .map(|c| if c.is_control() { '.' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_system_produces_source_string_event() {
        let mut bytes = b"\x89HDF\r\n\x1a\n some padding ".to_vec();
        bytes.extend_from_slice(b"payload os.system('rm -rf /') tail");
        let events = scan_bytes(&bytes);
        assert!(
            events
                .iter()
                .any(|e| e.raw_string.is_some() && e.note.as_deref() == Some("hdf5_embedded")),
            "expected a source_string event flagged hdf5_embedded, got {events:?}",
        );
        // The preview should mention the offending token.
        assert!(events
            .iter()
            .filter_map(|e| e.raw_string.as_deref())
            .any(|s| s.contains("os.system")));
    }

    #[test]
    fn clean_bytes_produce_no_events() {
        let bytes = b"\x89HDF\r\n\x1a\n just some innocuous tensor weights 0123456789";
        assert!(scan_bytes(bytes).is_empty());
    }

    #[test]
    fn can_handle_by_magic_and_extension() {
        let p = Hdf5Parser;
        assert!(p.can_handle(Path::new("model.bin"), &HDF5_MAGIC));
        assert!(p.can_handle(Path::new("weights.H5"), &[]));
        assert!(p.can_handle(Path::new("net.hdf5"), &[]));
        assert!(!p.can_handle(Path::new("notes.txt"), &[0x00, 0x01]));
    }
}
