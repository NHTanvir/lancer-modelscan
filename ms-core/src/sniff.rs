//! Format detection: pick a [`Parser`] for a path from its magic bytes +
//! extension. The parser list is ordered most-specific-first; the raw pickle
//! parser is the last-resort fallback.

use ms_formats::{read_magic, Parser};
use std::fs::File;
use std::path::Path;

/// How many leading bytes to sniff.
pub const MAGIC_LEN: usize = 16;

/// Build the ordered parser registry. Order matters: distinctive container /
/// header formats are tried before the permissive raw-pickle fallback.
pub fn parsers() -> Vec<Box<dyn Parser>> {
    vec![
        // Safe-by-construction headers (claim first so they're recognized, not
        // mis-sniffed as something else).
        Box::new(ms_formats::safetensors::SafetensorsParser),
        Box::new(ms_formats::gguf::GgufParser),
        // Containers / structured formats.
        Box::new(ms_formats::pytorch::PytorchParser),
        Box::new(ms_formats::keras::KerasParser),
        Box::new(ms_formats::hdf5::Hdf5Parser),
        // TensorFlow before ONNX: a SavedModel .pb begins with tag byte 0x08,
        // which the ONNX magic check also matches — TF claims .pb / saved_model.pb
        // by name+extension first so ONNX only gets genuine .onnx files.
        Box::new(ms_formats::tensorflow::TensorflowParser),
        Box::new(ms_formats::onnx::OnnxParser),
        // Pickle family. joblib/dill/cloudpickle are extension-driven; raw
        // pickle is the permissive fallback (claims any 0x80-led stream).
        Box::new(ms_formats::joblib::JoblibParser),
        Box::new(ms_formats::dill::DillParser),
        Box::new(ms_formats::cloudpickle::CloudpickleParser),
        Box::new(ms_formats::pickle::PickleParser),
    ]
}

/// Read up to [`MAGIC_LEN`] leading bytes (empty for dirs / unreadable files).
pub fn read_file_magic(path: &Path) -> Vec<u8> {
    match File::open(path) {
        Ok(mut f) => read_magic(&mut f, MAGIC_LEN).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// Select the first parser that claims `path`.
pub fn select<'a>(parsers: &'a [Box<dyn Parser>], path: &Path) -> Option<&'a dyn Parser> {
    let magic = read_file_magic(path);
    parsers
        .iter()
        .map(|b| b.as_ref())
        .find(|p| p.can_handle(path, &magic))
}

/// Select a parser given pre-read magic bytes (avoids re-opening the file).
pub fn select_with_magic<'a>(
    parsers: &'a [Box<dyn Parser>],
    path: &Path,
    magic: &[u8],
) -> Option<&'a dyn Parser> {
    parsers
        .iter()
        .map(|b| b.as_ref())
        .find(|p| p.can_handle(path, magic))
}
