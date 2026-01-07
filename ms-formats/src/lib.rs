//! `ms-formats` — parse-only parsers for serialized ML model formats.
//!
//! Each parser turns a model file into a stream of suspicious-call [`Event`]s
//! **without ever executing the file**. The pickle walker simulates the pickle
//! stack machine symbolically; the protobuf / HDF5 / zip readers walk container
//! structure only. Nothing in this crate calls `pickle.load`, `getattr`,
//! `import_module`, or `__reduce__`.
//!
//! The detector layer (`ms-detectors`) consumes these events and assigns
//! severities. This crate has no opinion on severity — it only reports *what it
//! saw* (which opcode bound which `module.name`, which graph op, which embedded
//! source string).

use std::io::Read;
use std::path::Path;

pub mod pickle;
pub mod marshal;
pub mod joblib;
pub mod dill;
pub mod cloudpickle;
pub mod pytorch;
pub mod tensorflow;
pub mod keras;
pub mod hdf5;
pub mod onnx;
pub mod safetensors;
pub mod gguf;
pub mod protobuf;
pub mod limits;

pub use limits::Limits;

/// Pickle opcodes. Names mirror CPython's `pickle` module / `pickletools`.
///
/// We carry the full opcode set so the walker can faithfully simulate the
/// stack machine across protocols 0–5 (plus the dill/cloudpickle extensions,
/// which reuse the same byte values with extra framing).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PickleOpcode {
    // ----- markers / framing -----
    Proto,        // \x80  PROTO
    Frame,        // \x95  FRAME
    Stop,         // .     STOP
    Mark,         // (     MARK
    PopMark,      // 1     POP_MARK
    Pop,          // 0     POP
    Dup,          // 2     DUP
    // ----- memo -----
    Put,          // p     PUT
    BinPut,       // q     BINPUT
    LongBinPut,   // r     LONG_BINPUT
    Memoize,      // \x94  MEMOIZE
    Get,          // g     GET
    BinGet,       // h     BINGET
    LongBinGet,   // j     LONG_BINGET
    // ----- ints / bools / none -----
    None_,        // N     NONE
    NewTrue,      // \x88  NEWTRUE
    NewFalse,     // \x89  NEWFALSE
    Int,          // I     INT
    BinInt,       // J     BININT
    BinInt1,      // K     BININT1
    BinInt2,      // M     BININT2
    Long,         // L     LONG
    Long1,        // \x8a  LONG1
    Long4,        // \x8b  LONG4
    // ----- floats -----
    Float,        // F     FLOAT
    BinFloat,     // G     BINFLOAT
    // ----- strings / bytes -----
    String_,      // S     STRING
    BinString,    // T     BINSTRING
    ShortBinString, // U   SHORT_BINSTRING
    BinBytes,     // B     BINBYTES
    ShortBinBytes,// C     SHORT_BINBYTES
    BinBytes8,    // \x8e  BINBYTES8
    ByteArray8,   // \x96  BYTEARRAY8
    Unicode,      // V     UNICODE
    BinUnicode,   // X     BINUNICODE
    ShortBinUnicode, // \x8c SHORT_BINUNICODE
    BinUnicode8,  // \x8d  BINUNICODE8
    // ----- containers -----
    EmptyList,    // ]     EMPTY_LIST
    Append,       // a     APPEND
    Appends,      // e     APPENDS
    List,         // l     LIST
    EmptyTuple,   // )     EMPTY_TUPLE
    Tuple,        // t     TUPLE
    Tuple1,       // \x85  TUPLE1
    Tuple2,       // \x86  TUPLE2
    Tuple3,       // \x87  TUPLE3
    EmptyDict,    // }     EMPTY_DICT
    Dict,         // d     DICT
    SetItem,      // s     SETITEM
    SetItems,     // u     SETITEMS
    EmptySet,     // \x8f  EMPTY_SET
    FrozenSet,    // \x91  FROZENSET
    AddItems,     // \x90  ADDITEMS
    // ----- the dangerous set -----
    Global,       // c     GLOBAL
    StackGlobal,  // \x93  STACK_GLOBAL
    Reduce,       // R     REDUCE
    Build,        // b     BUILD
    Inst,         // i     INST
    Obj,          // o     OBJ
    NewObj,       // \x81  NEWOBJ
    NewObjEx,     // \x92  NEWOBJ_EX
    Ext1,         // \x82  EXT1
    Ext2,         // \x83  EXT2
    Ext4,         // \x84  EXT4
    PersId,       // P     PERSID
    BinPersId,    // Q     BINPERSID
    // ----- next-buffer (proto 5, out-of-band) -----
    NextBuffer,   // \x97  NEXT_BUFFER
    ReadonlyBuffer, // \x98 READONLY_BUFFER
}

impl PickleOpcode {
    /// Human-readable opcode name (matches `pickletools` naming).
    pub fn name(self) -> &'static str {
        use PickleOpcode::*;
        match self {
            Proto => "PROTO", Frame => "FRAME", Stop => "STOP", Mark => "MARK",
            PopMark => "POP_MARK", Pop => "POP", Dup => "DUP",
            Put => "PUT", BinPut => "BINPUT", LongBinPut => "LONG_BINPUT", Memoize => "MEMOIZE",
            Get => "GET", BinGet => "BINGET", LongBinGet => "LONG_BINGET",
            None_ => "NONE", NewTrue => "NEWTRUE", NewFalse => "NEWFALSE",
            Int => "INT", BinInt => "BININT", BinInt1 => "BININT1", BinInt2 => "BININT2",
            Long => "LONG", Long1 => "LONG1", Long4 => "LONG4",
            Float => "FLOAT", BinFloat => "BINFLOAT",
            String_ => "STRING", BinString => "BINSTRING", ShortBinString => "SHORT_BINSTRING",
            BinBytes => "BINBYTES", ShortBinBytes => "SHORT_BINBYTES", BinBytes8 => "BINBYTES8",
            ByteArray8 => "BYTEARRAY8", Unicode => "UNICODE", BinUnicode => "BINUNICODE",
            ShortBinUnicode => "SHORT_BINUNICODE", BinUnicode8 => "BINUNICODE8",
            EmptyList => "EMPTY_LIST", Append => "APPEND", Appends => "APPENDS", List => "LIST",
            EmptyTuple => "EMPTY_TUPLE", Tuple => "TUPLE", Tuple1 => "TUPLE1", Tuple2 => "TUPLE2",
            Tuple3 => "TUPLE3", EmptyDict => "EMPTY_DICT", Dict => "DICT", SetItem => "SETITEM",
            SetItems => "SETITEMS", EmptySet => "EMPTY_SET", FrozenSet => "FROZENSET",
            AddItems => "ADDITEMS",
            Global => "GLOBAL", StackGlobal => "STACK_GLOBAL", Reduce => "REDUCE", Build => "BUILD",
            Inst => "INST", Obj => "OBJ", NewObj => "NEWOBJ", NewObjEx => "NEWOBJ_EX",
            Ext1 => "EXT1", Ext2 => "EXT2", Ext4 => "EXT4", PersId => "PERSID", BinPersId => "BINPERSID",
            NextBuffer => "NEXT_BUFFER", ReadonlyBuffer => "READONLY_BUFFER",
        }
    }

    /// Opcodes that *consume a callable and trigger code* on unpickle.
    /// These are the events detectors care most about.
    pub fn is_call_trigger(self) -> bool {
        use PickleOpcode::*;
        matches!(self, Reduce | Build | Inst | Obj | NewObj | NewObjEx)
    }
}

/// A single suspicious-call observation emitted by a parser.
///
/// A parser emits one `Event` per interesting thing it sees: a pickle opcode
/// that binds a `module.name` callable, an embedded lambda source string
/// (HDF5 / Keras), or a custom graph op (TensorFlow / ONNX). Fields not
/// relevant to a given event are `None`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Event {
    /// The pickle opcode that produced this event, if it came from a pickle stream.
    pub opcode: Option<PickleOpcode>,
    /// Resolved target module (e.g. `"os"`), if the event binds a global callable.
    pub target_module: Option<String>,
    /// Resolved target name (e.g. `"system"`).
    pub target_name: Option<String>,
    /// Raw embedded source / marshalled-code string (HDF5 / Keras lambda).
    pub raw_string: Option<String>,
    /// Graph operator name for TensorFlow `NodeDef.op` / ONNX node op.
    pub graph_op: Option<String>,
    /// Graph op domain (ONNX) — `""`/`ai.onnx` is builtin; anything else is custom.
    pub graph_domain: Option<String>,
    /// Byte offset within the parsed stream where this event was observed.
    pub offset: u64,
    /// Simulated pickle stack depth at the point of emission (0 for non-pickle).
    pub stack_depth: usize,
    /// Logical sub-source within the file (e.g. zip member `"data.pkl"`,
    /// HDF5 dataset path, SavedModel relative path). `None` == the file itself.
    pub source: Option<String>,
    /// Free-form note from the parser (e.g. a "bomb" / limit-exceeded marker).
    pub note: Option<String>,
}

impl Event {
    /// Convenience constructor for a global-binding pickle event.
    pub fn global(opcode: PickleOpcode, module: impl Into<String>, name: impl Into<String>, offset: u64, depth: usize) -> Self {
        Event {
            opcode: Some(opcode),
            target_module: Some(module.into()),
            target_name: Some(name.into()),
            offset,
            stack_depth: depth,
            ..Default::default()
        }
    }

    /// Convenience constructor for a graph-op event (TensorFlow / ONNX).
    pub fn graph(op: impl Into<String>, domain: Option<String>, offset: u64) -> Self {
        Event {
            graph_op: Some(op.into()),
            graph_domain: domain,
            offset,
            ..Default::default()
        }
    }

    /// Convenience constructor for an embedded-source event (HDF5 / Keras).
    pub fn source_string(raw: impl Into<String>, offset: u64) -> Self {
        Event {
            raw_string: Some(raw.into()),
            offset,
            ..Default::default()
        }
    }

    /// `"module.name"` for the bound callable, if both parts are present.
    pub fn qualified_target(&self) -> Option<String> {
        match (&self.target_module, &self.target_name) {
            (Some(m), Some(n)) => Some(format!("{m}.{n}")),
            _ => None,
        }
    }
}

/// Errors a parser can return. These map to the I/O-style operational exit
/// codes in `ms-core` — they are *not* findings.
#[derive(Debug, thiserror::Error)]
pub enum ParseError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("malformed {fmt} file: {msg}")]
    Malformed { fmt: &'static str, msg: String },
    #[error("unsupported: {0}")]
    Unsupported(String),
    #[error("resource limit exceeded ({0}) — possible decompression/opcode bomb")]
    Limit(String),
    #[error("zip error: {0}")]
    Zip(String),
    #[error("json error: {0}")]
    Json(String),
}

impl ParseError {
    pub fn malformed(fmt: &'static str, msg: impl Into<String>) -> Self {
        ParseError::Malformed { fmt, msg: msg.into() }
    }
}

/// A parse-only parser for one (or a family of) model format(s).
///
/// > NOTE: upstream `modelscan` exposes a `scan(reader)` shape. We use a
/// > path-based entry point instead, because several formats are containers
/// > (PyTorch = zip, TensorFlow SavedModel = directory) that need seek / dir
/// > access rather than a single forward `Read`. The byte-stream walkers
/// > ([`pickle::walk`], [`marshal::walk`]) keep the reader-based shape and are
/// > the reusable core that container parsers delegate to.
pub trait Parser: Send + Sync {
    /// Stable parser id (e.g. `"pickle"`, `"pytorch"`, `"onnx"`).
    fn id(&self) -> &str;

    /// Whether this parser claims `path` given its first magic bytes.
    fn can_handle(&self, path: &Path, magic: &[u8]) -> bool;

    /// Parse the file at `path`, returning all observed events.
    fn parse_path(&self, path: &Path, limits: &Limits) -> Result<Vec<Event>, ParseError>;
}

/// Read up to `n` magic bytes from the start of a reader (best effort).
pub fn read_magic<R: Read>(reader: &mut R, n: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    let mut filled = 0;
    while filled < n {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(k) => filled += k,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    buf.truncate(filled);
    Ok(buf)
}
