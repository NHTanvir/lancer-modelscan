//! Parse-only walker for TensorFlow `SavedModel` / `GraphDef` protobufs.
//!
//! TensorFlow stores its computation graph as a protobuf, either a full
//! `SavedModel` (`saved_model.pb`, the common SavedModel export) or a bare
//! `GraphDef` (frozen graph). The danger surface is *custom ops* — most notably
//! `PyFunc` / `PyFuncStateless`, which execute arbitrary Python on graph run —
//! so we walk the protobuf structurally and emit one [`Event`] per `NodeDef.op`
//! string we find. We never load the graph or run any op; we only read bytes.
//!
//! Op events are emitted with domain `None`: TensorFlow has no ONNX-style
//! op domain, so the `tf_custom_op` detector keys on the op name alone. (The
//! ONNX detector requires `Some(domain)`, which is why we leave it `None` here.)
//!
//! Field-number map (from `saved_model.proto` / `graph.proto` / `function.proto`):
//! - `SavedModel.meta_graphs` = field 2 (repeated `MetaGraphDef`)
//! - `MetaGraphDef.graph_def` = field 2 (`GraphDef`)
//! - `GraphDef.node` = field 1 (repeated `NodeDef`)
//! - `GraphDef.library` = field 2 (`FunctionDefLibrary`)
//! - `NodeDef.name` = field 1 (string), `NodeDef.op` = field 2 (string)
//! - `FunctionDefLibrary.function` = field 1 (repeated `FunctionDef`)
//! - `FunctionDef.node_def` = field 3 (repeated `NodeDef`)

use std::path::Path;

use crate::protobuf::ProtoReader;
use crate::{Event, Limits, ParseError};

/// `Parser` for TensorFlow `SavedModel` / `GraphDef` protobufs.
pub struct TensorflowParser;

impl crate::Parser for TensorflowParser {
    fn id(&self) -> &str {
        "tensorflow"
    }

    fn can_handle(&self, path: &Path, _magic: &[u8]) -> bool {
        if path.file_name().and_then(|n| n.to_str()) == Some("saved_model.pb") {
            return true;
        }
        match path.extension().and_then(|e| e.to_str()) {
            Some(ext) => ext.eq_ignore_ascii_case("pb"),
            None => false,
        }
    }

    fn parse_path(&self, path: &Path, limits: &Limits) -> Result<Vec<Event>, ParseError> {
        let len = std::fs::metadata(path)?.len();
        if len > limits.max_member_bytes {
            return Err(ParseError::Limit(format!(
                "tensorflow proto {len} bytes exceeds max_member_bytes {}",
                limits.max_member_bytes
            )));
        }
        let bytes = std::fs::read(path)?;
        Ok(walk(&bytes))
    }
}

/// Walk a TensorFlow protobuf buffer and emit one [`Event`] per `NodeDef.op`.
///
/// Handles both a full `SavedModel` (one or more `MetaGraphDef`s) and a bare
/// top-level `GraphDef`. The running index becomes each event's offset, giving
/// emission a stable, monotonic ordering.
pub fn walk(bytes: &[u8]) -> Vec<Event> {
    let root = ProtoReader::new(bytes);
    let mut events = Vec::new();
    let mut idx: u64 = 0;

    // SavedModel.meta_graphs (field 2). If present, descend per meta-graph.
    let meta_graphs = root.messages_with(2);
    if !meta_graphs.is_empty() {
        for meta in &meta_graphs {
            // MetaGraphDef.graph_def (field 2).
            for graph in meta.messages_with(2) {
                walk_graph_def(&graph, &mut events, &mut idx);
            }
        }
        return events;
    }

    // No meta_graphs: treat the buffer as a bare top-level GraphDef.
    walk_graph_def(&root, &mut events, &mut idx);
    events
}

/// Walk a `GraphDef`: its direct nodes (field 1) and its function library
/// (field 2 → `FunctionDefLibrary`).
fn walk_graph_def(graph: &ProtoReader<'_>, events: &mut Vec<Event>, idx: &mut u64) {
    // GraphDef.node (field 1) → NodeDef.
    for node in graph.messages_with(1) {
        emit_node_op(&node, events, idx);
    }

    // GraphDef.library (field 2) → FunctionDefLibrary. Note: field 2 also names
    // graph_def at the MetaGraphDef level — disambiguation is by parent, which
    // is why we only read field 2 *here*, inside an already-resolved GraphDef.
    for library in graph.messages_with(2) {
        // FunctionDefLibrary.function (field 1) → FunctionDef.
        for func in library.messages_with(1) {
            // FunctionDef.node_def (field 3) → NodeDef.
            for node in func.messages_with(3) {
                emit_node_op(&node, events, idx);
            }
        }
    }
}

/// Read `NodeDef.op` (field 2) and, if non-empty, emit a graph event with
/// `domain == None`.
fn emit_node_op(node: &ProtoReader<'_>, events: &mut Vec<Event>, idx: &mut u64) {
    if let Some(op) = node.first_str(2) {
        if !op.is_empty() {
            events.push(Event::graph(op, None, *idx));
            *idx += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode a protobuf length-delimited field (wire type 2): tag, len, bytes.
    fn len_field(number: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend(varint(((number as u64) << 3) | 2));
        out.extend(varint(payload.len() as u64));
        out.extend_from_slice(payload);
        out
    }

    fn varint(mut v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        loop {
            let mut byte = (v & 0x7f) as u8;
            v >>= 7;
            if v != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if v == 0 {
                break;
            }
        }
        out
    }

    #[test]
    fn finds_pyfunc_in_saved_model() {
        // NodeDef { name(1)="x", op(2)="PyFunc" }
        let mut node = Vec::new();
        node.extend(len_field(1, b"x"));
        node.extend(len_field(2, b"PyFunc"));
        // GraphDef { node(1) = node }
        let graph = len_field(1, &node);
        // MetaGraphDef { graph_def(2) = graph }
        let meta = len_field(2, &graph);
        // SavedModel { meta_graphs(2) = meta }
        let saved_model = len_field(2, &meta);

        let events = walk(&saved_model);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].graph_op.as_deref(), Some("PyFunc"));
        assert_eq!(events[0].graph_domain, None);
    }

    #[test]
    fn finds_op_in_bare_graph_def() {
        // NodeDef { op(2)="ReadFile" } with no enclosing meta_graphs.
        let mut node = Vec::new();
        node.extend(len_field(2, b"ReadFile"));
        let graph = len_field(1, &node);

        let events = walk(&graph);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].graph_op.as_deref(), Some("ReadFile"));
        assert_eq!(events[0].graph_domain, None);
    }

    #[test]
    fn finds_op_in_function_library() {
        // FunctionDef { node_def(3) = NodeDef { op(2)="PyFuncStateless" } }
        let mut inner_node = Vec::new();
        inner_node.extend(len_field(2, b"PyFuncStateless"));
        let func = len_field(3, &inner_node);
        // FunctionDefLibrary { function(1) = func }
        let library = len_field(1, &func);
        // GraphDef { library(2) = library }
        let graph = len_field(2, &library);
        // MetaGraphDef { graph_def(2) = graph }
        let meta = len_field(2, &graph);
        // SavedModel { meta_graphs(2) = meta }
        let saved_model = len_field(2, &meta);

        let events = walk(&saved_model);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].graph_op.as_deref(), Some("PyFuncStateless"));
        assert_eq!(events[0].graph_domain, None);
    }

    #[test]
    fn graph_def_with_both_nodes_and_library() {
        // GraphDef with a direct node and a library function node.
        let mut direct = Vec::new();
        direct.extend(len_field(2, b"MatMul"));
        let direct_node = len_field(1, &direct);

        let mut lib_inner = Vec::new();
        lib_inner.extend(len_field(2, b"PyFunc"));
        let func = len_field(3, &lib_inner);
        let library = len_field(1, &func);
        let lib_field = len_field(2, &library);

        let mut graph = Vec::new();
        graph.extend(direct_node);
        graph.extend(lib_field);

        let events = walk(&graph);
        let ops: Vec<_> = events.iter().filter_map(|e| e.graph_op.as_deref()).collect();
        assert_eq!(ops, vec!["MatMul", "PyFunc"]);
        assert!(events.iter().all(|e| e.graph_domain.is_none()));
    }

    #[test]
    fn skips_empty_ops() {
        // NodeDef with name only, no op string → no event.
        let mut node = Vec::new();
        node.extend(len_field(1, b"const_node"));
        let graph = len_field(1, &node);
        assert!(walk(&graph).is_empty());
    }

    #[test]
    fn can_handle_matches_name_and_extension() {
        let p = TensorflowParser;
        assert!(p.can_handle(Path::new("/models/saved_model.pb"), &[]));
        assert!(p.can_handle(Path::new("/models/frozen.pb"), &[]));
        assert!(p.can_handle(Path::new("/models/FROZEN.PB"), &[]));
        assert!(!p.can_handle(Path::new("/models/model.onnx"), &[]));
    }
}
