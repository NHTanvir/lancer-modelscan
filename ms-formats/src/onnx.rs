//! Parse-only ONNX `ModelProto` walker.
//!
//! ONNX models are protobuf. We never load or run them — we only walk the wire
//! structure with [`crate::protobuf::ProtoReader`] to enumerate the graph's
//! nodes and report each node's `op_type` plus its `domain`. The empty domain
//! (and `ai.onnx`) is the builtin operator set; any other domain is a *custom*
//! op, which the `onnx_custom_domain` detector keys on — so we always attach a
//! domain (`""` when the field is absent) and let the detector decide.
//!
//! Relevant ONNX field numbers (from `onnx.proto`):
//! - `ModelProto.graph` = 7 (nested `GraphProto`)
//! - `GraphProto.node`  = 1 (repeated `NodeProto`)
//! - `NodeProto.op_type` = 4 (string)
//! - `NodeProto.domain`  = 7 (string, default `""`)

use std::path::Path;

use crate::protobuf::ProtoReader;
use crate::{Event, Limits, ParseError, Parser};

/// Parse-only parser for ONNX `ModelProto` files (`.onnx`).
pub struct OnnxParser;

impl Parser for OnnxParser {
    fn id(&self) -> &str {
        "onnx"
    }

    fn can_handle(&self, path: &Path, magic: &[u8]) -> bool {
        let by_ext = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e.eq_ignore_ascii_case("onnx"))
            .unwrap_or(false);
        // A serialized `ModelProto` typically begins with the `ir_version`
        // field (field 1, wire type 0) whose tag byte is `(1 << 3) | 0` = 0x08.
        let by_magic = magic.first() == Some(&0x08);
        by_ext || by_magic
    }

    fn parse_path(&self, path: &Path, limits: &Limits) -> Result<Vec<Event>, ParseError> {
        let meta = std::fs::metadata(path)?;
        if meta.len() > limits.max_member_bytes {
            return Err(ParseError::Limit(format!(
                "onnx file {} bytes exceeds max_member_bytes {}",
                meta.len(),
                limits.max_member_bytes
            )));
        }

        let bytes = std::fs::read(path)?;
        // Guard again on the actual byte count in case the file grew between the
        // metadata stat and the read.
        if bytes.len() as u64 > limits.max_member_bytes {
            return Err(ParseError::Limit(format!(
                "onnx file {} bytes exceeds max_member_bytes {}",
                bytes.len(),
                limits.max_member_bytes
            )));
        }

        Ok(walk_model(&bytes))
    }
}

/// Walk a serialized `ModelProto`, emitting one [`Event::graph`] per node.
///
/// `offset` carries the running node index (across all graphs in the file),
/// matching the contract's "running node index" semantics.
fn walk_model(bytes: &[u8]) -> Vec<Event> {
    let model = ProtoReader::new(bytes);
    let mut events = Vec::new();
    let mut node_index: u64 = 0;

    // ModelProto.graph (field 7). There is normally one graph, but tolerate
    // repeats rather than assume a single occurrence.
    for graph in model.messages_with(7) {
        // GraphProto.node (field 1), repeated NodeProto.
        for node in graph.messages_with(1) {
            let op_type = node.first_str(4).unwrap_or_default();
            // NodeProto.domain (field 7); default to "" so the detector always
            // receives a domain to evaluate.
            let domain = node.first_str(7).unwrap_or_default();
            events.push(Event::graph(op_type, Some(domain), node_index));
            node_index += 1;
        }
    }

    events
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Append a length-delimited (wire type 2) field: tag, varint length, bytes.
    fn push_len_field(out: &mut Vec<u8>, field_number: u32, payload: &[u8]) {
        push_varint(out, ((field_number as u64) << 3) | 2);
        push_varint(out, payload.len() as u64);
        out.extend_from_slice(payload);
    }

    /// Append a base-128 varint.
    fn push_varint(out: &mut Vec<u8>, mut value: u64) {
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            out.push(byte);
            if value == 0 {
                break;
            }
        }
    }

    #[test]
    fn emits_node_op_and_domain() {
        // NodeProto { op_type (4) = "Foo", domain (7) = "com.evil" }
        let mut node = Vec::new();
        push_len_field(&mut node, 4, b"Foo");
        push_len_field(&mut node, 7, b"com.evil");

        // GraphProto { node (1) = <node> }
        let mut graph = Vec::new();
        push_len_field(&mut graph, 1, &node);

        // ModelProto { graph (7) = <graph> }
        let mut model = Vec::new();
        push_len_field(&mut model, 7, &graph);

        let events = walk_model(&model);
        assert_eq!(events.len(), 1);
        let e = &events[0];
        assert_eq!(e.graph_op.as_deref(), Some("Foo"));
        assert_eq!(e.graph_domain.as_deref(), Some("com.evil"));
        assert_eq!(e.offset, 0);
    }

    #[test]
    fn absent_domain_defaults_to_empty_string() {
        // NodeProto with only op_type, no domain field.
        let mut node = Vec::new();
        push_len_field(&mut node, 4, b"Bar");

        let mut graph = Vec::new();
        push_len_field(&mut graph, 1, &node);

        let mut model = Vec::new();
        push_len_field(&mut model, 7, &graph);

        let events = walk_model(&model);
        assert_eq!(events.len(), 1);
        // Domain is always set so the detector can decide.
        assert_eq!(events[0].graph_domain.as_deref(), Some(""));
        assert_eq!(events[0].graph_op.as_deref(), Some("Bar"));
    }

    #[test]
    fn multiple_nodes_get_running_index() {
        let mut node_a = Vec::new();
        push_len_field(&mut node_a, 4, b"A");
        let mut node_b = Vec::new();
        push_len_field(&mut node_b, 4, b"B");

        let mut graph = Vec::new();
        push_len_field(&mut graph, 1, &node_a);
        push_len_field(&mut graph, 1, &node_b);

        let mut model = Vec::new();
        push_len_field(&mut model, 7, &graph);

        let events = walk_model(&model);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].offset, 0);
        assert_eq!(events[1].offset, 1);
    }

    #[test]
    fn can_handle_by_extension_and_magic() {
        let p = OnnxParser;
        assert!(p.can_handle(Path::new("model.onnx"), &[]));
        assert!(p.can_handle(Path::new("MODEL.ONNX"), &[]));
        // ir_version tag byte even without the extension.
        assert!(p.can_handle(Path::new("blob.bin"), &[0x08, 0x07]));
        assert!(!p.can_handle(Path::new("blob.bin"), &[0x0a]));
        assert!(!p.can_handle(Path::new("notes.txt"), &[]));
    }
}
