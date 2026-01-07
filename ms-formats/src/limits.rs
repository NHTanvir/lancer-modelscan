//! Resource caps that keep adversarial / "bomb" files from exhausting memory
//! or CPU during a parse-only walk. See plan §8 (memory-bounded pickle walking).

/// Caps applied by the stream walkers. Above any cap, the walker stops and
/// emits a single "bomb" [`crate::Event`] (note set), rather than panicking or
/// allocating unboundedly.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// Max simulated stack depth (pickle/marshal). Default 10_000.
    pub max_stack_depth: usize,
    /// Max memo entries. Default 100_000.
    pub max_memo: usize,
    /// Max length of a single string/bytes object to materialize. Default 16 MiB.
    pub max_string_len: usize,
    /// Max total opcodes processed. Default 10_000_000.
    pub max_opcodes: u64,
    /// Max bytes read from any single container member (zip/hdf5 dataset). Default 256 MiB.
    pub max_member_bytes: u64,
    /// Max nesting depth for marshal code objects. Default 64.
    pub max_marshal_depth: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_stack_depth: 10_000,
            max_memo: 100_000,
            max_string_len: 16 * 1024 * 1024,
            max_opcodes: 10_000_000,
            max_member_bytes: 256 * 1024 * 1024,
            max_marshal_depth: 64,
        }
    }
}
