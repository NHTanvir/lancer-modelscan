//! Parse-only walker for CPython `marshal` byte streams — used to inspect the
//! marshalled code object that Keras stores for a `Lambda` layer (plan §3).
//!
//! Like the pickle walker, this **never executes** anything. It decodes the
//! marshal object graph symbolically and harvests `co_names` (the global / attr
//! names a function references) and string constants. The Keras parser pairs
//! those tokens into `module.name` targets for the detector layer.
//!
//! marshal's `TYPE_CODE` layout drifts across Python versions (3.8 vs 3.11
//! reorder/rename fields), so we use a tolerant strategy: a best-effort
//! structural decode (correct for 3.7–3.10), unioned with a version-independent
//! linear string scan. Recall matters more than precision here — severity is
//! decided downstream by matching against the unsafe-globals table.

use crate::Limits;

/// Tokens harvested from a marshalled code object.
#[derive(Debug, Default, Clone)]
pub struct CodeScan {
    /// `co_names`-like identifiers (global/attribute names).
    pub names: Vec<String>,
    /// String constants (`co_consts` strings), e.g. shell command literals.
    pub strings: Vec<String>,
    /// Whether a `TYPE_CODE` object was seen at all.
    pub had_code: bool,
}

impl CodeScan {
    fn push_name(&mut self, s: String) {
        if !s.is_empty() && !self.names.contains(&s) {
            self.names.push(s);
        }
    }
    fn push_string(&mut self, s: String) {
        if !s.is_empty() && !self.strings.contains(&s) {
            self.strings.push(s);
        }
    }
}

/// Best-effort scan of a marshal buffer. Never errors — returns whatever it
/// could harvest.
pub fn scan(bytes: &[u8], limits: &Limits) -> CodeScan {
    let mut out = CodeScan::default();
    // 1) Structural decode (tolerant; stops a branch on any inconsistency).
    let mut cur = Cursor { buf: bytes, pos: 0 };
    let mut budget = limits.max_opcodes.min(2_000_000);
    let _ = read_object(&mut cur, &mut out, 0, limits, &mut budget);
    // 2) Linear safety-net harvest (version-independent).
    linear_harvest(bytes, &mut out, limits);
    out
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn u8(&mut self) -> Option<u8> {
        let b = self.buf.get(self.pos).copied()?;
        self.pos += 1;
        Some(b)
    }
    fn i32(&mut self) -> Option<i32> {
        if self.pos + 4 > self.buf.len() {
            return None;
        }
        let v = i32::from_le_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]);
        self.pos += 4;
        Some(v)
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if self.pos + n > self.buf.len() {
            return None;
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Some(s)
    }
}

const TYPE_NULL: u8 = b'0';
const TYPE_NONE: u8 = b'N';
const TYPE_FALSE: u8 = b'F';
const TYPE_TRUE: u8 = b'T';
const TYPE_STOPITER: u8 = b'S';
const TYPE_ELLIPSIS: u8 = b'.';
const TYPE_INT: u8 = b'i';
const TYPE_INT64: u8 = b'I';
const TYPE_FLOAT: u8 = b'f';
const TYPE_BINARY_FLOAT: u8 = b'g';
const TYPE_COMPLEX: u8 = b'x';
const TYPE_BINARY_COMPLEX: u8 = b'y';
const TYPE_LONG: u8 = b'l';
const TYPE_STRING: u8 = b's';
const TYPE_INTERNED: u8 = b't';
const TYPE_REF: u8 = b'r';
const TYPE_STRINGREF: u8 = b'R';
const TYPE_UNICODE: u8 = b'u';
const TYPE_ASCII: u8 = b'a';
const TYPE_ASCII_INTERNED: u8 = b'A';
const TYPE_SHORT_ASCII: u8 = b'z';
const TYPE_SHORT_ASCII_INTERNED: u8 = b'Z';
const TYPE_TUPLE: u8 = b'(';
const TYPE_SMALL_TUPLE: u8 = b')';
const TYPE_LIST: u8 = b'[';
const TYPE_DICT: u8 = b'{';
const TYPE_SET: u8 = b'<';
const TYPE_FROZENSET: u8 = b'>';
const TYPE_CODE: u8 = b'c';

/// Where a harvested string should go.
#[derive(Clone, Copy, PartialEq)]
enum Sink {
    Names,
    Strings,
}

fn read_object(
    cur: &mut Cursor,
    out: &mut CodeScan,
    depth: usize,
    limits: &Limits,
    budget: &mut u64,
) -> Option<()> {
    read_object_into(cur, out, depth, limits, budget, Sink::Strings)
}

fn read_object_into(
    cur: &mut Cursor,
    out: &mut CodeScan,
    depth: usize,
    limits: &Limits,
    budget: &mut u64,
    sink: Sink,
) -> Option<()> {
    if depth > limits.max_marshal_depth || *budget == 0 {
        return None;
    }
    *budget -= 1;
    let raw = cur.u8()?;
    let ty = raw & 0x7f; // strip FLAG_REF (0x80)
    match ty {
        TYPE_NULL | TYPE_NONE | TYPE_FALSE | TYPE_TRUE | TYPE_STOPITER | TYPE_ELLIPSIS => Some(()),
        TYPE_INT => {
            cur.i32()?;
            Some(())
        }
        TYPE_INT64 => {
            cur.take(8)?;
            Some(())
        }
        TYPE_BINARY_FLOAT => {
            cur.take(8)?;
            Some(())
        }
        TYPE_BINARY_COMPLEX => {
            cur.take(16)?;
            Some(())
        }
        TYPE_FLOAT | TYPE_COMPLEX => {
            // 1-byte length-prefixed ascii repr(s)
            let n = cur.u8()? as usize;
            cur.take(n)?;
            Some(())
        }
        TYPE_LONG => {
            let ndigits = cur.i32()?;
            let n = ndigits.unsigned_abs() as usize;
            cur.take(n.checked_mul(2)?)?;
            Some(())
        }
        TYPE_REF | TYPE_STRINGREF => {
            cur.i32()?;
            Some(())
        }
        TYPE_STRING | TYPE_INTERNED | TYPE_UNICODE | TYPE_ASCII | TYPE_ASCII_INTERNED => {
            let n = cur.i32()?;
            if n < 0 || n as usize > limits.max_string_len {
                return None;
            }
            let bytes = cur.take(n as usize)?;
            let s = String::from_utf8_lossy(bytes).into_owned();
            match sink {
                Sink::Names => out.push_name(s),
                Sink::Strings => out.push_string(s),
            }
            Some(())
        }
        TYPE_SHORT_ASCII | TYPE_SHORT_ASCII_INTERNED => {
            let n = cur.u8()? as usize;
            let bytes = cur.take(n)?;
            let s = String::from_utf8_lossy(bytes).into_owned();
            match sink {
                Sink::Names => out.push_name(s),
                Sink::Strings => out.push_string(s),
            }
            Some(())
        }
        TYPE_SMALL_TUPLE => {
            let n = cur.u8()? as usize;
            for _ in 0..n {
                read_object_into(cur, out, depth + 1, limits, budget, sink)?;
            }
            Some(())
        }
        TYPE_TUPLE | TYPE_LIST | TYPE_SET | TYPE_FROZENSET => {
            let n = cur.i32()?;
            if n < 0 || n as u64 > 100_000 {
                return None;
            }
            for _ in 0..n {
                read_object_into(cur, out, depth + 1, limits, budget, sink)?;
            }
            Some(())
        }
        TYPE_DICT => {
            // key, value pairs until a TYPE_NULL key
            loop {
                let save = cur.pos;
                let peek = cur.u8()?;
                if (peek & 0x7f) == TYPE_NULL {
                    break;
                }
                cur.pos = save;
                read_object_into(cur, out, depth + 1, limits, budget, sink)?; // key
                read_object_into(cur, out, depth + 1, limits, budget, sink)?; // value
            }
            Some(())
        }
        TYPE_CODE => {
            out.had_code = true;
            read_code(cur, out, depth + 1, limits, budget)
        }
        _ => None, // unknown — stop this branch tolerantly
    }
}

/// Parse a `TYPE_CODE` body using the CPython 3.7–3.10 field order. On any
/// inconsistency we just stop — the linear harvest backstops missed names.
fn read_code(
    cur: &mut Cursor,
    out: &mut CodeScan,
    depth: usize,
    limits: &Limits,
    budget: &mut u64,
) -> Option<()> {
    // Leading int32 header fields (argcount, posonly, kwonly, nlocals,
    // stacksize, flags). 3.11 drops nlocals; the extra read just consumes part
    // of co_code's tag, after which we stop gracefully.
    for _ in 0..6 {
        cur.i32()?;
    }
    // co_code (bytes)
    read_object_into(cur, out, depth, limits, budget, Sink::Strings)?;
    // co_consts (recurse; may contain nested code objects)
    read_object_into(cur, out, depth, limits, budget, Sink::Strings)?;
    // co_names (the interesting one — global/attr identifiers)
    read_object_into(cur, out, depth, limits, budget, Sink::Names)?;
    // The remaining fields (varnames, freevars, cellvars, filename, name,
    // firstlineno, lnotab) are not needed; leave them for the linear pass.
    Some(())
}

/// Version-independent linear scan: walk the buffer and pull out every
/// plausibly-textual marshal string, classifying identifier-like tokens as
/// names. Over-collects slightly; that's fine (severity is decided later).
fn linear_harvest(buf: &[u8], out: &mut CodeScan, limits: &Limits) {
    let mut i = 0usize;
    while i < buf.len() {
        let ty = buf[i] & 0x7f;
        match ty {
            TYPE_STRING | TYPE_INTERNED | TYPE_UNICODE | TYPE_ASCII | TYPE_ASCII_INTERNED => {
                if i + 5 > buf.len() {
                    i += 1;
                    continue;
                }
                let n = i32::from_le_bytes([buf[i + 1], buf[i + 2], buf[i + 3], buf[i + 4]]);
                if n < 0 || n as usize > limits.max_string_len || i + 5 + n as usize > buf.len() {
                    i += 1;
                    continue;
                }
                let s = &buf[i + 5..i + 5 + n as usize];
                classify(s, out);
                i += 5 + n as usize;
            }
            TYPE_SHORT_ASCII | TYPE_SHORT_ASCII_INTERNED => {
                if i + 2 > buf.len() {
                    i += 1;
                    continue;
                }
                let n = buf[i + 1] as usize;
                if i + 2 + n > buf.len() {
                    i += 1;
                    continue;
                }
                classify(&buf[i + 2..i + 2 + n], out);
                i += 2 + n;
            }
            _ => i += 1,
        }
    }
}

fn classify(bytes: &[u8], out: &mut CodeScan) {
    if bytes.is_empty() || bytes.len() > 256 {
        return;
    }
    let s = String::from_utf8_lossy(bytes).into_owned();
    let identifier_like = s
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.');
    if identifier_like && !s.is_empty() {
        out.push_name(s);
    } else if s.is_ascii() {
        out.push_string(s);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn harvests_short_ascii_names() {
        // SHORT_ASCII_INTERNED "os" then "system"
        let mut b = Vec::new();
        b.push(TYPE_SHORT_ASCII_INTERNED);
        b.push(2);
        b.extend_from_slice(b"os");
        b.push(TYPE_SHORT_ASCII_INTERNED);
        b.push(6);
        b.extend_from_slice(b"system");
        let scan = scan(&b, &Limits::default());
        assert!(scan.names.iter().any(|n| n == "os"));
        assert!(scan.names.iter().any(|n| n == "system"));
    }
}
