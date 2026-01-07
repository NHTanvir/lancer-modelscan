//! Parse-only pickle opcode walker (protocols 0–5).
//!
//! This is the heart of the scanner. It simulates pickle's stack machine
//! *symbolically* — pushing markers like [`Sym::Global`] instead of resolving
//! objects — so it can identify which `module.name` callables a pickle would
//! invoke on load **without ever importing, `getattr`-ing, or calling
//! `__reduce__`**. It mirrors CPython's `pickletools.genops()`: a pure operand
//! reader that advances byte-for-byte through the stream.
//!
//! It emits one [`Event`] per *global reference* (`GLOBAL` / `STACK_GLOBAL` /
//! `INST` / `OBJ`) — the canonical "this dangerous thing is referenced" signal
//! that picklescan / modelscan key on. Resource caps ([`Limits`]) bound stack
//! depth, memo size, string length, and opcode count; exceeding any emits a
//! "bomb" event (note set) and stops gracefully.

use std::collections::HashMap;
use std::io::{BufReader, Read};

use crate::{Event, Limits, ParseError, PickleOpcode};

/// A symbolic value on the simulated stack. We only track what we need to find
/// global callables; everything else is `Opaque`.
#[derive(Debug, Clone)]
enum Sym {
    Mark,
    Global(String, String),
    Str(String),
    Opaque,
}

/// Streaming reader with a byte-position counter and read caps.
struct Reader<R: Read> {
    inner: R,
    pos: u64,
}

impl<R: Read> Reader<R> {
    fn new(inner: R) -> Self {
        Reader { inner, pos: 0 }
    }

    /// Read one byte, or `None` at clean EOF.
    fn u8(&mut self) -> Result<Option<u8>, ParseError> {
        let mut b = [0u8; 1];
        loop {
            match self.inner.read(&mut b) {
                Ok(0) => return Ok(None),
                Ok(_) => {
                    self.pos += 1;
                    return Ok(Some(b[0]));
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(ParseError::Io(e)),
            }
        }
    }

    fn u8_req(&mut self, what: &'static str) -> Result<u8, ParseError> {
        self.u8()?
            .ok_or_else(|| ParseError::malformed("pickle", format!("EOF reading {what}")))
    }

    /// Read exactly `n` bytes.
    fn take(&mut self, n: usize) -> Result<Vec<u8>, ParseError> {
        let mut buf = vec![0u8; n];
        self.inner
            .read_exact(&mut buf)
            .map_err(|e| ParseError::malformed("pickle", format!("EOF reading {n} bytes: {e}")))?;
        self.pos += n as u64;
        Ok(buf)
    }

    /// Skip exactly `n` bytes without materializing them (for big binary blobs).
    fn skip(&mut self, n: u64) -> Result<(), ParseError> {
        let mut remaining = n;
        let mut buf = [0u8; 8192];
        while remaining > 0 {
            let want = remaining.min(buf.len() as u64) as usize;
            self.inner
                .read_exact(&mut buf[..want])
                .map_err(|e| ParseError::malformed("pickle", format!("EOF skipping bytes: {e}")))?;
            remaining -= want as u64;
        }
        self.pos += n;
        Ok(())
    }

    /// Read a `\n`-terminated line (newline consumed, not included).
    fn line(&mut self, cap: usize) -> Result<Vec<u8>, ParseError> {
        let mut out = Vec::new();
        loop {
            match self.u8()? {
                None => {
                    return Err(ParseError::malformed("pickle", "EOF reading text line"));
                }
                Some(b'\n') => break,
                Some(b) => {
                    out.push(b);
                    if out.len() > cap {
                        return Err(ParseError::Limit(format!(
                            "text line exceeds {cap} bytes"
                        )));
                    }
                }
            }
        }
        Ok(out)
    }

    fn u16_le(&mut self) -> Result<u16, ParseError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    fn u32_le(&mut self) -> Result<u32, ParseError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn i32_le(&mut self) -> Result<i32, ParseError> {
        let b = self.take(4)?;
        Ok(i32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64_le(&mut self) -> Result<u64, ParseError> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }
}

/// Walk a pickle stream, returning all global-reference events. Stops at the
/// first `STOP` opcode or clean EOF; tolerates malformed tails.
pub fn walk(reader: &mut dyn Read, limits: &Limits) -> Result<Vec<Event>, ParseError> {
    let mut r = Reader::new(BufReader::new(reader));
    let mut stack: Vec<Sym> = Vec::new();
    let mut marks: Vec<usize> = Vec::new();
    let mut memo: HashMap<u32, Sym> = HashMap::new();
    let mut memo_counter: u32 = 0;
    let mut events: Vec<Event> = Vec::new();
    let mut opcodes: u64 = 0;

    // Helper to emit a bomb event and signal stop.
    macro_rules! bomb {
        ($offset:expr, $reason:expr) => {{
            let mut e = Event::default();
            e.offset = $offset;
            e.note = Some(format!("bomb: {}", $reason));
            events.push(e);
            return Ok(events);
        }};
    }

    loop {
        let op_offset = r.pos;
        opcodes += 1;
        if opcodes > limits.max_opcodes {
            bomb!(op_offset, format!("opcode count exceeds {}", limits.max_opcodes));
        }
        if stack.len() > limits.max_stack_depth {
            bomb!(op_offset, format!("stack depth exceeds {}", limits.max_stack_depth));
        }
        if memo.len() > limits.max_memo {
            bomb!(op_offset, format!("memo entries exceed {}", limits.max_memo));
        }

        let opcode = match r.u8()? {
            None => break, // clean EOF
            Some(b) => b,
        };

        match opcode {
            // ---- framing / protocol ----
            0x80 => {
                let _proto = r.u8_req("PROTO version")?;
            }
            0x95 => {
                let _frame_len = r.u64_le()?; // FRAME — informational only
            }
            b'.' => break, // STOP

            // ---- markers ----
            b'(' => {
                marks.push(stack.len());
                stack.push(Sym::Mark);
            }
            b'1' => {
                pop_to_mark(&mut stack, &mut marks);
            }
            b'0' => {
                stack.pop();
            }
            b'2' => {
                if let Some(top) = stack.last().cloned() {
                    stack.push(top);
                }
            }

            // ---- memo ----
            b'p' => {
                let idx: u32 = parse_decimal(&r.line(limits.max_string_len)?)?;
                memoize(&mut memo, idx, stack.last());
            }
            b'q' => {
                let idx = r.u8_req("BINPUT index")? as u32;
                memoize(&mut memo, idx, stack.last());
            }
            b'r' => {
                let idx = r.u32_le()?;
                memoize(&mut memo, idx, stack.last());
            }
            0x94 => {
                let idx = memo_counter;
                memo_counter += 1;
                memoize(&mut memo, idx, stack.last());
            }
            b'g' => {
                let idx: u32 = parse_decimal(&r.line(limits.max_string_len)?)?;
                stack.push(memo.get(&idx).cloned().unwrap_or(Sym::Opaque));
            }
            b'h' => {
                let idx = r.u8_req("BINGET index")? as u32;
                stack.push(memo.get(&idx).cloned().unwrap_or(Sym::Opaque));
            }
            b'j' => {
                let idx = r.u32_le()?;
                stack.push(memo.get(&idx).cloned().unwrap_or(Sym::Opaque));
            }

            // ---- scalars ----
            b'N' => stack.push(Sym::Opaque),
            0x88 | 0x89 => stack.push(Sym::Opaque), // NEWTRUE / NEWFALSE
            b'I' | b'L' | b'F' => {
                let _ = r.line(limits.max_string_len)?;
                stack.push(Sym::Opaque);
            }
            b'J' => {
                let _ = r.i32_le()?;
                stack.push(Sym::Opaque);
            }
            b'K' => {
                let _ = r.u8_req("BININT1")?;
                stack.push(Sym::Opaque);
            }
            b'M' => {
                let _ = r.u16_le()?;
                stack.push(Sym::Opaque);
            }
            b'G' => {
                let _ = r.take(8)?; // BINFLOAT (big-endian double)
                stack.push(Sym::Opaque);
            }
            0x8a => {
                let n = r.u8_req("LONG1 length")? as usize;
                let _ = r.take(n)?;
                stack.push(Sym::Opaque);
            }
            0x8b => {
                let n = r.u32_le()? as u64;
                if n > limits.max_string_len as u64 {
                    bomb!(op_offset, format!("LONG4 length {n} exceeds cap"));
                }
                r.skip(n)?;
                stack.push(Sym::Opaque);
            }

            // ---- text strings (push as Sym::Str) ----
            b'S' | b'V' => {
                let line = r.line(limits.max_string_len)?;
                stack.push(Sym::Str(String::from_utf8_lossy(&line).into_owned()));
            }
            // ---- length-prefixed strings ----
            b'U' => {
                let n = r.u8_req("SHORT_BINSTRING length")? as usize;
                let s = read_str(&mut r, n, limits, op_offset)?;
                stack.push(Sym::Str(s));
            }
            b'T' => {
                let n = r.i32_le()?;
                if n < 0 || n as u64 > limits.max_string_len as u64 {
                    bomb!(op_offset, format!("BINSTRING length {n} invalid/over cap"));
                }
                let s = read_str(&mut r, n as usize, limits, op_offset)?;
                stack.push(Sym::Str(s));
            }
            0x8c => {
                let n = r.u8_req("SHORT_BINUNICODE length")? as usize;
                let s = read_str(&mut r, n, limits, op_offset)?;
                stack.push(Sym::Str(s));
            }
            b'X' => {
                let n = r.u32_le()? as u64;
                if n > limits.max_string_len as u64 {
                    bomb!(op_offset, format!("BINUNICODE length {n} exceeds cap"));
                }
                let s = read_str(&mut r, n as usize, limits, op_offset)?;
                stack.push(Sym::Str(s));
            }
            0x8d => {
                let n = r.u64_le()?;
                if n > limits.max_string_len as u64 {
                    bomb!(op_offset, format!("BINUNICODE8 length {n} exceeds cap"));
                }
                let s = read_str(&mut r, n as usize, limits, op_offset)?;
                stack.push(Sym::Str(s));
            }
            // ---- length-prefixed bytes (don't materialize; skip) ----
            b'C' => {
                let n = r.u8_req("SHORT_BINBYTES length")? as u64;
                r.skip(n)?;
                stack.push(Sym::Opaque);
            }
            b'B' => {
                let n = r.u32_le()? as u64;
                if n > limits.max_string_len as u64 {
                    bomb!(op_offset, format!("BINBYTES length {n} exceeds cap"));
                }
                r.skip(n)?;
                stack.push(Sym::Opaque);
            }
            0x8e | 0x96 => {
                // BINBYTES8 / BYTEARRAY8
                let n = r.u64_le()?;
                if n > limits.max_member_bytes {
                    bomb!(op_offset, format!("BINBYTES8/BYTEARRAY8 length {n} exceeds cap"));
                }
                r.skip(n)?;
                stack.push(Sym::Opaque);
            }

            // ---- containers ----
            b']' | b')' | b'}' | 0x8f => stack.push(Sym::Opaque), // EMPTY_LIST/TUPLE/DICT/SET
            b'a' => {
                stack.pop();
            } // APPEND
            b'e' => {
                pop_to_mark(&mut stack, &mut marks);
            } // APPENDS
            b's' => {
                stack.pop();
                stack.pop();
            } // SETITEM
            b'u' | 0x90 => {
                pop_to_mark(&mut stack, &mut marks);
            } // SETITEMS / ADDITEMS
            b'l' | b'd' | b't' | 0x91 => {
                // LIST / DICT / TUPLE / FROZENSET — collapse to opaque
                pop_to_mark(&mut stack, &mut marks);
                stack.push(Sym::Opaque);
            }
            0x85 => {
                stack.pop();
                stack.push(Sym::Opaque);
            } // TUPLE1
            0x86 => {
                stack.pop();
                stack.pop();
                stack.push(Sym::Opaque);
            } // TUPLE2
            0x87 => {
                stack.pop();
                stack.pop();
                stack.pop();
                stack.push(Sym::Opaque);
            } // TUPLE3

            // ---- the dangerous set: global references ----
            b'c' => {
                // GLOBAL module\nname\n
                let module = read_text(&mut r, limits)?;
                let name = read_text(&mut r, limits)?;
                events.push(Event::global(
                    PickleOpcode::Global,
                    &module,
                    &name,
                    op_offset,
                    stack.len(),
                ));
                stack.push(Sym::Global(module, name));
            }
            0x93 => {
                // STACK_GLOBAL — pops name then module (both strings).
                let name = pop_str(&mut stack);
                let module = pop_str(&mut stack);
                events.push(Event::global(
                    PickleOpcode::StackGlobal,
                    &module,
                    &name,
                    op_offset,
                    stack.len(),
                ));
                stack.push(Sym::Global(module, name));
            }
            b'i' => {
                // INST module\nname\n ; consumes args down to MARK.
                let module = read_text(&mut r, limits)?;
                let name = read_text(&mut r, limits)?;
                pop_to_mark(&mut stack, &mut marks);
                events.push(Event::global(
                    PickleOpcode::Inst,
                    &module,
                    &name,
                    op_offset,
                    stack.len(),
                ));
                stack.push(Sym::Opaque);
            }
            b'o' => {
                // OBJ — callable is the first item after the MARK.
                let callable = callable_at_mark(&stack, &marks);
                pop_to_mark(&mut stack, &mut marks);
                if let Sym::Global(m, n) = callable {
                    events.push(Event::global(PickleOpcode::Obj, &m, &n, op_offset, stack.len()));
                }
                stack.push(Sym::Opaque);
            }
            b'R' => {
                // REDUCE — pops (callable, args). The callable was already
                // emitted at its GLOBAL/STACK_GLOBAL push, so we only adjust
                // the stack here (avoids double-counting the same target).
                stack.pop();
                stack.pop();
                stack.push(Sym::Opaque);
            }
            0x81 => {
                // NEWOBJ — pops (cls, args).
                stack.pop();
                stack.pop();
                stack.push(Sym::Opaque);
            }
            0x92 => {
                // NEWOBJ_EX — pops (cls, args, kwargs).
                stack.pop();
                stack.pop();
                stack.pop();
                stack.push(Sym::Opaque);
            }
            b'b' => {
                // BUILD — pops state; the object stays on the stack.
                stack.pop();
            }

            // ---- copyreg extensions ----
            0x82 => {
                let code = r.u8_req("EXT1")? as u64;
                push_ext(&mut events, op_offset, code, &mut stack);
            }
            0x83 => {
                let code = r.u16_le()? as u64;
                push_ext(&mut events, op_offset, code, &mut stack);
            }
            0x84 => {
                let code = r.u32_le()? as u64;
                push_ext(&mut events, op_offset, code, &mut stack);
            }

            // ---- persistent id ----
            b'P' => {
                let _id = r.line(limits.max_string_len)?;
                stack.push(Sym::Opaque);
            }
            b'Q' => {
                stack.pop();
                stack.push(Sym::Opaque);
            }

            // ---- proto-5 out-of-band buffers ----
            0x97 => stack.push(Sym::Opaque), // NEXT_BUFFER
            0x98 => {}                        // READONLY_BUFFER (no stack effect)

            other => {
                // Unknown opcode: stop tolerantly rather than desync.
                let mut e = Event::default();
                e.offset = op_offset;
                e.note = Some(format!("unknown pickle opcode 0x{other:02x}; stopping walk"));
                events.push(e);
                break;
            }
        }
    }

    Ok(events)
}

/// Convenience: walk a byte slice.
pub fn walk_bytes(bytes: &[u8], limits: &Limits) -> Result<Vec<Event>, ParseError> {
    let mut cursor = std::io::Cursor::new(bytes);
    walk(&mut cursor, limits)
}

// ---------------------------------------------------------------------------
// helpers

fn read_str<R: Read>(
    r: &mut Reader<R>,
    n: usize,
    limits: &Limits,
    op_offset: u64,
) -> Result<String, ParseError> {
    if n > limits.max_string_len {
        return Err(ParseError::Limit(format!(
            "string length {n} exceeds {} at offset {op_offset}",
            limits.max_string_len
        )));
    }
    let bytes = r.take(n)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// Read a `\n`-terminated module/name token for GLOBAL/INST.
fn read_text<R: Read>(r: &mut Reader<R>, limits: &Limits) -> Result<String, ParseError> {
    let line = r.line(limits.max_string_len)?;
    Ok(String::from_utf8_lossy(&line).trim_end().to_string())
}

fn parse_decimal(bytes: &[u8]) -> Result<u32, ParseError> {
    let s = String::from_utf8_lossy(bytes);
    s.trim()
        .parse::<u32>()
        .map_err(|_| ParseError::malformed("pickle", format!("bad memo index '{s}'")))
}

fn memoize(memo: &mut HashMap<u32, Sym>, idx: u32, top: Option<&Sym>) {
    if let Some(v) = top {
        memo.insert(idx, v.clone());
    }
}

/// Pop everything down to (and including) the most recent MARK.
fn pop_to_mark(stack: &mut Vec<Sym>, marks: &mut Vec<usize>) {
    if let Some(m) = marks.pop() {
        stack.truncate(m);
    } else {
        // No mark: clear conservatively to keep the stack from growing wrong.
        stack.clear();
    }
}

/// The callable just above the most recent MARK (for OBJ).
fn callable_at_mark(stack: &[Sym], marks: &[usize]) -> Sym {
    if let Some(&m) = marks.last() {
        stack.get(m).cloned().unwrap_or(Sym::Opaque)
    } else {
        Sym::Opaque
    }
}

fn pop_str(stack: &mut Vec<Sym>) -> String {
    match stack.pop() {
        Some(Sym::Str(s)) => s,
        Some(Sym::Global(m, n)) => format!("{m}.{n}"),
        _ => "<dynamic>".to_string(),
    }
}

fn push_ext(events: &mut Vec<Event>, offset: u64, code: u64, stack: &mut Vec<Sym>) {
    let mut e = Event::default();
    e.offset = offset;
    e.note = Some(format!("copyreg extension code {code}"));
    events.push(e);
    stack.push(Sym::Opaque);
}

/// Common raw-pickle file extensions (lowercase, no dot).
pub const PICKLE_EXTENSIONS: &[&str] = &[
    "pkl", "pickle", "pck", "pk", "dat", "model", "ckpt", "bin", "pt", "pth", "npy",
];

/// `Parser` for raw pickle streams. Registered last in the sniff order so
/// container formats (zip/hdf5/proto) claim their files first; this catches
/// pre-1.6 PyTorch `.pt`, `pytorch_model.bin`, and bare `*.pkl`.
pub struct PickleParser;

impl crate::Parser for PickleParser {
    fn id(&self) -> &str {
        "pickle"
    }

    fn can_handle(&self, path: &std::path::Path, magic: &[u8]) -> bool {
        // The PROTO opcode (0x80) starts any protocol-2+ pickle.
        if magic.first() == Some(&0x80) {
            return true;
        }
        // Otherwise fall back to extension (protocol-0 pickles are ascii).
        match path.extension().and_then(|e| e.to_str()) {
            Some(ext) => PICKLE_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()),
            None => false,
        }
    }

    fn parse_path(&self, path: &std::path::Path, limits: &Limits) -> Result<Vec<Event>, ParseError> {
        let mut f = std::fs::File::open(path)?;
        walk(&mut f, limits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `GLOBAL os system` + tuple + REDUCE, protocol 2.
    fn os_system_pickle() -> Vec<u8> {
        // \x80\x02  PROTO 2
        // c os\nsystem\n  GLOBAL
        // q\x00       BINPUT 0
        // X\x06...echo hi  BINUNICODE
        // \x85        TUPLE1
        // R           REDUCE
        // .           STOP
        let mut p = vec![0x80, 0x02];
        p.extend_from_slice(b"cos\nsystem\n");
        p.extend_from_slice(&[b'q', 0x00]);
        let arg = b"echo hi";
        p.push(b'X');
        p.extend_from_slice(&(arg.len() as u32).to_le_bytes());
        p.extend_from_slice(arg);
        p.push(0x85); // TUPLE1
        p.push(b'R'); // REDUCE
        p.push(b'.'); // STOP
        p
    }

    #[test]
    fn detects_os_system_global() {
        let p = os_system_pickle();
        let events = walk_bytes(&p, &Limits::default()).unwrap();
        let g = events
            .iter()
            .find(|e| e.target_module.as_deref() == Some("os"))
            .expect("should find os global");
        assert_eq!(g.target_name.as_deref(), Some("system"));
        assert_eq!(g.opcode, Some(PickleOpcode::Global));
    }

    #[test]
    fn empty_stops_cleanly() {
        let events = walk_bytes(&[b'.'], &Limits::default()).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn stack_global_protocol4() {
        // \x80\x04 PROTO 4
        // \x8c\x02 os  SHORT_BINUNICODE "os"
        // \x8c\x06 system SHORT_BINUNICODE "system"
        // \x93 STACK_GLOBAL
        // .
        let mut p = vec![0x80, 0x04];
        p.extend_from_slice(&[0x8c, 2]);
        p.extend_from_slice(b"os");
        p.extend_from_slice(&[0x8c, 6]);
        p.extend_from_slice(b"system");
        p.push(0x93);
        p.push(b'.');
        let events = walk_bytes(&p, &Limits::default()).unwrap();
        let g = events
            .iter()
            .find(|e| e.opcode == Some(PickleOpcode::StackGlobal))
            .expect("stack_global event");
        assert_eq!(g.target_module.as_deref(), Some("os"));
        assert_eq!(g.target_name.as_deref(), Some("system"));
    }

    #[test]
    fn bomb_on_huge_binunicode() {
        // BINUNICODE with a 4 GiB length must bomb, not allocate.
        let mut p = vec![0x80, 0x04, b'X'];
        p.extend_from_slice(&u32::MAX.to_le_bytes());
        let events = walk_bytes(&p, &Limits::default()).unwrap();
        assert!(events.iter().any(|e| e
            .note
            .as_deref()
            .map(|n| n.contains("bomb"))
            .unwrap_or(false)));
    }
}
