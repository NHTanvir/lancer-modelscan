//! A tiny, dependency-free protobuf wire-format reader.
//!
//! We do **not** generate types from `.proto` files (no `prost`, no `protoc`).
//! ONNX and TensorFlow models only need a structural walk — find specific field
//! numbers, descend into nested messages, read op-name / domain strings — so a
//! generic field walker is simpler, self-contained, and immune to schema drift.
//!
//! Wire format reference (developers.google.com/protocol-buffers/docs/encoding):
//! each field is a varint tag `(field_number << 3) | wire_type`, followed by a
//! payload whose shape depends on the wire type.

/// Errors from malformed protobuf input.
#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error("unexpected end of protobuf input")]
    Eof,
    #[error("varint too long / overflow")]
    VarintOverflow,
    #[error("invalid wire type {0}")]
    BadWireType(u8),
    #[error("length-delimited field overruns buffer")]
    LengthOverrun,
}

/// A decoded field value.
#[derive(Debug, Clone)]
pub enum WireValue<'a> {
    Varint(u64),
    Fixed64([u8; 8]),
    /// Length-delimited: a string, bytes, or nested message.
    Len(&'a [u8]),
    Fixed32([u8; 4]),
}

/// One field: its number and value.
#[derive(Debug, Clone)]
pub struct Field<'a> {
    pub number: u32,
    pub value: WireValue<'a>,
}

impl<'a> Field<'a> {
    /// The payload bytes if this is a length-delimited field.
    pub fn bytes(&self) -> Option<&'a [u8]> {
        match self.value {
            WireValue::Len(b) => Some(b),
            _ => None,
        }
    }

    /// The payload as a UTF-8 string (lossy) if length-delimited.
    pub fn as_str(&self) -> Option<String> {
        self.bytes().map(|b| String::from_utf8_lossy(b).into_owned())
    }

    /// Interpret a length-delimited payload as a nested message reader.
    pub fn as_message(&self) -> Option<ProtoReader<'a>> {
        self.bytes().map(ProtoReader::new)
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self.value {
            WireValue::Varint(v) => Some(v),
            _ => None,
        }
    }
}

/// A forward reader over a protobuf message buffer.
#[derive(Debug, Clone)]
pub struct ProtoReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> ProtoReader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        ProtoReader { buf, pos: 0 }
    }

    pub fn is_done(&self) -> bool {
        self.pos >= self.buf.len()
    }

    fn read_varint(&mut self) -> Result<u64, ProtoError> {
        let mut result: u64 = 0;
        let mut shift = 0;
        loop {
            let byte = *self.buf.get(self.pos).ok_or(ProtoError::Eof)?;
            self.pos += 1;
            result |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
            if shift >= 64 {
                return Err(ProtoError::VarintOverflow);
            }
        }
        Ok(result)
    }

    /// Read the next field, or `None` at end of buffer.
    pub fn next_field(&mut self) -> Result<Option<Field<'a>>, ProtoError> {
        if self.is_done() {
            return Ok(None);
        }
        let tag = self.read_varint()?;
        let number = (tag >> 3) as u32;
        let wire_type = (tag & 0x07) as u8;
        let value = match wire_type {
            0 => WireValue::Varint(self.read_varint()?),
            1 => {
                let b = self.take(8)?;
                let mut a = [0u8; 8];
                a.copy_from_slice(b);
                WireValue::Fixed64(a)
            }
            2 => {
                let len = self.read_varint()? as usize;
                WireValue::Len(self.take(len)?)
            }
            5 => {
                let b = self.take(4)?;
                let mut a = [0u8; 4];
                a.copy_from_slice(b);
                WireValue::Fixed32(a)
            }
            // Wire types 3/4 (start/end group) are deprecated; treat as error
            // so callers stop rather than misread.
            other => return Err(ProtoError::BadWireType(other)),
        };
        Ok(Some(Field { number, value }))
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ProtoError> {
        let end = self.pos.checked_add(n).ok_or(ProtoError::LengthOverrun)?;
        if end > self.buf.len() {
            return Err(ProtoError::LengthOverrun);
        }
        let s = &self.buf[self.pos..end];
        self.pos = end;
        Ok(s)
    }

    /// Convenience: collect all fields with a given number that are
    /// length-delimited, as nested message readers. Skips on malformed tail.
    pub fn messages_with(&self, number: u32) -> Vec<ProtoReader<'a>> {
        let mut reader = ProtoReader::new(self.buf);
        let mut out = Vec::new();
        while let Ok(Some(field)) = reader.next_field() {
            if field.number == number {
                if let Some(m) = field.as_message() {
                    out.push(m);
                }
            }
        }
        out
    }

    /// Convenience: first length-delimited string field with `number`.
    pub fn first_str(&self, number: u32) -> Option<String> {
        let mut reader = ProtoReader::new(self.buf);
        while let Ok(Some(field)) = reader.next_field() {
            if field.number == number {
                if let Some(s) = field.as_str() {
                    return Some(s);
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_string_field() {
        // field 1, wire type 2, len 3, "abc"
        let buf = [0x0a, 0x03, b'a', b'b', b'c'];
        let r = ProtoReader::new(&buf);
        assert_eq!(r.first_str(1).as_deref(), Some("abc"));
    }

    #[test]
    fn reads_varint_field() {
        // field 2, wire type 0, value 150 (0x96 0x01)
        let buf = [0x10, 0x96, 0x01];
        let mut r = ProtoReader::new(&buf);
        let f = r.next_field().unwrap().unwrap();
        assert_eq!(f.number, 2);
        assert_eq!(f.as_u64(), Some(150));
    }
}
