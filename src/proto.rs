//! The protobuf wire format, without a schema compiler: messages are read
//! and written field by field by code that knows their layout.
//!
//! Writers follow proto3 and leave out fields that hold their default
//! value, which is what other implementations expect and what keeps
//! messages byte for byte comparable with theirs.

pub const MAX_VARINT_LEN: usize = 10;
pub const MAX_FIELD_NUMBER: u32 = (1 << 29) - 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    Truncated,
    Overflow,
    /// 3 and 4 are the deprecated group types, 6 and 7 do not exist.
    BadWireType(u8),
    ZeroFieldNumber,
    FieldNumberTooLarge,
    /// The field exists in the schema with a different wire type.
    WrongWireType(u32),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::Truncated => f.write_str("message truncated"),
            DecodeError::Overflow => f.write_str("varint overflows 64 bits"),
            DecodeError::BadWireType(t) => write!(f, "unsupported wire type {t}"),
            DecodeError::ZeroFieldNumber => f.write_str("field number 0"),
            DecodeError::FieldNumberTooLarge => f.write_str("field number above 2^29 - 1"),
            DecodeError::WrongWireType(n) => write!(f, "field {n} has the wrong wire type"),
        }
    }
}

impl std::error::Error for DecodeError {}

pub fn encode_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

pub fn varint_len(value: u64) -> usize {
    let bits = 64 - value.leading_zeros() as usize;
    bits.div_ceil(7).max(1)
}

/// Returns the value and the bytes it occupied. Non-minimal encodings such
/// as `80 00` are accepted: the specification allows them and some
/// encoders produce them.
pub fn decode_varint(input: &[u8]) -> Result<(u64, usize), DecodeError> {
    let mut value: u64 = 0;
    for (i, &byte) in input.iter().enumerate() {
        // Nine groups of seven leave exactly one bit for the tenth byte.
        if i == MAX_VARINT_LEN - 1 && byte > 1 {
            return Err(DecodeError::Overflow);
        }
        value |= u64::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
    }
    Err(DecodeError::Truncated)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireType {
    Varint = 0,
    I64 = 1,
    Len = 2,
    I32 = 5,
}

/// # Panics
///
/// If `field` is outside 1 to [`MAX_FIELD_NUMBER`]. Field numbers come
/// from the schema, so a bad one is a bug, not bad input.
pub fn encode_key(field: u32, wire: WireType, out: &mut Vec<u8>) {
    assert!(
        (1..=MAX_FIELD_NUMBER).contains(&field),
        "field number {field} out of range"
    );
    encode_varint((u64::from(field) << 3) | wire as u64, out);
}

pub fn decode_key(input: &[u8]) -> Result<(u32, WireType, usize), DecodeError> {
    let (raw, used) = decode_varint(input)?;
    let wire = match raw & 7 {
        0 => WireType::Varint,
        1 => WireType::I64,
        2 => WireType::Len,
        5 => WireType::I32,
        other => return Err(DecodeError::BadWireType(other as u8)),
    };
    let field = raw >> 3;
    if field == 0 {
        return Err(DecodeError::ZeroFieldNumber);
    }
    if field > u64::from(MAX_FIELD_NUMBER) {
        return Err(DecodeError::FieldNumberTooLarge);
    }
    Ok((field as u32, wire, used))
}

/// One field as it appeared on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Value<'a> {
    Varint(u64),
    I64(u64),
    Len(&'a [u8]),
    I32(u32),
}

impl<'a> Value<'a> {
    pub fn uint(self, field: u32) -> Result<u64, DecodeError> {
        match self {
            Value::Varint(v) => Ok(v),
            _ => Err(DecodeError::WrongWireType(field)),
        }
    }

    /// int64 and int32 are plain varints of the two's complement, so a
    /// negative number always takes ten bytes.
    pub fn int(self, field: u32) -> Result<i64, DecodeError> {
        self.uint(field).map(|v| v as i64)
    }

    pub fn bool(self, field: u32) -> Result<bool, DecodeError> {
        self.uint(field).map(|v| v != 0)
    }

    pub fn bytes(self, field: u32) -> Result<&'a [u8], DecodeError> {
        match self {
            Value::Len(b) => Ok(b),
            _ => Err(DecodeError::WrongWireType(field)),
        }
    }
}

/// Walks the fields of one message. Unknown fields are returned like any
/// other; callers skip what they do not know, as protobuf requires.
pub struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf }
    }

    pub fn next_field(&mut self) -> Result<Option<(u32, Value<'a>)>, DecodeError> {
        if self.buf.is_empty() {
            return Ok(None);
        }
        let (field, wire, used) = decode_key(self.buf)?;
        let rest = &self.buf[used..];
        let (value, len) = match wire {
            WireType::Varint => {
                let (v, n) = decode_varint(rest)?;
                (Value::Varint(v), n)
            }
            WireType::I64 => {
                let b = rest.get(..8).ok_or(DecodeError::Truncated)?;
                (Value::I64(u64::from_le_bytes(b.try_into().unwrap())), 8)
            }
            WireType::I32 => {
                let b = rest.get(..4).ok_or(DecodeError::Truncated)?;
                (Value::I32(u32::from_le_bytes(b.try_into().unwrap())), 4)
            }
            WireType::Len => {
                let (n, h) = decode_varint(rest)?;
                let end = usize::try_from(n)
                    .ok()
                    .and_then(|n| n.checked_add(h))
                    .ok_or(DecodeError::Truncated)?;
                let b = rest.get(h..end).ok_or(DecodeError::Truncated)?;
                (Value::Len(b), end)
            }
        };
        self.buf = &rest[len..];
        Ok(Some((field, value)))
    }
}

pub fn put_uint(out: &mut Vec<u8>, field: u32, v: u64) {
    if v != 0 {
        encode_key(field, WireType::Varint, out);
        encode_varint(v, out);
    }
}

pub fn put_int(out: &mut Vec<u8>, field: u32, v: i64) {
    put_uint(out, field, v as u64);
}

pub fn put_bool(out: &mut Vec<u8>, field: u32, v: bool) {
    put_uint(out, field, u64::from(v));
}

pub fn put_bytes(out: &mut Vec<u8>, field: u32, v: &[u8]) {
    if !v.is_empty() {
        put_len(out, field, v);
    }
}

/// An embedded message is written even when empty: unlike a scalar, its
/// presence is observable.
pub fn put_message(out: &mut Vec<u8>, field: u32, encoded: &[u8]) {
    put_len(out, field, encoded);
}

fn put_len(out: &mut Vec<u8>, field: u32, v: &[u8]) {
    encode_key(field, WireType::Len, out);
    encode_varint(v.len() as u64, out);
    out.extend_from_slice(v);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        encode_varint(v, &mut out);
        out
    }

    // From the protobuf encoding documentation.
    #[test]
    fn known_encodings() {
        assert_eq!(enc(1), [0x01]);
        assert_eq!(enc(150), [0x96, 0x01]);
        assert_eq!(enc(300), [0xac, 0x02]);
        assert_eq!(
            enc(-1i64 as u64),
            [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]
        );
        assert_eq!(decode_varint(&[0xac, 0x02, 0xff]), Ok((300, 2)));
    }

    #[test]
    fn round_trip_at_every_length_boundary() {
        let mut values = vec![0, u64::MAX];
        for k in 1..64 {
            let b = 1u64 << k;
            values.extend([b - 1, b]);
        }
        for v in values {
            let bytes = enc(v);
            assert_eq!(bytes.len(), varint_len(v), "length of {v}");
            assert_eq!(decode_varint(&bytes), Ok((v, bytes.len())), "value {v}");
        }
    }

    #[test]
    fn malformed_varints() {
        assert_eq!(decode_varint(&[0x80, 0x00]), Ok((0, 2)));
        assert_eq!(decode_varint(&[0xff; 9]), Err(DecodeError::Truncated));
        let mut too_big = vec![0xff; 9];
        too_big.push(0x02);
        assert_eq!(decode_varint(&too_big), Err(DecodeError::Overflow));
        let mut padded = vec![0x80; 10];
        padded.push(0x00);
        assert_eq!(decode_varint(&padded), Err(DecodeError::Overflow));
    }

    #[test]
    fn keys() {
        assert_eq!(decode_key(&[0x08]), Ok((1, WireType::Varint, 1)));
        assert_eq!(decode_key(&[0x12]), Ok((2, WireType::Len, 1)));
        let mut out = Vec::new();
        encode_key(MAX_FIELD_NUMBER, WireType::I32, &mut out);
        assert_eq!(
            decode_key(&out),
            Ok((MAX_FIELD_NUMBER, WireType::I32, out.len()))
        );
        for t in [3u8, 4, 6, 7] {
            assert_eq!(
                decode_key(&[(1 << 3) | t]),
                Err(DecodeError::BadWireType(t))
            );
        }
        assert_eq!(decode_key(&[0x00]), Err(DecodeError::ZeroFieldNumber));
        out.clear();
        encode_varint((u64::from(MAX_FIELD_NUMBER) + 1) << 3, &mut out);
        assert_eq!(decode_key(&out), Err(DecodeError::FieldNumberTooLarge));
    }

    #[test]
    fn a_message_round_trips_and_defaults_are_left_out() {
        let mut inner = Vec::new();
        put_bytes(&mut inner, 1, b"key");
        let mut msg = Vec::new();
        put_int(&mut msg, 1, -5);
        put_uint(&mut msg, 2, 0);
        put_bool(&mut msg, 3, true);
        put_bytes(&mut msg, 4, b"");
        put_message(&mut msg, 5, &inner);
        put_message(&mut msg, 6, &[]);
        msg.extend([0x39, 1, 2, 3, 4, 5, 6, 7, 8]);

        let mut r = Reader::new(&msg);
        let mut seen = Vec::new();
        while let Some((f, v)) = r.next_field().unwrap() {
            seen.push((f, v));
        }
        assert_eq!(
            seen,
            [
                (1, Value::Varint(-5i64 as u64)),
                (3, Value::Varint(1)),
                (5, Value::Len(&inner)),
                (6, Value::Len(&[])),
                (7, Value::I64(0x0807_0605_0403_0201)),
            ]
        );
        assert_eq!(seen[0].1.int(1), Ok(-5));
        assert_eq!(seen[2].1.uint(5), Err(DecodeError::WrongWireType(5)));
    }

    #[test]
    fn a_length_past_the_end_is_truncation() {
        let mut r = Reader::new(&[0x0a, 0x05, b'a']);
        assert_eq!(r.next_field(), Err(DecodeError::Truncated));
        let mut huge = vec![0x0a];
        encode_varint(u64::MAX, &mut huge);
        assert_eq!(Reader::new(&huge).next_field(), Err(DecodeError::Truncated));
    }
}
