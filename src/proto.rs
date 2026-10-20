//! The protobuf wire format.
//!
//! This is the encoding only, not a schema compiler. Messages are read and
//! written field by field by the code that knows their layout. The reference
//! is the "Encoding" page of the protobuf documentation.
//!
//! A varint stores an unsigned 64 bit integer in 7 bit groups, least
//! significant group first, with the high bit of each byte set when more
//! bytes follow. The longest legal varint is ten bytes, and its tenth byte
//! may only carry the single bit that is left over after nine groups of
//! seven.

/// The longest a varint may be. Ten groups of seven bits cover 64 bits.
pub const MAX_VARINT_LEN: usize = 10;

/// Why a varint or a field key could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// The input ended while the last byte still said more would follow.
    Truncated,
    /// The value does not fit in 64 bits: either an eleventh byte was
    /// announced, or the tenth byte carried more than one bit.
    Overflow,
    /// A field key named a wire type that does not exist (6 or 7), or one
    /// of the deprecated group types (3 or 4), which are not supported.
    BadWireType(u8),
    /// A field key named field number 0, which protobuf reserves.
    ZeroFieldNumber,
    /// A field number above the protobuf maximum of 2^29 - 1.
    FieldNumberTooLarge,
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::Truncated => f.write_str("varint truncated"),
            DecodeError::Overflow => f.write_str("varint overflows 64 bits"),
            DecodeError::BadWireType(t) => write!(f, "unsupported wire type {t}"),
            DecodeError::ZeroFieldNumber => f.write_str("field number 0"),
            DecodeError::FieldNumberTooLarge => f.write_str("field number above 2^29 - 1"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Appends `value` as a varint.
pub fn encode_varint(mut value: u64, out: &mut Vec<u8>) {
    while value >= 0x80 {
        out.push((value as u8) | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

/// The number of bytes [`encode_varint`] writes for `value`.
pub fn varint_len(value: u64) -> usize {
    // One byte per started group of seven significant bits, and at least
    // one byte for zero.
    let bits = 64 - value.leading_zeros() as usize;
    bits.div_ceil(7).max(1)
}

/// Reads a varint from the front of `input`.
///
/// Returns the value and how many bytes it occupied. Encodings longer than
/// necessary, such as `80 00` for zero, are accepted, because the protobuf
/// specification allows them and other implementations produce them.
pub fn decode_varint(input: &[u8]) -> Result<(u64, usize), DecodeError> {
    let mut value: u64 = 0;
    for (i, &byte) in input.iter().enumerate() {
        if i == MAX_VARINT_LEN - 1 && byte > 1 {
            // The tenth byte holds bit 63 and nothing else. Anything more,
            // including a continuation bit, cannot fit.
            return Err(DecodeError::Overflow);
        }
        value |= u64::from(byte & 0x7f) << (7 * i);
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
    }
    Err(DecodeError::Truncated)
}

/// How a field's payload is laid out on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireType {
    /// int32, int64, uint32, uint64, sint32, sint64, bool, enum.
    Varint = 0,
    /// fixed64, sfixed64, double.
    I64 = 1,
    /// string, bytes, embedded messages, packed repeated fields.
    Len = 2,
    /// fixed32, sfixed32, float.
    I32 = 5,
}

/// The largest field number protobuf allows.
pub const MAX_FIELD_NUMBER: u32 = (1 << 29) - 1;

/// Appends the key that precedes every field: the field number shifted
/// left by three, with the wire type in the low bits.
///
/// # Panics
///
/// If `field` is 0 or above [`MAX_FIELD_NUMBER`]. Field numbers come from
/// the schema, so a bad one is a bug in the caller, not bad input.
pub fn encode_key(field: u32, wire: WireType, out: &mut Vec<u8>) {
    assert!(
        (1..=MAX_FIELD_NUMBER).contains(&field),
        "field number {field} out of range"
    );
    encode_varint((u64::from(field) << 3) | wire as u64, out);
}

/// Reads a field key from the front of `input`.
///
/// Returns the field number, the wire type and the bytes consumed.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(v: u64) -> Vec<u8> {
        let mut out = Vec::new();
        encode_varint(v, &mut out);
        out
    }

    // Byte strings taken from the protobuf encoding documentation and from
    // the definition of int64, where a negative number is its two's
    // complement as an unsigned 64 bit value and always ten bytes long.
    #[test]
    fn known_encodings() {
        assert_eq!(enc(0), [0x00]);
        assert_eq!(enc(1), [0x01]);
        assert_eq!(enc(127), [0x7f]);
        assert_eq!(enc(128), [0x80, 0x01]);
        assert_eq!(enc(150), [0x96, 0x01]);
        assert_eq!(enc(300), [0xac, 0x02]);
        assert_eq!(
            enc(-1i64 as u64),
            [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]
        );
        assert_eq!(enc(u64::MAX), enc(-1i64 as u64));
    }

    #[test]
    fn known_decodings() {
        assert_eq!(decode_varint(&[0x96, 0x01]), Ok((150, 2)));
        assert_eq!(decode_varint(&[0xac, 0x02, 0xff]), Ok((300, 2)));
        assert_eq!(
            decode_varint(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]),
            Ok((u64::MAX, 10))
        );
    }

    // Every boundary where the length changes, both sides of it, plus the
    // extremes. Encoding, decoding and the length function must agree.
    #[test]
    fn round_trip_at_every_length_boundary() {
        let mut values = vec![0, 1, u64::MAX, u64::MAX - 1, 1 << 63];
        for k in 1..64 {
            let b = 1u64 << k;
            values.extend([b - 1, b, b + 1]);
        }
        for v in values {
            let bytes = enc(v);
            assert_eq!(bytes.len(), varint_len(v), "length of {v}");
            assert_eq!(decode_varint(&bytes), Ok((v, bytes.len())), "value {v}");
        }
    }

    #[test]
    fn lengths_step_every_seven_bits() {
        assert_eq!(varint_len(0), 1);
        assert_eq!(varint_len(127), 1);
        assert_eq!(varint_len(128), 2);
        assert_eq!(varint_len(16_383), 2);
        assert_eq!(varint_len(16_384), 3);
        assert_eq!(varint_len(u64::MAX), 10);
    }

    #[test]
    fn overlong_but_legal_encodings_are_accepted() {
        assert_eq!(decode_varint(&[0x80, 0x00]), Ok((0, 2)));
        assert_eq!(decode_varint(&[0x81, 0x80, 0x00]), Ok((1, 3)));
    }

    #[test]
    fn truncation_is_reported() {
        assert_eq!(decode_varint(&[]), Err(DecodeError::Truncated));
        assert_eq!(decode_varint(&[0x80]), Err(DecodeError::Truncated));
        assert_eq!(decode_varint(&[0xff; 9]), Err(DecodeError::Truncated));
    }

    #[test]
    fn values_beyond_64_bits_are_rejected() {
        // Tenth byte carrying bit 64.
        let mut too_big = vec![0xff; 9];
        too_big.push(0x02);
        assert_eq!(decode_varint(&too_big), Err(DecodeError::Overflow));
        // Tenth byte announcing an eleventh.
        let mut eleven = vec![0xff; 9];
        eleven.extend([0x81, 0x00]);
        assert_eq!(decode_varint(&eleven), Err(DecodeError::Overflow));
        // Non-minimal zero padded past ten bytes is still too long.
        let mut padded = vec![0x80; 10];
        padded.push(0x00);
        assert_eq!(decode_varint(&padded), Err(DecodeError::Overflow));
    }

    #[test]
    fn keys_from_the_documentation() {
        // Field 1, varint: the 08 in "08 96 01".
        let mut out = Vec::new();
        encode_key(1, WireType::Varint, &mut out);
        assert_eq!(out, [0x08]);
        assert_eq!(
            decode_key(&[0x08, 0x96, 0x01]),
            Ok((1, WireType::Varint, 1))
        );
        // Field 2, length delimited: the 12 in "12 07 74 65 73 74 69 6e 67".
        out.clear();
        encode_key(2, WireType::Len, &mut out);
        assert_eq!(out, [0x12]);
        assert_eq!(decode_key(&[0x12]), Ok((2, WireType::Len, 1)));
    }

    #[test]
    fn key_round_trip_for_every_wire_type_and_extreme_field() {
        for wire in [
            WireType::Varint,
            WireType::I64,
            WireType::Len,
            WireType::I32,
        ] {
            for field in [1, 15, 16, 2047, 2048, MAX_FIELD_NUMBER] {
                let mut out = Vec::new();
                encode_key(field, wire, &mut out);
                assert_eq!(decode_key(&out), Ok((field, wire, out.len())));
            }
        }
    }

    #[test]
    fn bad_keys_are_rejected() {
        for t in [3u8, 4, 6, 7] {
            assert_eq!(
                decode_key(&[(1 << 3) | t]),
                Err(DecodeError::BadWireType(t))
            );
        }
        assert_eq!(decode_key(&[0x00]), Err(DecodeError::ZeroFieldNumber));
        let mut out = Vec::new();
        encode_varint((u64::from(MAX_FIELD_NUMBER) + 1) << 3, &mut out);
        assert_eq!(decode_key(&out), Err(DecodeError::FieldNumberTooLarge));
    }

    #[test]
    #[should_panic(expected = "out of range")]
    fn encoding_field_zero_is_a_caller_bug() {
        encode_key(0, WireType::Varint, &mut Vec::new());
    }
}
