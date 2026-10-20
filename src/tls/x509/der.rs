//! A strict DER reader (X.690). Strict because a certificate parser that
//! accepts two encodings of the same value lets an attacker present a
//! certificate that two verifiers read differently.
//!
//! Refused: indefinite lengths, lengths not in their shortest form, tags
//! above 30, and anything after the outermost value.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DerError(pub &'static str);

impl std::fmt::Display for DerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "malformed DER: {}", self.0)
    }
}

impl std::error::Error for DerError {}

pub mod tag {
    pub const BOOLEAN: u8 = 0x01;
    pub const INTEGER: u8 = 0x02;
    pub const BIT_STRING: u8 = 0x03;
    pub const OCTET_STRING: u8 = 0x04;
    pub const NULL: u8 = 0x05;
    pub const OID: u8 = 0x06;
    pub const UTF8_STRING: u8 = 0x0c;
    pub const PRINTABLE_STRING: u8 = 0x13;
    pub const IA5_STRING: u8 = 0x16;
    pub const UTC_TIME: u8 = 0x17;
    pub const GENERALIZED_TIME: u8 = 0x18;
    pub const SEQUENCE: u8 = 0x30;
    pub const SET: u8 = 0x31;

    pub const fn context(n: u8) -> u8 {
        0x80 | n
    }
    pub const fn context_constructed(n: u8) -> u8 {
        0xa0 | n
    }
}

#[derive(Clone, Copy)]
pub struct Der<'a> {
    buf: &'a [u8],
}

pub type Result<T> = std::result::Result<T, DerError>;

impl<'a> Der<'a> {
    pub fn new(buf: &'a [u8]) -> Der<'a> {
        Der { buf }
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn peek_tag(&self) -> Option<u8> {
        self.buf.first().copied()
    }

    /// The next value: its tag, its contents, and the whole encoding.
    pub fn read(&mut self) -> Result<(u8, &'a [u8], &'a [u8])> {
        let b = self.buf;
        let tag = *b.first().ok_or(DerError("truncated tag"))?;
        if tag & 0x1f == 0x1f {
            return Err(DerError("high tag number"));
        }
        let first = *b.get(1).ok_or(DerError("truncated length"))?;
        let (len, hdr) = if first < 0x80 {
            (first as usize, 2)
        } else {
            let n = (first & 0x7f) as usize;
            if n == 0 {
                return Err(DerError("indefinite length"));
            }
            if n > 4 {
                return Err(DerError("length too large"));
            }
            let bytes = b.get(2..2 + n).ok_or(DerError("truncated length"))?;
            if bytes[0] == 0 {
                return Err(DerError("length not minimal"));
            }
            let len = bytes.iter().fold(0usize, |a, &x| (a << 8) | x as usize);
            if len < 0x80 {
                return Err(DerError("length not minimal"));
            }
            (len, 2 + n)
        };
        let end = hdr.checked_add(len).ok_or(DerError("length overflow"))?;
        let whole = b.get(..end).ok_or(DerError("truncated value"))?;
        self.buf = &b[end..];
        Ok((tag, &whole[hdr..], whole))
    }

    pub fn expect(&mut self, want: u8) -> Result<&'a [u8]> {
        let (t, v, _) = self.read()?;
        if t != want {
            return Err(DerError("unexpected tag"));
        }
        Ok(v)
    }

    /// Like `expect`, also returning the whole encoding.
    pub fn expect_whole(&mut self, want: u8) -> Result<(&'a [u8], &'a [u8])> {
        let (t, v, w) = self.read()?;
        if t != want {
            return Err(DerError("unexpected tag"));
        }
        Ok((v, w))
    }

    pub fn optional(&mut self, want: u8) -> Result<Option<&'a [u8]>> {
        if self.peek_tag() == Some(want) {
            self.expect(want).map(Some)
        } else {
            Ok(None)
        }
    }

    pub fn sequence(&mut self) -> Result<Der<'a>> {
        self.expect(tag::SEQUENCE).map(Der::new)
    }

    pub fn end(&self) -> Result<()> {
        if self.buf.is_empty() {
            Ok(())
        } else {
            Err(DerError("trailing data"))
        }
    }

    /// DER BOOLEAN: exactly 0x00 or 0xff.
    pub fn boolean(&mut self) -> Result<bool> {
        match self.expect(tag::BOOLEAN)? {
            [0x00] => Ok(false),
            [0xff] => Ok(true),
            _ => Err(DerError("BOOLEAN")),
        }
    }

    /// The bytes of an INTEGER, checked for minimal encoding, sign
    /// included.
    pub fn integer(&mut self) -> Result<&'a [u8]> {
        let v = self.expect(tag::INTEGER)?;
        check_integer(v)?;
        Ok(v)
    }

    /// A nonnegative INTEGER without its sign byte.
    pub fn unsigned(&mut self) -> Result<&'a [u8]> {
        let v = self.integer()?;
        if v[0] & 0x80 != 0 {
            return Err(DerError("negative INTEGER"));
        }
        Ok(if v.len() > 1 && v[0] == 0 { &v[1..] } else { v })
    }

    pub fn small_unsigned(&mut self) -> Result<u64> {
        let v = self.unsigned()?;
        if v.len() > 8 {
            return Err(DerError("INTEGER too large"));
        }
        Ok(v.iter().fold(0u64, |a, &x| (a << 8) | x as u64))
    }

    /// A BIT STRING with no unused bits, as keys and signatures are.
    pub fn bit_string_bytes(&mut self) -> Result<&'a [u8]> {
        let v = self.expect(tag::BIT_STRING)?;
        match v.split_first() {
            Some((0, rest)) => Ok(rest),
            _ => Err(DerError("BIT STRING with unused bits")),
        }
    }

    pub fn oid(&mut self) -> Result<&'a [u8]> {
        let v = self.expect(tag::OID)?;
        if v.is_empty() || v.last().unwrap() & 0x80 != 0 {
            return Err(DerError("OID"));
        }
        Ok(v)
    }
}

fn check_integer(v: &[u8]) -> Result<()> {
    match v {
        [] => Err(DerError("empty INTEGER")),
        [0, b, ..] if b & 0x80 == 0 => Err(DerError("INTEGER not minimal")),
        [0xff, b, ..] if b & 0x80 != 0 => Err(DerError("INTEGER not minimal")),
        _ => Ok(()),
    }
}

/// A BIT STRING used as a set of flags, such as KeyUsage: bit 0 is the
/// most significant bit of the first byte. DER requires the unused bits
/// to be zero and the trailing zero bits to be dropped.
pub fn named_bits(v: &[u8]) -> Result<u16> {
    let (&unused, bits) = v.split_first().ok_or(DerError("BIT STRING"))?;
    if unused > 7 || (bits.is_empty() && unused != 0) || bits.len() > 2 {
        return Err(DerError("BIT STRING"));
    }
    if let Some(&last) = bits.last() {
        if last & ((1u8 << unused) - 1) != 0 {
            return Err(DerError("BIT STRING unused bits set"));
        }
        if last == 0 {
            return Err(DerError("BIT STRING not minimal"));
        }
    }
    let mut out = 0u16;
    for (i, b) in bits.iter().enumerate() {
        for j in 0..8 {
            if b & (0x80 >> j) != 0 {
                out |= 1 << (8 * i + j);
            }
        }
    }
    Ok(out)
}

/// Writes a DER value: tag, minimal length, contents.
pub fn write(out: &mut Vec<u8>, tag: u8, contents: &[u8]) {
    out.push(tag);
    let n = contents.len();
    if n < 0x80 {
        out.push(n as u8);
    } else {
        let be = (n as u32).to_be_bytes();
        let skip = be.iter().take_while(|&&b| b == 0).count();
        out.push(0x80 | (4 - skip) as u8);
        out.extend_from_slice(&be[skip..]);
    }
    out.extend_from_slice(contents);
}

pub fn wrap(tag: u8, contents: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(contents.len() + 6);
    write(&mut out, tag, contents);
    out
}

/// An unsigned big endian number as a DER INTEGER.
pub fn write_unsigned(out: &mut Vec<u8>, n: &[u8]) {
    let skip = n
        .iter()
        .take_while(|&&b| b == 0)
        .count()
        .min(n.len().saturating_sub(1));
    let n = &n[skip..];
    if n.is_empty() {
        write(out, tag::INTEGER, &[0]);
    } else if n[0] & 0x80 != 0 {
        let mut v = vec![0];
        v.extend_from_slice(n);
        write(out, tag::INTEGER, &v);
    } else {
        write(out, tag::INTEGER, n);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_minimal_encodings_are_refused() {
        assert!(Der::new(&[0x04, 0x81, 0x05, 1, 2, 3, 4, 5]).read().is_err());
        assert!(Der::new(&[0x04, 0x82, 0x00, 0x80]).read().is_err());
        assert!(Der::new(&[0x04, 0x80, 0, 0]).read().is_err());
        assert!(Der::new(&[0x02, 0x02, 0x00, 0x01]).integer().is_err());
        assert!(Der::new(&[0x02, 0x02, 0xff, 0x80]).integer().is_err());
        assert_eq!(
            Der::new(&[0x02, 0x02, 0x00, 0x80]).unsigned().unwrap(),
            &[0x80]
        );
        assert!(Der::new(&[0x01, 0x01, 0x01]).boolean().is_err());
        assert!(Der::new(&[0x1f, 0x01, 0x00]).read().is_err());
        let long = wrap(tag::OCTET_STRING, &[7; 200]);
        assert_eq!(&long[..3], &[0x04, 0x81, 200]);
        assert_eq!(
            Der::new(&long).expect(tag::OCTET_STRING).unwrap().len(),
            200
        );
    }

    #[test]
    fn key_usage_bits() {
        // digitalSignature (0) and keyCertSign (5): 1000_0100, two unused.
        assert_eq!(named_bits(&[2, 0x84]).unwrap(), 1 | 1 << 5);
        assert!(named_bits(&[1, 0x84]).is_ok());
        assert!(named_bits(&[3, 0x84]).is_err());
        assert!(named_bits(&[0, 0x84, 0x00]).is_err());
    }
}
