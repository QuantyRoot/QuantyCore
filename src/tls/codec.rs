//! Reading and writing the TLS presentation language (RFC 8446 section 3):
//! big endian integers and vectors with a one, two or three byte length.
//!
//! The reader never panics on hostile input. Every read returns `None`
//! past the end, and a length prefix that claims more than is left is
//! treated the same way, so the callers turn both into a `decode_error`.

#[derive(Clone, Copy)]
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader { buf }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub(crate) fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        if n > self.buf.len() {
            return None;
        }
        let (a, b) = self.buf.split_at(n);
        self.buf = b;
        Some(a)
    }

    pub(crate) fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|b| b[0])
    }

    pub(crate) fn u16(&mut self) -> Option<u16> {
        self.take(2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }

    pub(crate) fn u24(&mut self) -> Option<u32> {
        self.take(3)
            .map(|b| u32::from_be_bytes([0, b[0], b[1], b[2]]))
    }

    pub(crate) fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub(crate) fn vec8(&mut self) -> Option<&'a [u8]> {
        let n = self.u8()? as usize;
        self.take(n)
    }

    pub(crate) fn vec16(&mut self) -> Option<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }

    pub(crate) fn vec24(&mut self) -> Option<&'a [u8]> {
        let n = self.u24()? as usize;
        self.take(n)
    }

    /// `Some(())` only if nothing is left, for the end of a structure
    /// whose length was given by its container.
    pub(crate) fn end(&self) -> Option<()> {
        self.buf.is_empty().then_some(())
    }
}

pub(crate) fn put_u16(out: &mut Vec<u8>, v: u16) {
    out.extend_from_slice(&v.to_be_bytes());
}

pub(crate) fn put_u24(out: &mut Vec<u8>, v: u32) {
    debug_assert!(v < 1 << 24);
    out.extend_from_slice(&v.to_be_bytes()[1..]);
}

/// Writes what `body` writes, preceded by its length in `len_bytes`
/// bytes. Panics if it does not fit, which for the messages built here
/// would be a bug, not a property of the input.
pub(crate) fn put_vec(out: &mut Vec<u8>, len_bytes: usize, body: impl FnOnce(&mut Vec<u8>)) {
    let at = out.len();
    out.resize(at + len_bytes, 0);
    body(out);
    let n = out.len() - at - len_bytes;
    assert!(
        n < 1 << (8 * len_bytes),
        "vector too long for its length field"
    );
    let be = (n as u32).to_be_bytes();
    out[at..at + len_bytes].copy_from_slice(&be[4 - len_bytes..]);
}

pub(crate) fn put_bytes(out: &mut Vec<u8>, len_bytes: usize, data: &[u8]) {
    put_vec(out, len_bytes, |o| o.extend_from_slice(data));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_prefix_past_the_end_is_refused() {
        assert_eq!(Reader::new(&[0, 3, 1, 2]).vec16(), None);
        assert_eq!(Reader::new(&[0, 2, 1, 2]).vec16(), Some(&[1u8, 2][..]));
        assert_eq!(Reader::new(&[0, 0]).u24(), None);
        let mut out = Vec::new();
        put_vec(&mut out, 3, |o| o.extend_from_slice(&[7; 300]));
        assert_eq!(&out[..3], &[0, 1, 44]);
        assert_eq!(Reader::new(&out).vec24().unwrap().len(), 300);
    }
}
