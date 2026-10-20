//! The record layer: framing, protection and reassembly of handshake
//! messages (RFC 8446 section 5).

use super::crypto::ct;
use super::error::{alert, Error};
use super::key_schedule::traffic_keys;
use super::msgs::{content, Handshake};
use super::suites::{AeadAlg, RecordCipher, Suite};

pub const MAX_PLAINTEXT: usize = 1 << 14;
/// TLS 1.3 allows 256 bytes of expansion (5.2), TLS 1.2 2048 (RFC 5246
/// 6.2.3). A record longer than the version in use allows is a
/// record_overflow; before the version is known the larger bound holds.
pub const MAX_CIPHERTEXT_13: usize = MAX_PLAINTEXT + 256;
pub const MAX_CIPHERTEXT_12: usize = MAX_PLAINTEXT + 2048;

/// A handshake message larger than this is refused before it is
/// buffered. Certificate chains are the largest messages in practice and
/// stay far below it.
pub const MAX_HANDSHAKE_MESSAGE: usize = 1 << 18;

pub struct RawRecord {
    pub typ: u8,
    pub version: u16,
    pub payload: Vec<u8>,
}

#[derive(Default)]
pub struct Deframer {
    buf: Vec<u8>,
    pub max_ciphertext: usize,
}

impl Deframer {
    pub fn new() -> Deframer {
        Deframer {
            buf: Vec::new(),
            max_ciphertext: MAX_CIPHERTEXT_12,
        }
    }

    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// The next complete record, if one has arrived. The header is checked
    /// as soon as it is complete, so garbage is refused after five bytes
    /// instead of after buffering whatever length it claims.
    pub fn pop(&mut self) -> Result<Option<RawRecord>, Error> {
        if self.buf.len() < 5 {
            return Ok(None);
        }
        let typ = self.buf[0];
        let version = u16::from_be_bytes([self.buf[1], self.buf[2]]);
        let len = u16::from_be_bytes([self.buf[3], self.buf[4]]) as usize;
        if !matches!(
            typ,
            content::CHANGE_CIPHER_SPEC
                | content::ALERT
                | content::HANDSHAKE
                | content::APPLICATION_DATA
        ) {
            return Err(Error::unexpected("unknown record type"));
        }
        if version >> 8 != 3 {
            return Err(Error::decode("record version"));
        }
        if len > self.max_ciphertext {
            return Err(Error::new(alert::RECORD_OVERFLOW, "record too long"));
        }
        if self.buf.len() < 5 + len {
            return Ok(None);
        }
        let payload = self.buf[5..5 + len].to_vec();
        self.buf.drain(..5 + len);
        Ok(Some(RawRecord {
            typ,
            version,
            payload,
        }))
    }
}

/// One direction's record protection: cipher, static IV and sequence
/// number.
pub struct Protection {
    cipher: RecordCipher,
    iv: [u8; 12],
    seq: u64,
    limit: u64,
}

impl Protection {
    pub fn tls13(suite: Suite, secret: &[u8]) -> Protection {
        let k = traffic_keys(suite.hash, secret, suite.aead.key_len());
        Protection {
            cipher: suite.aead.cipher(k.key.expose()),
            iv: k.iv,
            seq: 0,
            limit: suite.aead.record_limit(),
        }
    }

    pub fn from_parts(aead: AeadAlg, key: &[u8], iv: [u8; 12]) -> Protection {
        Protection {
            cipher: aead.cipher(key),
            iv,
            seq: 0,
            limit: aead.record_limit(),
        }
    }

    /// The per-record nonce of RFC 8446 5.3: the sequence number, left
    /// padded, xored into the IV.
    fn nonce(&self) -> [u8; 12] {
        let mut n = self.iv;
        for (a, b) in n[4..].iter_mut().zip(self.seq.to_be_bytes()) {
            *a ^= b;
        }
        n
    }

    /// True once this key has protected as many records as it safely can.
    /// The sender then has to switch keys with a KeyUpdate.
    pub fn exhausted(&self) -> bool {
        self.seq >= self.limit
    }

    /// Appends one protected TLS 1.3 record holding `data` of type `typ`
    /// to `out`.
    pub fn seal13(&mut self, typ: u8, data: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        debug_assert!(data.len() <= MAX_PLAINTEXT);
        if self.seq == u64::MAX {
            return Err(Error::internal("sequence number exhausted"));
        }
        let mut inner = Vec::with_capacity(data.len() + 1 + 16);
        inner.extend_from_slice(data);
        inner.push(typ);
        let len = inner.len() + 16;
        let header = [content::APPLICATION_DATA, 3, 3, (len >> 8) as u8, len as u8];
        let nonce = self.nonce();
        self.cipher.seal(&nonce, &header, &mut inner);
        self.seq += 1;
        out.extend_from_slice(&header);
        out.extend_from_slice(&inner);
        ct::wipe(&mut inner);
        Ok(())
    }

    /// Opens a TLS 1.3 record and returns its real type and content with
    /// the padding removed.
    pub fn open13(&mut self, rec: RawRecord) -> Result<(u8, Vec<u8>), Error> {
        if rec.typ != content::APPLICATION_DATA {
            return Err(Error::unexpected("unprotected record after keys changed"));
        }
        if rec.payload.len() > MAX_CIPHERTEXT_13 {
            return Err(Error::new(alert::RECORD_OVERFLOW, "record too long"));
        }
        if self.seq == u64::MAX {
            return Err(Error::internal("sequence number exhausted"));
        }
        let len = rec.payload.len();
        let header = [
            rec.typ,
            (rec.version >> 8) as u8,
            rec.version as u8,
            (len >> 8) as u8,
            len as u8,
        ];
        let nonce = self.nonce();
        let mut buf = rec.payload;
        self.cipher
            .open(&nonce, &header, &mut buf)
            .map_err(|_| Error::new(alert::BAD_RECORD_MAC, "record failed authentication"))?;
        self.seq += 1;
        // The padding is zeros after the type byte. Its length is not
        // secret from the peer that chose it, so a plain scan is fine.
        let Some(end) = buf.iter().rposition(|&b| b != 0) else {
            return Err(Error::unexpected("record with no content type"));
        };
        let typ = buf[end];
        buf.truncate(end);
        if buf.len() > MAX_PLAINTEXT {
            return Err(Error::new(alert::RECORD_OVERFLOW, "plaintext too long"));
        }
        Ok((typ, buf))
    }
}

/// Collects handshake messages that are split across records or packed
/// several to a record.
#[derive(Default)]
pub struct HandshakeJoiner {
    buf: Vec<u8>,
}

impl HandshakeJoiner {
    pub fn push(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// True when a message is partly received. Keys must not change then
    /// (RFC 8446 5.1): the rest would arrive under different protection.
    pub fn is_mid_message(&self) -> bool {
        !self.buf.is_empty()
    }

    pub fn pop(&mut self) -> Result<Option<(Handshake, Vec<u8>)>, Error> {
        if self.buf.len() < 4 {
            return Ok(None);
        }
        let len = u32::from_be_bytes([0, self.buf[1], self.buf[2], self.buf[3]]) as usize;
        if len > MAX_HANDSHAKE_MESSAGE {
            return Err(Error::illegal("handshake message too large"));
        }
        if self.buf.len() < 4 + len {
            return Ok(None);
        }
        let raw: Vec<u8> = self.buf.drain(..4 + len).collect();
        let msg = Handshake::new(raw[0], raw[4..].to_vec());
        Ok(Some((msg, raw)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::suites::TLS_AES_128_GCM_SHA256;

    #[test]
    fn padding_is_removed_and_an_all_zero_record_refused() {
        let secret = [5u8; 32];
        let mut tx = Protection::tls13(TLS_AES_128_GCM_SHA256, &secret);
        let mut rx = Protection::tls13(TLS_AES_128_GCM_SHA256, &secret);
        let mut out = Vec::new();
        tx.seal13(content::HANDSHAKE, b"abc", &mut out).unwrap();
        let mut d = Deframer::new();
        d.push(&out);
        let (typ, body) = rx.open13(d.pop().unwrap().unwrap()).unwrap();
        assert_eq!((typ, body.as_slice()), (content::HANDSHAKE, &b"abc"[..]));

        // A record whose inner plaintext is only padding: seal raw zeros
        // with type 0, which leaves nothing that is not zero.
        let mut out = Vec::new();
        tx.seal13(0, &[0, 0, 0], &mut out).unwrap();
        d.push(&out);
        assert_eq!(
            rx.open13(d.pop().unwrap().unwrap()).unwrap_err(),
            Error::unexpected("record with no content type")
        );
    }

    #[test]
    fn records_out_of_order_fail_authentication() {
        let secret = [9u8; 32];
        let mut tx = Protection::tls13(TLS_AES_128_GCM_SHA256, &secret);
        let mut rx = Protection::tls13(TLS_AES_128_GCM_SHA256, &secret);
        let (mut a, mut b) = (Vec::new(), Vec::new());
        tx.seal13(content::APPLICATION_DATA, b"first", &mut a)
            .unwrap();
        tx.seal13(content::APPLICATION_DATA, b"second", &mut b)
            .unwrap();
        let mut d = Deframer::new();
        d.push(&b);
        let e = rx.open13(d.pop().unwrap().unwrap()).unwrap_err();
        assert_eq!(
            e,
            Error::new(alert::BAD_RECORD_MAC, "record failed authentication")
        );
    }

    #[test]
    fn oversized_records_are_refused_from_the_header() {
        let mut d = Deframer::new();
        d.max_ciphertext = MAX_CIPHERTEXT_13;
        let n = MAX_CIPHERTEXT_13 + 1;
        d.push(&[23, 3, 3, (n >> 8) as u8, n as u8]);
        assert!(matches!(
            d.pop(),
            Err(Error::Local {
                alert: alert::RECORD_OVERFLOW,
                ..
            })
        ));
    }
}
