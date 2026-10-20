//! The TLS 1.3 key schedule (RFC 8446 section 7).
//!
//! Only secrets come out of here; turning them into record keys is the
//! record layer's job. That split is what a QUIC transport would need: it
//! takes the same traffic secrets and derives its own packet keys.

use super::codec::{put_bytes, put_u16};
use super::crypto::ct::{self, Secret};
use super::crypto::hkdf;
use super::crypto::hmac::Hmac;
use super::crypto::sha2::HashAlg;

/// HKDF-Expand-Label (RFC 8446 7.1). `label` is without the "tls13 "
/// prefix.
pub fn expand_label(
    hash: HashAlg,
    secret: &[u8],
    label: &[u8],
    context: &[u8],
    len: usize,
) -> Secret {
    let mut info = Vec::with_capacity(4 + 6 + label.len() + context.len());
    put_u16(&mut info, len as u16);
    let mut full = b"tls13 ".to_vec();
    full.extend_from_slice(label);
    put_bytes(&mut info, 1, &full);
    put_bytes(&mut info, 1, context);
    hkdf::expand(hash, secret, &info, len).expect("TLS labels ask for at most one hash length")
}

/// Derive-Secret: `transcript_hash` is the hash of the messages, already
/// computed.
pub fn derive_secret(hash: HashAlg, secret: &[u8], label: &[u8], transcript_hash: &[u8]) -> Secret {
    expand_label(hash, secret, label, transcript_hash, hash.output_len())
}

/// The record keys for one traffic secret.
pub struct TrafficKeys {
    pub key: Secret,
    pub iv: [u8; 12],
}

pub fn traffic_keys(hash: HashAlg, secret: &[u8], key_len: usize) -> TrafficKeys {
    let key = expand_label(hash, secret, b"key", b"", key_len);
    let iv = expand_label(hash, secret, b"iv", b"", 12);
    TrafficKeys {
        key,
        iv: iv.expose().try_into().unwrap(),
    }
}

/// The verify_data of a Finished message sent under `base_secret`.
pub fn finished_verify_data(hash: HashAlg, base_secret: &[u8], transcript_hash: &[u8]) -> Vec<u8> {
    let key = expand_label(hash, base_secret, b"finished", b"", hash.output_len());
    let mut h = Hmac::new(hash, key.expose());
    h.update(transcript_hash);
    h.finish()
}

/// The next application traffic secret after a KeyUpdate (7.2).
pub fn next_traffic_secret(hash: HashAlg, secret: &[u8]) -> Secret {
    expand_label(hash, secret, b"traffic upd", b"", hash.output_len())
}

/// The PSK a NewSessionTicket stands for (4.6.1).
pub fn resumption_psk(hash: HashAlg, resumption_master: &[u8], nonce: &[u8]) -> Secret {
    expand_label(
        hash,
        resumption_master,
        b"resumption",
        nonce,
        hash.output_len(),
    )
}

/// TLS-Exporter (7.5).
pub fn export(
    hash: HashAlg,
    exporter_master: &[u8],
    label: &[u8],
    context: &[u8],
    len: usize,
) -> Secret {
    let empty = hash.digest(b"");
    let s = derive_secret(hash, exporter_master, label, &empty);
    let ctx = hash.digest(context);
    expand_label(hash, s.expose(), b"exporter", &ctx, len)
}

/// The secrets of one handshake, advanced stage by stage. Each stage
/// replaces the secret before it, so a key schedule that has reached the
/// master secret no longer holds the handshake secret.
pub struct KeySchedule {
    pub hash: HashAlg,
    current: Secret,
}

impl KeySchedule {
    /// The early secret, from a PSK or, without one, from zeros.
    pub fn new(hash: HashAlg, psk: Option<&[u8]>) -> KeySchedule {
        let zeros = vec![0u8; hash.output_len()];
        let current = hkdf::extract(hash, &zeros, psk.unwrap_or(&zeros));
        KeySchedule { hash, current }
    }

    /// The binder key for a resumption PSK (4.2.11.2).
    pub fn resumption_binder_key(&self) -> Secret {
        let empty = self.hash.digest(b"");
        derive_secret(self.hash, self.current.expose(), b"res binder", &empty)
    }

    fn advance(&mut self, ikm: Option<&[u8]>) {
        let empty = self.hash.digest(b"");
        let derived = derive_secret(self.hash, self.current.expose(), b"derived", &empty);
        let zeros = vec![0u8; self.hash.output_len()];
        self.current = hkdf::extract(self.hash, derived.expose(), ikm.unwrap_or(&zeros));
    }

    /// Mixes in the (EC)DHE shared secret: early secret to handshake secret.
    pub fn into_handshake(&mut self, shared: &[u8]) {
        self.advance(Some(shared));
    }

    /// Handshake secret to master secret.
    pub fn into_master(&mut self) {
        self.advance(None);
    }

    /// Derive-Secret from the current stage, e.g. "c hs traffic" after
    /// `into_handshake` or "c ap traffic" after `into_master`.
    pub fn derive(&self, label: &[u8], transcript_hash: &[u8]) -> Secret {
        derive_secret(self.hash, self.current.expose(), label, transcript_hash)
    }

    #[cfg(test)]
    pub(crate) fn current(&self) -> &[u8] {
        self.current.expose()
    }
}

impl std::fmt::Debug for KeySchedule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KeySchedule({:?})", self.hash)
    }
}

/// Constant time comparison of a received Finished against the expected
/// one.
pub fn verify_finished(expected: &[u8], received: &[u8]) -> bool {
    ct::eq(expected, received)
}

/// The TLS 1.2 PRF (RFC 5246 5): P_hash over `label || seed`.
pub fn prf12(hash: HashAlg, secret: &[u8], label: &[u8], seed: &[u8], len: usize) -> Secret {
    let mut ls = label.to_vec();
    ls.extend_from_slice(seed);
    let base = Hmac::new(hash, secret);
    let mut a = {
        let mut h = base.clone();
        h.update(&ls);
        h.finish()
    };
    let mut buf = Vec::with_capacity(len + hash.output_len());
    while buf.len() < len {
        let mut h = base.clone();
        h.update(&a);
        h.update(&ls);
        buf.extend(h.finish());
        let mut h = base.clone();
        h.update(&a);
        a = h.finish();
    }
    buf.truncate(len);
    ct::wipe(&mut a);
    Secret::new(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // The P_SHA256 example circulated on the IETF TLS list and used by
    // most implementations' tests; checked against OpenSSL's TLS1-PRF.
    #[test]
    fn tls12_prf_sha256() {
        let out = prf12(
            HashAlg::Sha256,
            &hex("9bbe436ba940f017b17652849a71db35"),
            b"test label",
            &hex("a0ba9f936cda311827a6f796ffd5198c"),
            100,
        );
        assert_eq!(
            out.expose(),
            hex(
                "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a
                 6b301791e90d35c9c9a46b4e14baf9af0fa022f7077def17abfd3797c0564bab
                 4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff701
                 87347b66"
            )
        );
    }

    // The first steps of RFC 8448 section 3, which pin the label encoding
    // and the empty-hash context; the full trace runs in CI.
    #[test]
    fn rfc_8448_early_and_derived() {
        let ks = KeySchedule::new(HashAlg::Sha256, None);
        assert_eq!(
            ks.current(),
            hex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a")
        );
        let empty = HashAlg::Sha256.digest(b"");
        let derived = derive_secret(HashAlg::Sha256, ks.current(), b"derived", &empty);
        assert_eq!(
            derived.expose(),
            hex("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba")
        );
    }
}
