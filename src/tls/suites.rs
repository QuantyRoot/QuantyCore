//! Cipher suites and the record ciphers behind them.

use super::crypto::aead::{Aead, AeadError, NONCE_LEN};
use super::crypto::chacha20poly1305::ChaCha20Poly1305;
use super::crypto::gcm::AesGcm;
use super::crypto::sha2::HashAlg;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AeadAlg {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl AeadAlg {
    pub fn key_len(self) -> usize {
        match self {
            AeadAlg::Aes128Gcm => 16,
            AeadAlg::Aes256Gcm | AeadAlg::ChaCha20Poly1305 => 32,
        }
    }

    pub(crate) fn cipher(self, key: &[u8]) -> RecordCipher {
        match self {
            AeadAlg::Aes128Gcm | AeadAlg::Aes256Gcm => RecordCipher::Gcm(AesGcm::new(key)),
            AeadAlg::ChaCha20Poly1305 => RecordCipher::ChaCha(ChaCha20Poly1305::new(key)),
        }
    }

    /// How many records one key may protect before it has to be replaced.
    /// For AES-GCM, RFC 8446 section 5.5 sets 2^24.5 full size records;
    /// this stays below with 2^24. ChaCha20-Poly1305 has no limit that a
    /// 64-bit sequence number could reach first, so only the sequence
    /// number itself bounds it.
    pub fn record_limit(self) -> u64 {
        match self {
            AeadAlg::Aes128Gcm | AeadAlg::Aes256Gcm => 1 << 24,
            AeadAlg::ChaCha20Poly1305 => u64::MAX - 1,
        }
    }
}

/// A TLS 1.3 cipher suite.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Suite {
    pub id: u16,
    pub hash: HashAlg,
    pub aead: AeadAlg,
}

pub const TLS_AES_128_GCM_SHA256: Suite = Suite {
    id: 0x1301,
    hash: HashAlg::Sha256,
    aead: AeadAlg::Aes128Gcm,
};
pub const TLS_AES_256_GCM_SHA384: Suite = Suite {
    id: 0x1302,
    hash: HashAlg::Sha384,
    aead: AeadAlg::Aes256Gcm,
};
pub const TLS_CHACHA20_POLY1305_SHA256: Suite = Suite {
    id: 0x1303,
    hash: HashAlg::Sha256,
    aead: AeadAlg::ChaCha20Poly1305,
};

pub const ALL_TLS13: [Suite; 3] = [
    TLS_AES_128_GCM_SHA256,
    TLS_AES_256_GCM_SHA384,
    TLS_CHACHA20_POLY1305_SHA256,
];

pub fn tls13_suite(id: u16) -> Option<Suite> {
    ALL_TLS13.into_iter().find(|s| s.id == id)
}

#[derive(Clone)]
pub(crate) enum RecordCipher {
    Gcm(AesGcm),
    ChaCha(ChaCha20Poly1305),
}

impl RecordCipher {
    pub(crate) fn seal(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], buf: &mut Vec<u8>) {
        match self {
            RecordCipher::Gcm(c) => c.seal(nonce, aad, buf),
            RecordCipher::ChaCha(c) => c.seal(nonce, aad, buf),
        }
    }

    pub(crate) fn open(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buf: &mut Vec<u8>,
    ) -> Result<(), AeadError> {
        match self {
            RecordCipher::Gcm(c) => c.open(nonce, aad, buf),
            RecordCipher::ChaCha(c) => c.open(nonce, aad, buf),
        }
    }
}
