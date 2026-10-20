//! The AEAD interface TLS uses: 12-byte nonces and 16-byte tags.

pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

/// Deliberately carries no detail: telling a peer which check failed is
/// how padding oracles start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AeadError;

impl std::fmt::Display for AeadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("authentication failed")
    }
}

impl std::error::Error for AeadError {}

pub trait Aead: Sized {
    const KEY_LEN: usize;

    /// Panics unless `key` is `KEY_LEN` bytes.
    fn new(key: &[u8]) -> Self;

    /// Encrypts `buf` in place and appends the tag.
    fn seal(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], buf: &mut Vec<u8>);

    /// Checks the tag at the end of `buf`, then decrypts in place and
    /// removes the tag. The tag is checked before any plaintext exists, so
    /// on failure `buf` still holds exactly the ciphertext it was given.
    fn open(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], buf: &mut Vec<u8>)
        -> Result<(), AeadError>;
}
