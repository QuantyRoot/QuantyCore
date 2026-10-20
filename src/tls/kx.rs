//! Key exchange groups for the handshake.

use super::crypto::ct::Secret;
use super::crypto::ec::{self, Curve};
use super::crypto::x25519;
use super::error::Error;
use super::msgs::group;

/// The groups this crate can use, in its default order of preference.
pub const SUPPORTED_GROUPS: &[u16] = &[group::X25519, group::SECP256R1, group::SECP384R1];

/// The private half of a key share this side sent.
pub(crate) enum KxSecret {
    X25519(x25519::PrivateKey),
    Ec(ec::SecretKey),
}

impl KxSecret {
    pub(crate) fn generate(g: u16) -> Result<KxSecret, Error> {
        match g {
            group::X25519 => x25519::PrivateKey::generate()
                .map(KxSecret::X25519)
                .map_err(|_| Error::internal("no randomness")),
            group::SECP256R1 => ec::SecretKey::generate(Curve::P256)
                .map(KxSecret::Ec)
                .map_err(|_| Error::internal("no randomness")),
            group::SECP384R1 => ec::SecretKey::generate(Curve::P384)
                .map(KxSecret::Ec)
                .map_err(|_| Error::internal("no randomness")),
            _ => Err(Error::internal("unsupported group")),
        }
    }

    pub(crate) fn group(&self) -> u16 {
        match self {
            KxSecret::X25519(_) => group::X25519,
            KxSecret::Ec(k) => match k.curve() {
                Curve::P256 => group::SECP256R1,
                Curve::P384 => group::SECP384R1,
            },
        }
    }

    pub(crate) fn public(&self) -> Vec<u8> {
        match self {
            KxSecret::X25519(k) => k.public_key().to_vec(),
            KxSecret::Ec(k) => k.public_key(),
        }
    }

    /// The shared secret with the peer's share. A malformed share is an
    /// illegal_parameter (RFC 8446 4.2.8), and so is one that gives the
    /// all-zero X25519 output (7.4.2).
    pub(crate) fn agree(&self, peer: &[u8]) -> Result<Secret, Error> {
        match self {
            KxSecret::X25519(k) => {
                let p: [u8; 32] = peer
                    .try_into()
                    .map_err(|_| Error::illegal("X25519 share is not 32 bytes"))?;
                k.diffie_hellman(&p)
                    .ok_or(Error::illegal("X25519 share of small order"))
            }
            // Only uncompressed points on the curve (RFC 8446 4.2.8.2).
            KxSecret::Ec(k) => k
                .diffie_hellman(peer)
                .ok_or(Error::illegal("EC share is not a point on the curve")),
        }
    }
}

impl std::fmt::Debug for KxSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KxSecret({:#06x})", self.group())
    }
}
