//! Key exchange groups for the handshake.

use super::crypto::ct::Secret;
use super::crypto::ec::{self, Curve};
use super::crypto::mlkem;
use super::crypto::x25519;
use super::error::Error;
use super::msgs::group;

/// The groups this crate can use, in its default order of preference.
/// The hybrid comes first, so that a connection recorded today cannot be
/// decrypted by a quantum computer later (ADR-029).
pub const SUPPORTED_GROUPS: &[u16] = &[
    group::X25519MLKEM768,
    group::X25519,
    group::SECP256R1,
    group::SECP384R1,
];

/// True for the groups TLS 1.2 can use: elliptic curve Diffie-Hellman.
/// The hybrid is a TLS 1.3 key exchange only.
pub(crate) fn is_ecdhe(g: u16) -> bool {
    matches!(g, group::X25519 | group::SECP256R1 | group::SECP384R1)
}

const X25519_LEN: usize = 32;

/// The private half of a key share this side sent.
pub(crate) enum KxSecret {
    X25519(x25519::PrivateKey),
    Ec(ec::SecretKey),
    /// ML-KEM-768 and X25519 together; the ML-KEM part comes first on the
    /// wire and in the shared secret (draft-ietf-tls-ecdhe-mlkem).
    Hybrid(Box<mlkem::DecapsulationKey>, x25519::PrivateKey),
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
            group::X25519MLKEM768 => {
                let k = mlkem::DecapsulationKey::generate()
                    .map_err(|_| Error::internal("no randomness"))?;
                let x =
                    x25519::PrivateKey::generate().map_err(|_| Error::internal("no randomness"))?;
                Ok(KxSecret::Hybrid(Box::new(k), x))
            }
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
            KxSecret::Hybrid(..) => group::X25519MLKEM768,
        }
    }

    pub(crate) fn public(&self) -> Vec<u8> {
        match self {
            KxSecret::X25519(k) => k.public_key().to_vec(),
            KxSecret::Ec(k) => k.public_key(),
            KxSecret::Hybrid(k, x) => {
                let mut v = k.encapsulation_key().to_vec();
                v.extend_from_slice(&x.public_key());
                v
            }
        }
    }

    /// The shared secret with the peer's share. A malformed share is an
    /// illegal_parameter (RFC 8446 4.2.8), and so is one that gives the
    /// all-zero X25519 output (7.4.2).
    pub(crate) fn agree(&self, peer: &[u8]) -> Result<Secret, Error> {
        match self {
            KxSecret::X25519(k) => x25519_agree(k, peer),
            // Only uncompressed points on the curve (RFC 8446 4.2.8.2).
            KxSecret::Ec(k) => k
                .diffie_hellman(peer)
                .ok_or(Error::illegal("EC share is not a point on the curve")),
            KxSecret::Hybrid(k, x) => {
                if peer.len() != mlkem::CIPHERTEXT_LEN + X25519_LEN {
                    return Err(Error::illegal("hybrid share length"));
                }
                let (ct, xp) = peer.split_at(mlkem::CIPHERTEXT_LEN);
                let ss = k
                    .decapsulate(ct)
                    .ok_or(Error::illegal("ML-KEM ciphertext"))?;
                let xs = x25519_agree(x, xp)?;
                Ok(concat(&ss, &xs))
            }
        }
    }
}

fn x25519_agree(k: &x25519::PrivateKey, peer: &[u8]) -> Result<Secret, Error> {
    let p: [u8; 32] = peer
        .try_into()
        .map_err(|_| Error::illegal("X25519 share is not 32 bytes"))?;
    k.diffie_hellman(&p)
        .ok_or(Error::illegal("X25519 share of small order"))
}

fn concat(a: &Secret, b: &Secret) -> Secret {
    let mut v = a.expose().to_vec();
    v.extend_from_slice(b.expose());
    Secret::new(v)
}

/// The server's side of the exchange: its key share in answer to the
/// client's `share`, and the shared secret. For Diffie-Hellman that is a
/// fresh key pair; for the hybrid it is an ML-KEM encapsulation to the
/// client's key, which a key pair cannot express.
pub(crate) fn respond(g: u16, share: &[u8]) -> Result<(Vec<u8>, Secret), Error> {
    if g != group::X25519MLKEM768 {
        let kx = KxSecret::generate(g)?;
        let shared = kx.agree(share)?;
        return Ok((kx.public(), shared));
    }
    if share.len() != mlkem::ENCAPSULATION_KEY_LEN + X25519_LEN {
        return Err(Error::illegal("hybrid share length"));
    }
    let (ek, xp) = share.split_at(mlkem::ENCAPSULATION_KEY_LEN);
    let (ct, ss) = mlkem::encapsulate(ek)
        .map_err(|_| Error::internal("no randomness"))?
        .ok_or(Error::illegal("ML-KEM encapsulation key"))?;
    let x = KxSecret::generate(group::X25519)?;
    let xs = x.agree(xp)?;
    let mut out = ct;
    out.extend_from_slice(&x.public());
    Ok((out, concat(&ss, &xs)))
}

impl std::fmt::Debug for KxSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "KxSecret({:#06x})", self.group())
    }
}
