//! Signing and verifying the handshake, and the boundary to certificate
//! validation.

use super::crypto::ec::{self, Curve};
use super::crypto::ed25519;
use super::crypto::sha2::HashAlg;
use super::error::{alert, Error};
use super::x509::cert::{oid, Spki};
use super::x509::der::{ecdsa_signature, Der};
use super::x509::CertError;

pub mod scheme {
    pub const RSA_PKCS1_SHA256: u16 = 0x0401;
    pub const RSA_PKCS1_SHA384: u16 = 0x0501;
    pub const RSA_PKCS1_SHA512: u16 = 0x0601;
    pub const ECDSA_SECP256R1_SHA256: u16 = 0x0403;
    pub const ECDSA_SECP384R1_SHA384: u16 = 0x0503;
    pub const RSA_PSS_RSAE_SHA256: u16 = 0x0804;
    pub const RSA_PSS_RSAE_SHA384: u16 = 0x0805;
    pub const RSA_PSS_RSAE_SHA512: u16 = 0x0806;
    pub const ED25519: u16 = 0x0807;
}

/// A public key taken from a validated certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublicKey {
    Ed25519([u8; 32]),
    /// An uncompressed point, checked to be on the curve.
    Ec(Curve, Vec<u8>),
    /// Accepts every signature. Exists only in this crate's tests, for
    /// the RFC 8448 traces, whose RSA signatures come before RSA does.
    #[cfg(test)]
    AcceptAny,
}

impl PublicKey {
    /// The key in a certificate. Algorithms this crate cannot verify yet
    /// are refused here, so a chain that needs one fails as unsupported
    /// instead of later as a bad signature.
    pub fn from_spki(spki: &Spki) -> Result<PublicKey, CertError> {
        match spki.algorithm.as_slice() {
            oid::ED25519 => {
                if spki.curve.is_some() {
                    return Err(CertError::Malformed("Ed25519 key with parameters"));
                }
                let k: [u8; 32] = spki
                    .key
                    .as_slice()
                    .try_into()
                    .map_err(|_| CertError::Malformed("Ed25519 key length"))?;
                Ok(PublicKey::Ed25519(k))
            }
            oid::EC_PUBLIC_KEY => {
                let curve = match spki.curve.as_deref() {
                    Some(oid::P256) => Curve::P256,
                    Some(oid::P384) => Curve::P384,
                    _ => return Err(CertError::UnsupportedAlgorithm),
                };
                if !ec::is_valid_point(curve, &spki.key) {
                    return Err(CertError::Malformed("EC public key not on the curve"));
                }
                Ok(PublicKey::Ec(curve, spki.key.clone()))
            }
            _ => Err(CertError::UnsupportedAlgorithm),
        }
    }

    /// Checks a certificate's signature made with this key.
    /// `algorithm` is the certificate's AlgorithmIdentifier as DER.
    pub fn verify_x509(&self, algorithm: &[u8], tbs: &[u8], sig: &[u8]) -> Result<(), CertError> {
        let mut outer = Der::new(algorithm);
        let mut alg = outer.sequence().map_err(|e| CertError::Malformed(e.0))?;
        let id = alg.oid().map_err(|e| CertError::Malformed(e.0))?;
        let has_params = !alg.is_empty();
        let ok = match (self, id) {
            (PublicKey::Ed25519(k), oid::ED25519) if !has_params => ed25519::verify(k, tbs, sig),
            (_, oid::ED25519) => return Err(CertError::BadSignature),
            (PublicKey::Ec(curve, q), id) if !has_params => {
                let hash = match id {
                    oid::ECDSA_SHA256 => HashAlg::Sha256,
                    oid::ECDSA_SHA384 => HashAlg::Sha384,
                    oid::ECDSA_SHA512 => HashAlg::Sha512,
                    _ => return Err(CertError::UnsupportedAlgorithm),
                };
                ecdsa_verify(*curve, q, hash, tbs, sig)
            }
            _ => return Err(CertError::UnsupportedAlgorithm),
        };
        if ok {
            Ok(())
        } else {
            Err(CertError::BadSignature)
        }
    }

    /// The schemes this key can verify in TLS 1.3. RSA PKCS#1 v1.5 is not
    /// among them for handshake signatures (RFC 8446 4.2.3).
    pub fn tls13_schemes(&self) -> &'static [u16] {
        match self {
            PublicKey::Ed25519(_) => &[scheme::ED25519],
            PublicKey::Ec(Curve::P256, _) => &[scheme::ECDSA_SECP256R1_SHA256],
            PublicKey::Ec(Curve::P384, _) => &[scheme::ECDSA_SECP384R1_SHA384],
            #[cfg(test)]
            PublicKey::AcceptAny => &[],
        }
    }

    pub fn verify(&self, sig_scheme: u16, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
        let ok = match (self, sig_scheme) {
            (PublicKey::Ed25519(pk), scheme::ED25519) => ed25519::verify(pk, msg, sig),
            // In TLS 1.3 the scheme fixes both curve and hash (RFC 8446
            // 4.2.3).
            (PublicKey::Ec(Curve::P256, q), scheme::ECDSA_SECP256R1_SHA256) => {
                ecdsa_verify(Curve::P256, q, HashAlg::Sha256, msg, sig)
            }
            (PublicKey::Ec(Curve::P384, q), scheme::ECDSA_SECP384R1_SHA384) => {
                ecdsa_verify(Curve::P384, q, HashAlg::Sha384, msg, sig)
            }
            #[cfg(test)]
            (PublicKey::AcceptAny, _) => true,
            _ => return Err(Error::illegal("signature scheme does not fit the key")),
        };
        if ok {
            Ok(())
        } else {
            Err(Error::new(
                alert::DECRYPT_ERROR,
                "signature does not verify",
            ))
        }
    }
}

fn ecdsa_verify(curve: Curve, q: &[u8], hash: HashAlg, msg: &[u8], sig: &[u8]) -> bool {
    match ecdsa_signature(sig) {
        Some((r, s)) => ec::verify_prehashed(curve, q, &hash.digest(msg), r, s),
        None => false,
    }
}

/// The private key behind a certificate.
pub trait Signer: Send + Sync {
    /// The first of `offered` this key can produce, in the peer's order.
    fn choose_scheme(&self, offered: &[u16]) -> Option<u16>;
    fn sign(&self, scheme: u16, msg: &[u8]) -> Result<Vec<u8>, Error>;
}

impl Signer for ed25519::SigningKey {
    fn choose_scheme(&self, offered: &[u16]) -> Option<u16> {
        offered.iter().copied().find(|&s| s == scheme::ED25519)
    }
    fn sign(&self, s: u16, msg: &[u8]) -> Result<Vec<u8>, Error> {
        if s != scheme::ED25519 {
            return Err(Error::internal("scheme not offered by this key"));
        }
        Ok(ed25519::SigningKey::sign(self, msg).to_vec())
    }
}

/// Checks a peer's certificate chain. The chain is leaf first, as sent.
/// For a server, `name` is the name the client asked for; a client
/// certificate is checked without one.
pub(crate) trait PeerVerifier: Send + Sync {
    fn verify(&self, chain: &[Vec<u8>], name: Option<&str>) -> Result<PublicKey, Error>;
    /// The signature schemes accepted in CertificateVerify, in order of
    /// preference, for the signature_algorithms extension.
    fn schemes(&self) -> Vec<u16>;
}

/// The content a CertificateVerify signs (RFC 8446 4.4.3): 64 spaces, a
/// context string, a zero byte and the transcript hash.
pub(crate) fn signed_content(server: bool, transcript_hash: &[u8]) -> Vec<u8> {
    let mut m = vec![0x20u8; 64];
    m.extend_from_slice(if server {
        b"TLS 1.3, server CertificateVerify"
    } else {
        b"TLS 1.3, client CertificateVerify"
    });
    m.push(0);
    m.extend_from_slice(transcript_hash);
    m
}
