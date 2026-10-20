//! Private keys: loading from PKCS#8 (and, as algorithms arrive, SEC1 and
//! PKCS#1), generating, and signing with them.

use super::cert::oid;
use super::der::{self, tag, Der};
use super::pem;
use crate::tls::auth::{scheme, Signer};
use crate::tls::crypto::ct;
use crate::tls::crypto::ec::{self, Curve};
use crate::tls::crypto::ed25519::SigningKey;
use crate::tls::crypto::rsa;
use crate::tls::crypto::sha2::HashAlg;
use crate::tls::error::Error;

pub enum PrivateKey {
    Ed25519(SigningKey),
    Ec(ec::SecretKey),
    /// The key, and its PKCS#1 encoding to write it back out.
    Rsa(rsa::PrivateKey, ct::Secret),
}

/// PKCS#1 RSAPrivateKey (RFC 8017 A.1.2), two primes only.
pub fn rsa_from_pkcs1(der: &[u8]) -> Result<rsa::PrivateKey, &'static str> {
    let e = |_| "malformed RSA private key";
    let mut outer = Der::new(der);
    let mut s = outer.sequence().map_err(e)?;
    if s.small_unsigned().map_err(e)? != 0 {
        return Err("RSA keys with more than two primes are not supported");
    }
    let n = s.unsigned().map_err(e)?;
    let pe = s.unsigned().map_err(e)?;
    let d = s.unsigned().map_err(e)?;
    let p = s.unsigned().map_err(e)?;
    let q = s.unsigned().map_err(e)?;
    rsa::PrivateKey::new(n, pe, d, p, q).ok_or("RSA key is inconsistent or of an unsupported size")
}

fn curve_oid(c: Curve) -> &'static [u8] {
    match c {
        Curve::P256 => oid::P256,
        Curve::P384 => oid::P384,
    }
}

fn curve_from_oid(o: &[u8]) -> Option<Curve> {
    match o {
        oid::P256 => Some(Curve::P256),
        oid::P384 => Some(Curve::P384),
        _ => None,
    }
}

/// SEC1 ECPrivateKey (RFC 5915). `curve` comes from the PKCS#8 wrapper
/// when there is one; otherwise the structure must name it.
fn sec1(der: &[u8], curve: Option<Curve>) -> Result<PrivateKey, &'static str> {
    let e = |_| "malformed EC private key";
    let mut outer = Der::new(der);
    let mut s = outer.sequence().map_err(e)?;
    if s.small_unsigned().map_err(e)? != 1 {
        return Err("EC private key version");
    }
    let d = s.expect(tag::OCTET_STRING).map_err(e)?;
    let named = match s.optional(tag::context_constructed(0)).map_err(e)? {
        Some(p) => Some(curve_from_oid(Der::new(p).oid().map_err(e)?).ok_or("unsupported curve")?),
        None => None,
    };
    let curve = match (curve, named) {
        (Some(a), Some(b)) if a != b => return Err("curves disagree"),
        (Some(c), _) | (None, Some(c)) => c,
        (None, None) => return Err("EC private key without a curve"),
    };
    ec::SecretKey::from_bytes(curve, d)
        .map(PrivateKey::Ec)
        .ok_or("EC private key out of range")
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrivateKey::Ed25519(_) => f.write_str("PrivateKey(Ed25519)"),
            PrivateKey::Ec(k) => write!(f, "PrivateKey({:?})", k.curve()),
            PrivateKey::Rsa(k, _) => write!(f, "PrivateKey(RSA {})", k.public().bits()),
        }
    }
}

impl PrivateKey {
    pub fn generate_ed25519() -> std::io::Result<PrivateKey> {
        SigningKey::generate().map(PrivateKey::Ed25519)
    }

    pub fn generate_ec(curve: Curve) -> std::io::Result<PrivateKey> {
        ec::SecretKey::generate(curve).map(PrivateKey::Ec)
    }

    /// PKCS#8 (RFC 5208, RFC 8410 for Ed25519).
    pub fn from_pkcs8(der: &[u8]) -> Result<PrivateKey, &'static str> {
        let e = |_| "malformed PKCS#8";
        let mut outer = Der::new(der);
        let mut s = outer.sequence().map_err(e)?;
        outer.end().map_err(e)?;
        let version = s.small_unsigned().map_err(e)?;
        if version > 1 {
            return Err("PKCS#8 version");
        }
        let mut alg = s.sequence().map_err(e)?;
        let id = alg.oid().map_err(e)?;
        let key = s.expect(tag::OCTET_STRING).map_err(e)?;
        match id {
            oid::ED25519 => {
                if !alg.is_empty() {
                    return Err("Ed25519 with parameters");
                }
                let seed = Der::new(key).expect(tag::OCTET_STRING).map_err(e)?;
                let mut seed: [u8; 32] = seed.try_into().map_err(|_| "Ed25519 key length")?;
                let k = SigningKey::from_seed(&seed);
                ct::wipe(&mut seed);
                Ok(PrivateKey::Ed25519(k))
            }
            oid::EC_PUBLIC_KEY => {
                let curve = curve_from_oid(alg.oid().map_err(e)?).ok_or("unsupported curve")?;
                sec1(key, Some(curve))
            }
            oid::RSA_ENCRYPTION => {
                rsa_from_pkcs1(key).map(|k| PrivateKey::Rsa(k, ct::Secret::from(key)))
            }
            _ => Err("unsupported private key algorithm"),
        }
    }

    /// The first private key in a PEM text.
    pub fn from_pem(text: &str) -> Result<PrivateKey, &'static str> {
        match pem::decode_first(text, &["PRIVATE KEY", "EC PRIVATE KEY", "RSA PRIVATE KEY"])? {
            Some((label, der)) => {
                let der = crate::tls::crypto::ct::Secret::new(der);
                match label {
                    "EC PRIVATE KEY" => sec1(der.expose(), None),
                    "RSA PRIVATE KEY" => rsa_from_pkcs1(der.expose())
                        .map(|k| PrivateKey::Rsa(k, ct::Secret::from(der.expose()))),
                    _ => PrivateKey::from_pkcs8(der.expose()),
                }
            }
            None => Err("no private key in PEM text"),
        }
    }

    pub fn to_pkcs8(&self) -> Vec<u8> {
        match self {
            PrivateKey::Ed25519(k) => {
                let mut body = Vec::new();
                der::write(&mut body, tag::INTEGER, &[0]);
                der::write(&mut body, tag::SEQUENCE, &der::wrap(tag::OID, oid::ED25519));
                der::write(
                    &mut body,
                    tag::OCTET_STRING,
                    &der::wrap(tag::OCTET_STRING, k.seed()),
                );
                der::wrap(tag::SEQUENCE, &body)
            }
            PrivateKey::Ec(k) => {
                let mut alg = der::wrap(tag::OID, oid::EC_PUBLIC_KEY);
                der::write(&mut alg, tag::OID, curve_oid(k.curve()));
                let mut inner = Vec::new();
                der::write(&mut inner, tag::INTEGER, &[1]);
                der::write(&mut inner, tag::OCTET_STRING, k.to_bytes());
                let mut body = Vec::new();
                der::write(&mut body, tag::INTEGER, &[0]);
                der::write(&mut body, tag::SEQUENCE, &alg);
                der::write(
                    &mut body,
                    tag::OCTET_STRING,
                    &der::wrap(tag::SEQUENCE, &inner),
                );
                der::wrap(tag::SEQUENCE, &body)
            }
            PrivateKey::Rsa(_, pkcs1) => {
                let mut body = Vec::new();
                der::write(&mut body, tag::INTEGER, &[0]);
                der::write(&mut body, tag::SEQUENCE, &rsa_alg_id());
                der::write(&mut body, tag::OCTET_STRING, pkcs1.expose());
                der::wrap(tag::SEQUENCE, &body)
            }
        }
    }

    pub fn to_pem(&self) -> String {
        pem::encode("PRIVATE KEY", &self.to_pkcs8())
    }

    /// The SubjectPublicKeyInfo of the public half, as DER.
    pub fn public_spki(&self) -> Vec<u8> {
        match self {
            PrivateKey::Ed25519(k) => {
                let mut body = der::wrap(tag::SEQUENCE, &der::wrap(tag::OID, oid::ED25519));
                let mut bits = vec![0];
                bits.extend_from_slice(&k.public_key());
                der::write(&mut body, tag::BIT_STRING, &bits);
                der::wrap(tag::SEQUENCE, &body)
            }
            PrivateKey::Ec(k) => {
                let mut alg = der::wrap(tag::OID, oid::EC_PUBLIC_KEY);
                der::write(&mut alg, tag::OID, curve_oid(k.curve()));
                let mut body = der::wrap(tag::SEQUENCE, &alg);
                let mut bits = vec![0];
                bits.extend_from_slice(&k.public_key());
                der::write(&mut body, tag::BIT_STRING, &bits);
                der::wrap(tag::SEQUENCE, &body)
            }
            PrivateKey::Rsa(k, _) => {
                let mut key = Vec::new();
                der::write_unsigned(&mut key, &k.public().modulus());
                der::write_unsigned(&mut key, &k.public().exponent());
                let mut body = der::wrap(tag::SEQUENCE, &rsa_alg_id());
                let mut bits = vec![0];
                bits.extend_from_slice(&der::wrap(tag::SEQUENCE, &key));
                der::write(&mut body, tag::BIT_STRING, &bits);
                der::wrap(tag::SEQUENCE, &body)
            }
        }
    }

    /// The AlgorithmIdentifier this key signs certificates with, and the
    /// signature over `tbs`.
    pub(crate) fn sign_x509(&self, tbs: &[u8]) -> (Vec<u8>, Vec<u8>) {
        match self {
            PrivateKey::Ed25519(k) => (
                der::wrap(tag::SEQUENCE, &der::wrap(tag::OID, oid::ED25519)),
                k.sign(tbs).to_vec(),
            ),
            PrivateKey::Ec(k) => {
                let (id, hash) = match k.curve() {
                    Curve::P256 => (oid::ECDSA_SHA256, crate::tls::crypto::sha2::HashAlg::Sha256),
                    Curve::P384 => (oid::ECDSA_SHA384, crate::tls::crypto::sha2::HashAlg::Sha384),
                };
                (
                    der::wrap(tag::SEQUENCE, &der::wrap(tag::OID, id)),
                    ecdsa_der(k, hash, tbs),
                )
            }
            // PKCS#1 v1.5 with SHA-256: what every verifier accepts in a
            // certificate.
            PrivateKey::Rsa(k, _) => {
                let mut alg = der::wrap(tag::OID, oid::SHA256_WITH_RSA);
                der::write(&mut alg, tag::NULL, &[]);
                let sig = k
                    .sign_pkcs1(HashAlg::Sha256, tbs)
                    .expect("randomness for RSA blinding");
                (der::wrap(tag::SEQUENCE, &alg), sig)
            }
        }
    }
}

/// rsaEncryption with its NULL parameter.
fn rsa_alg_id() -> Vec<u8> {
    let mut alg = der::wrap(tag::OID, oid::RSA_ENCRYPTION);
    der::write(&mut alg, tag::NULL, &[]);
    alg
}

/// An ECDSA signature over `msg`, as the DER SEQUENCE of r and s. The
/// signature is checked against the public key before it leaves, so a
/// fault during signing cannot hand out a value that leaks the key.
fn ecdsa_der(k: &ec::SecretKey, hash: crate::tls::crypto::sha2::HashAlg, msg: &[u8]) -> Vec<u8> {
    let h = hash.digest(msg);
    let (r, s) = k.sign_prehashed(&h, hash);
    assert!(
        ec::verify_prehashed(k.curve(), &k.public_key(), &h, &r, &s),
        "ECDSA signature failed its own check"
    );
    let mut body = Vec::new();
    der::write_unsigned(&mut body, &r);
    der::write_unsigned(&mut body, &s);
    der::wrap(tag::SEQUENCE, &body)
}

fn pss(k: &rsa::PrivateKey, hash: HashAlg, msg: &[u8]) -> Result<Vec<u8>, Error> {
    k.sign_pss(hash, msg)
        .map_err(|_| Error::internal("RSA signing failed"))
}

impl Signer for PrivateKey {
    fn choose_scheme(&self, offered: &[u16]) -> Option<u16> {
        match self {
            PrivateKey::Ed25519(_) => offered.iter().copied().find(|&s| s == scheme::ED25519),
            PrivateKey::Ec(k) => {
                let mine = match k.curve() {
                    Curve::P256 => scheme::ECDSA_SECP256R1_SHA256,
                    Curve::P384 => scheme::ECDSA_SECP384R1_SHA384,
                };
                offered.iter().copied().find(|&s| s == mine)
            }
            PrivateKey::Rsa(..) => offered.iter().copied().find(|&s| {
                matches!(
                    s,
                    scheme::RSA_PSS_RSAE_SHA256
                        | scheme::RSA_PSS_RSAE_SHA384
                        | scheme::RSA_PSS_RSAE_SHA512
                )
            }),
        }
    }

    fn sign(&self, s: u16, msg: &[u8]) -> Result<Vec<u8>, Error> {
        match (self, s) {
            (PrivateKey::Ed25519(k), scheme::ED25519) => Ok(k.sign(msg).to_vec()),
            (PrivateKey::Ec(k), scheme::ECDSA_SECP256R1_SHA256) if k.curve() == Curve::P256 => {
                Ok(ecdsa_der(k, crate::tls::crypto::sha2::HashAlg::Sha256, msg))
            }
            (PrivateKey::Ec(k), scheme::ECDSA_SECP384R1_SHA384) if k.curve() == Curve::P384 => {
                Ok(ecdsa_der(k, crate::tls::crypto::sha2::HashAlg::Sha384, msg))
            }
            (PrivateKey::Rsa(k, _), scheme::RSA_PSS_RSAE_SHA256) => pss(k, HashAlg::Sha256, msg),
            (PrivateKey::Rsa(k, _), scheme::RSA_PSS_RSAE_SHA384) => pss(k, HashAlg::Sha384, msg),
            (PrivateKey::Rsa(k, _), scheme::RSA_PSS_RSAE_SHA512) => pss(k, HashAlg::Sha512, msg),
            _ => Err(Error::internal("scheme does not fit the key")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8410 10.3: an Ed25519 private key in PKCS#8.
    #[test]
    fn rfc_8410_private_key() {
        let pem = "-----BEGIN PRIVATE KEY-----\n\
                   MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC\n\
                   -----END PRIVATE KEY-----\n";
        let k = PrivateKey::from_pem(pem).unwrap();
        assert_eq!(k.to_pem(), pem.replace("                   ", ""));
        let PrivateKey::Ed25519(s) = &k else {
            panic!("not Ed25519");
        };
        assert_eq!(
            s.public_key()[..4],
            [0x19, 0xbf, 0x44, 0x09],
            "public key of RFC 8410 10.1"
        );
    }
}
