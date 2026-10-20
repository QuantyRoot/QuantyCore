//! Private keys: loading from PKCS#8 (and, as algorithms arrive, SEC1 and
//! PKCS#1), generating, and signing with them.

use super::cert::oid;
use super::der::{self, tag, Der};
use super::pem;
use crate::tls::auth::{scheme, Signer};
use crate::tls::crypto::ct;
use crate::tls::crypto::ed25519::SigningKey;
use crate::tls::error::Error;

pub enum PrivateKey {
    Ed25519(SigningKey),
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PrivateKey::Ed25519(_) => f.write_str("PrivateKey(Ed25519)"),
        }
    }
}

impl PrivateKey {
    pub fn generate_ed25519() -> std::io::Result<PrivateKey> {
        SigningKey::generate().map(PrivateKey::Ed25519)
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
            _ => Err("unsupported private key algorithm"),
        }
    }

    /// The first private key in a PEM text.
    pub fn from_pem(text: &str) -> Result<PrivateKey, &'static str> {
        match pem::decode_first(text, &["PRIVATE KEY"])? {
            Some(("PRIVATE KEY", der)) => {
                let der = crate::tls::crypto::ct::Secret::new(der);
                PrivateKey::from_pkcs8(der.expose())
            }
            _ => Err("no private key in PEM text"),
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
        }
    }
}

impl Signer for PrivateKey {
    fn choose_scheme(&self, offered: &[u16]) -> Option<u16> {
        match self {
            PrivateKey::Ed25519(_) => offered.iter().copied().find(|&s| s == scheme::ED25519),
        }
    }

    fn sign(&self, s: u16, msg: &[u8]) -> Result<Vec<u8>, Error> {
        match (self, s) {
            (PrivateKey::Ed25519(k), scheme::ED25519) => Ok(k.sign(msg).to_vec()),
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
        let PrivateKey::Ed25519(s) = &k;
        assert_eq!(
            s.public_key()[..4],
            [0x19, 0xbf, 0x44, 0x09],
            "public key of RFC 8410 10.1"
        );
    }
}
