//! X.509 certificates: parsing, path validation, name matching, private
//! keys, and issuing certificates.

pub mod build;
pub mod cert;
pub mod der;
pub mod keys;
pub mod name;
pub mod path;
pub mod pem;
mod tests;

pub use cert::Certificate;
pub use keys::PrivateKey;
pub use name::ServerName;
pub use path::{verify_chain, CertError, RootStore, Usage};

use super::auth::{scheme, PeerVerifier, PublicKey};
use super::error::Error;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// The signature schemes accepted in CertificateVerify, best first.
pub(crate) fn supported_schemes() -> Vec<u16> {
    vec![scheme::ED25519]
}

/// Path validation against a root store, as the handshake uses it.
pub(crate) struct Verifier {
    pub roots: Arc<RootStore>,
    pub usage: Usage,
}

impl PeerVerifier for Verifier {
    fn verify(&self, chain: &[Vec<u8>], name: Option<&str>) -> Result<PublicKey, Error> {
        let name = match name {
            Some(n) => Some(ServerName::parse(n).ok_or(Error::new(
                super::error::alert::BAD_CERTIFICATE,
                "server name is not a valid DNS name or address",
            ))?),
            None => None,
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        verify_chain(&self.roots, chain, name.as_ref(), self.usage, now)
            .map_err(|e| Error::new(e.alert(), e.reason()))
    }

    fn schemes(&self) -> Vec<u16> {
        supported_schemes()
    }
}

impl CertError {
    pub(crate) fn reason(&self) -> &'static str {
        match self {
            CertError::Malformed(r) => r,
            CertError::Expired => "certificate expired",
            CertError::NotYetValid => "certificate not yet valid",
            CertError::UnknownIssuer => "no path to a trusted root",
            CertError::BadSignature => "certificate signature does not verify",
            CertError::UnsupportedAlgorithm => "certificate uses an unsupported algorithm",
            CertError::NotCa => "issuer is not a CA",
            CertError::CaAsEndEntity => "CA certificate used as end entity",
            CertError::PathLength => "path length constraint exceeded",
            CertError::KeyUsage => "key usage does not allow this",
            CertError::ExtendedKeyUsage => "extended key usage does not allow this",
            CertError::NameMismatch => "certificate is not valid for this name",
            CertError::NameConstraint(r) => r,
            CertError::TooComplex => "certificate path too long or too complex",
        }
    }
}
