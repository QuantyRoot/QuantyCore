//! Certificate path validation (RFC 5280 section 6, in the subset a TLS
//! client or server needs): from the peer's leaf through the
//! intermediates it sent to a configured trust anchor.
//!
//! Not evaluated: certificate policies, CRLs and OCSP. A critical policy
//! extension is refused at parsing instead of being ignored here.

use super::cert::{key_usage, oid, Certificate, GeneralName, NameConstraints, Spki};
use super::name::{check_constraints, name_matches, ServerName};
use super::pem;
use crate::tls::auth::PublicKey;
use crate::tls::error::alert;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CertError {
    Malformed(&'static str),
    Expired,
    NotYetValid,
    UnknownIssuer,
    BadSignature,
    UnsupportedAlgorithm,
    NotCa,
    CaAsEndEntity,
    PathLength,
    KeyUsage,
    ExtendedKeyUsage,
    NameMismatch,
    NameConstraint(&'static str),
    TooComplex,
}

impl CertError {
    /// The TLS alert for this failure (RFC 8446 6.2).
    pub fn alert(&self) -> u8 {
        match self {
            CertError::Expired | CertError::NotYetValid => alert::CERTIFICATE_EXPIRED,
            CertError::UnknownIssuer => alert::UNKNOWN_CA,
            CertError::UnsupportedAlgorithm => alert::UNSUPPORTED_CERTIFICATE,
            _ => alert::BAD_CERTIFICATE,
        }
    }
}

impl std::fmt::Display for CertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for CertError {}

/// What the leaf certificate is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Usage {
    Server,
    Client,
}

impl Usage {
    fn eku(self) -> &'static [u8] {
        match self {
            Usage::Server => oid::KP_SERVER_AUTH,
            Usage::Client => oid::KP_CLIENT_AUTH,
        }
    }
}

/// A trusted root: its subject, key and name constraints. A root's own
/// validity period and signature are not checked, as RFC 5280 6.1.1(d)
/// treats a trust anchor as information, not as a certificate.
#[derive(Clone, Debug)]
pub struct TrustAnchor {
    subject: Vec<u8>,
    spki: Spki,
    constraints: Option<NameConstraints>,
}

#[derive(Clone, Debug, Default)]
pub struct RootStore {
    anchors: Vec<TrustAnchor>,
}

/// Where Linux distributions keep their bundled roots.
const SYSTEM_BUNDLES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/ssl/cert.pem",
];

impl RootStore {
    pub fn new() -> RootStore {
        RootStore::default()
    }

    pub fn add_der(&mut self, der: &[u8]) -> Result<(), CertError> {
        let c = Certificate::parse(der).map_err(|e| CertError::Malformed(e.0))?;
        self.anchors.push(TrustAnchor {
            subject: c.subject,
            spki: c.spki,
            constraints: c.name_constraints,
        });
        Ok(())
    }

    /// Adds every certificate in a PEM file's text; returns how many. A
    /// certificate that does not parse is skipped and counted in the
    /// second number, so one odd root does not lose the whole store.
    pub fn add_pem(&mut self, text: &str) -> Result<(usize, usize), CertError> {
        let blocks = pem::decode_all(text, "CERTIFICATE").map_err(CertError::Malformed)?;
        let (mut ok, mut bad) = (0, 0);
        for b in blocks {
            match self.add_der(&b) {
                Ok(()) => ok += 1,
                Err(_) => bad += 1,
            }
        }
        Ok((ok, bad))
    }

    /// The system's roots, from the first bundle file that exists.
    pub fn system() -> std::io::Result<RootStore> {
        for path in SYSTEM_BUNDLES {
            if let Ok(text) = std::fs::read_to_string(path) {
                let mut s = RootStore::new();
                s.add_pem(&text)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                if !s.is_empty() {
                    return Ok(s);
                }
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "no system certificate bundle found",
        ))
    }

    pub fn len(&self) -> usize {
        self.anchors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.anchors.is_empty()
    }
}

/// Paths deeper than this are refused; real ones have one or two
/// intermediates.
const MAX_INTERMEDIATES: usize = 6;
/// Signature checks per validation, against a peer that sends many
/// certificates with the same subject to make path building explode.
const MAX_SIGNATURE_CHECKS: usize = 64;

struct Search<'a> {
    roots: &'a RootStore,
    leaf: &'a Certificate,
    intermediates: Vec<Certificate>,
    usage: Usage,
    now: i64,
    budget: usize,
}

/// Validates `chain` (leaf first, as sent) for `name` at time `now` (Unix
/// seconds) and returns the leaf's public key.
pub fn verify_chain(
    roots: &RootStore,
    chain: &[Vec<u8>],
    name: Option<&ServerName>,
    usage: Usage,
    now: i64,
) -> Result<PublicKey, CertError> {
    let leaf_der = chain.first().ok_or(CertError::Malformed("empty chain"))?;
    let leaf = Certificate::parse(leaf_der).map_err(|e| CertError::Malformed(e.0))?;
    if leaf.version != 3 {
        return Err(CertError::Malformed("end-entity certificate before v3"));
    }
    if leaf.ca.is_some_and(|(ca, _)| ca) {
        return Err(CertError::CaAsEndEntity);
    }
    check_time(&leaf, now)?;
    if leaf
        .key_usage
        .is_some_and(|ku| ku & key_usage::DIGITAL_SIGNATURE == 0)
    {
        return Err(CertError::KeyUsage);
    }
    if let Some(eku) = &leaf.eku {
        if !eku.iter().any(|e| e == usage.eku()) {
            return Err(CertError::ExtendedKeyUsage);
        }
    }
    let key = PublicKey::from_spki(&leaf.spki)?;
    if let Some(name) = name {
        if !leaf
            .san
            .as_deref()
            .is_some_and(|san| name_matches(san, name))
        {
            return Err(CertError::NameMismatch);
        }
    }
    let mut s = Search {
        roots,
        leaf: &leaf,
        // Certificates that do not parse cannot be on any path; they are
        // dropped instead of failing a chain that does not need them.
        intermediates: chain[1..]
            .iter()
            .filter_map(|d| Certificate::parse(d).ok())
            .take(32)
            .collect(),
        usage,
        now,
        budget: MAX_SIGNATURE_CHECKS,
    };
    let mut path = Vec::new();
    s.extend(&leaf, &mut path)?;
    Ok(key)
}

fn check_time(c: &Certificate, now: i64) -> Result<(), CertError> {
    if now < c.not_before {
        return Err(CertError::NotYetValid);
    }
    if now > c.not_after {
        return Err(CertError::Expired);
    }
    Ok(())
}

impl Search<'_> {
    /// Finds an issuer for `cert`, which `path` (intermediates above the
    /// leaf, nearest first) leads to. The error returned is the one from
    /// the most promising branch: an issuer that was found but failed
    /// beats no issuer at all.
    fn extend(&mut self, cert: &Certificate, path: &mut Vec<usize>) -> Result<(), CertError> {
        let mut best = CertError::UnknownIssuer;
        for i in 0..self.roots.anchors.len() {
            let a = &self.roots.anchors[i];
            if a.subject != cert.issuer {
                continue;
            }
            match self.signed_by(cert, &a.spki) {
                Ok(()) => {}
                Err(e) => {
                    best = e;
                    continue;
                }
            }
            match self.check_constraints(path, a.constraints.as_ref()) {
                Ok(()) => return Ok(()),
                Err(e) => best = e,
            }
        }
        if path.len() >= MAX_INTERMEDIATES {
            return Err(if best == CertError::UnknownIssuer {
                CertError::TooComplex
            } else {
                best
            });
        }
        for i in 0..self.intermediates.len() {
            if path.contains(&i) || self.intermediates[i].subject != cert.issuer {
                continue;
            }
            let ca = self.intermediates[i].clone();
            if let Err(e) = self.check_ca(&ca, path) {
                best = e;
                continue;
            }
            if let Err(e) = self.signed_by(cert, &ca.spki) {
                best = e;
                continue;
            }
            path.push(i);
            match self.extend(&ca, path) {
                Ok(()) => return Ok(()),
                Err(CertError::TooComplex) => return Err(CertError::TooComplex),
                Err(e) => best = e,
            }
            path.pop();
        }
        Err(best)
    }

    fn signed_by(&mut self, cert: &Certificate, issuer: &Spki) -> Result<(), CertError> {
        if self.budget == 0 {
            return Err(CertError::TooComplex);
        }
        self.budget -= 1;
        PublicKey::from_spki(issuer)?.verify_x509(&cert.sig_alg, &cert.tbs, &cert.signature)
    }

    /// An intermediate is acceptable as an issuer at this point of the
    /// path: a v3 CA, in time, allowed to sign certificates, for this
    /// purpose, and with path length to spare for the CAs below it.
    fn check_ca(&self, ca: &Certificate, path: &[usize]) -> Result<(), CertError> {
        if ca.version != 3 {
            return Err(CertError::NotCa);
        }
        let Some((true, path_len)) = ca.ca else {
            return Err(CertError::NotCa);
        };
        check_time(ca, self.now)?;
        if ca
            .key_usage
            .is_some_and(|ku| ku & key_usage::KEY_CERT_SIGN == 0)
        {
            return Err(CertError::KeyUsage);
        }
        if let Some(eku) = &ca.eku {
            if !eku
                .iter()
                .any(|e| e == self.usage.eku() || e == oid::ANY_EKU)
            {
                return Err(CertError::ExtendedKeyUsage);
            }
        }
        if let Some(n) = path_len {
            // CAs between this one and the leaf, not counting self-issued
            // ones (RFC 5280 6.1.4(l)).
            let below = path
                .iter()
                .filter(|&&i| !self.intermediates[i].is_self_issued())
                .count() as u64;
            if below > n {
                return Err(CertError::PathLength);
            }
        }
        Ok(())
    }

    /// Applies the name constraints of every CA on the path, the anchor's
    /// included, to every certificate below that CA.
    fn check_constraints(
        &self,
        path: &[usize],
        anchor: Option<&NameConstraints>,
    ) -> Result<(), CertError> {
        // Certificates below the anchor, leaf last.
        let mut below: Vec<(&[GeneralName], &[u8], bool)> = path
            .iter()
            .rev()
            .map(|&i| {
                let c = &self.intermediates[i];
                (
                    c.san.as_deref().unwrap_or(&[]),
                    c.subject.as_slice(),
                    !c.is_self_issued(),
                )
            })
            .collect();
        below.push((
            self.leaf.san.as_deref().unwrap_or(&[]),
            &self.leaf.subject,
            true,
        ));
        let apply = |nc: &NameConstraints,
                     certs: &[(&[GeneralName], &[u8], bool)]|
         -> Result<(), CertError> {
            for (san, subject, check_subject) in certs {
                check_constraints(
                    nc.permitted.as_deref(),
                    &nc.excluded,
                    san,
                    subject,
                    *check_subject,
                )
                .map_err(CertError::NameConstraint)?;
            }
            Ok(())
        };
        if let Some(nc) = anchor {
            apply(nc, &below)?;
        }
        for (k, &i) in path.iter().rev().enumerate() {
            if let Some(nc) = &self.intermediates[i].name_constraints {
                apply(nc, &below[k + 1..])?;
            }
        }
        Ok(())
    }
}
