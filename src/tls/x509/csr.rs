//! Certificate signing requests (PKCS#10, RFC 2986): a key asks a CA for
//! a certificate with a name and subjectAltNames. `request` writes one,
//! `CertificateRequest::parse` reads one and checks its signature, and
//! the CA then issues with `build::issue` for the key in it.

use super::build::{self, SanEntry};
use super::cert::{general_names, oid, parse_spki, GeneralName, Spki};
use super::der::{self, tag, Der, DerError};
use super::keys::PrivateKey;
use super::name::valid_dns;
use crate::tls::auth::PublicKey;

/// pkcs-9-at-extensionRequest (RFC 2985 5.4.2).
const EXTENSION_REQUEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e];

/// A request from `key` for a certificate naming `common_name` and
/// `san`, as DER.
pub fn request(common_name: &str, san: &[SanEntry], key: &PrivateKey) -> Vec<u8> {
    let mut info = der::wrap(tag::INTEGER, &[0]);
    info.extend_from_slice(&build::name(common_name));
    info.extend_from_slice(&key.public_spki());
    let mut attrs = Vec::new();
    if !san.is_empty() {
        let mut ext = der::wrap(tag::OID, oid::SUBJECT_ALT_NAME);
        der::write(&mut ext, tag::OCTET_STRING, &build::san_der(san));
        let exts = der::wrap(tag::SEQUENCE, &der::wrap(tag::SEQUENCE, &ext));
        let mut attr = der::wrap(tag::OID, EXTENSION_REQUEST);
        der::write(&mut attr, tag::SET, &exts);
        der::write(&mut attrs, tag::SEQUENCE, &attr);
    }
    der::write(&mut info, tag::context_constructed(0), &attrs);
    let info = der::wrap(tag::SEQUENCE, &info);
    let (alg, sig) = key.sign_x509(&info);
    let mut out = info;
    out.extend_from_slice(&alg);
    let mut bits = vec![0];
    bits.extend_from_slice(&sig);
    der::write(&mut out, tag::BIT_STRING, &bits);
    der::wrap(tag::SEQUENCE, &out)
}

/// A parsed request whose signature has been checked: its key really
/// asked for these names.
#[derive(Clone, Debug)]
pub struct CertificateRequest {
    /// The subject Name as DER.
    pub subject: Vec<u8>,
    pub spki: Spki,
    /// The subjectAltNames asked for, if any.
    pub san: Vec<SanEntry>,
}

type R<T> = Result<T, DerError>;

impl CertificateRequest {
    pub fn parse(der: &[u8]) -> R<CertificateRequest> {
        let mut outer = Der::new(der);
        let mut req = outer.sequence()?;
        outer.end()?;
        let (info, info_whole) = req.expect_whole(tag::SEQUENCE)?;
        let (_, alg) = req.expect_whole(tag::SEQUENCE)?;
        let sig = req.bit_string_bytes()?;
        req.end()?;

        let mut i = Der::new(info);
        if i.small_unsigned()? != 0 {
            return Err(DerError("request version"));
        }
        let (_, subject) = i.expect_whole(tag::SEQUENCE)?;
        let (_, spki_der) = i.expect_whole(tag::SEQUENCE)?;
        let spki = parse_spki(spki_der)?;
        let attrs = i.expect(tag::context_constructed(0))?;
        i.end()?;

        let mut san = None;
        let mut seen_request = false;
        let mut a = Der::new(attrs);
        while !a.is_empty() {
            let mut attr = a.sequence()?;
            let id = attr.oid()?;
            let mut values = Der::new(attr.expect(tag::SET)?);
            attr.end()?;
            if id != EXTENSION_REQUEST {
                continue;
            }
            if seen_request {
                return Err(DerError("extensionRequest twice"));
            }
            seen_request = true;
            let mut exts = values.sequence()?;
            values.end()?;
            while !exts.is_empty() {
                let mut e = exts.sequence()?;
                let eid = e.oid()?;
                if e.peek_tag() == Some(tag::BOOLEAN) {
                    e.boolean()?;
                }
                let value = e.expect(tag::OCTET_STRING)?;
                e.end()?;
                if eid != oid::SUBJECT_ALT_NAME {
                    continue;
                }
                if san.is_some() {
                    return Err(DerError("subjectAltName twice"));
                }
                let mut v = Der::new(value);
                let names = general_names(v.sequence()?)?;
                v.end()?;
                let list: &mut Vec<SanEntry> = san.insert(Vec::new());
                for n in names {
                    list.push(match n {
                        // A wildcard is a valid request; whether to grant
                        // it is the CA's decision.
                        GeneralName::Dns(d) if valid_dns(&d, true) => SanEntry::Dns(d),
                        GeneralName::Dns(_) => return Err(DerError("invalid dNSName")),
                        GeneralName::Ip(ip) => SanEntry::Ip(ip_of(&ip)?),
                        _ => return Err(DerError("subjectAltName kind not supported")),
                    });
                }
            }
        }

        let key = PublicKey::from_spki(&spki).map_err(|_| DerError("request key"))?;
        key.verify_x509(alg, info_whole, sig)
            .map_err(|_| DerError("request signature does not verify"))?;
        Ok(CertificateRequest {
            subject: subject.to_vec(),
            spki,
            san: san.unwrap_or_default(),
        })
    }

    /// The common name of the subject, if it has one.
    pub fn common_name(&self) -> Option<String> {
        super::cert::name_cn(&self.subject)
    }
}

fn ip_of(b: &[u8]) -> R<std::net::IpAddr> {
    match b.len() {
        4 => Ok(std::net::IpAddr::from(<[u8; 4]>::try_from(b).unwrap())),
        16 => Ok(std::net::IpAddr::from(<[u8; 16]>::try_from(b).unwrap())),
        _ => Err(DerError("iPAddress length")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::crypto::ec::Curve;

    #[test]
    #[cfg_attr(not(unix), ignore = "needs operating system randomness (ADR-040)")]
    fn round_trip_and_a_forged_request() {
        let san = vec![
            SanEntry::Dns("node-1.cluster.test".into()),
            SanEntry::Ip("10.0.0.1".parse().unwrap()),
            SanEntry::Ip("fd00::1".parse().unwrap()),
        ];
        for key in [
            PrivateKey::generate_ed25519().unwrap(),
            PrivateKey::generate_ec(Curve::P256).unwrap(),
            PrivateKey::generate_ec(Curve::P384).unwrap(),
        ] {
            let der = request("node-1", &san, &key);
            let r = CertificateRequest::parse(&der).unwrap();
            assert_eq!(r.san, san);
            assert_eq!(r.spki.der, key.public_spki());
            assert_eq!(r.subject, build::name("node-1"));
            assert_eq!(r.common_name().as_deref(), Some("node-1"));

            // Any changed byte of the request info breaks the signature
            // or the encoding.
            for i in [10, der.len() / 2] {
                let mut bad = der.clone();
                bad[i] ^= 1;
                assert!(CertificateRequest::parse(&bad).is_err(), "byte {i}");
            }
            // Another key's signature over the same info.
            let other = PrivateKey::generate_ed25519().unwrap();
            let forged = request("node-1", &san, &other);
            let mut d = Der::new(&der);
            let mut s = d.sequence().unwrap();
            let (_, info) = s.expect_whole(tag::SEQUENCE).unwrap();
            let mut f = Der::new(&forged);
            let mut fs = f.sequence().unwrap();
            fs.expect_whole(tag::SEQUENCE).unwrap();
            let (_, alg) = fs.expect_whole(tag::SEQUENCE).unwrap();
            let (_, sig) = fs.expect_whole(tag::BIT_STRING).unwrap();
            let mut body = info.to_vec();
            body.extend_from_slice(alg);
            body.extend_from_slice(sig);
            let spliced = der::wrap(tag::SEQUENCE, &body);
            assert!(CertificateRequest::parse(&spliced).is_err());
        }
    }

    #[test]
    #[cfg_attr(not(unix), ignore = "needs operating system randomness (ADR-040)")]
    fn requests_with_bad_names_are_refused() {
        let key = PrivateKey::generate_ed25519().unwrap();
        let wildcard = request("w", &[SanEntry::Dns("*.cluster.test".into())], &key);
        assert_eq!(
            CertificateRequest::parse(&wildcard).unwrap().san,
            vec![SanEntry::Dns("*.cluster.test".into())]
        );
        let bad = request("b", &[SanEntry::Dns("bad name.test".into())], &key);
        assert!(CertificateRequest::parse(&bad).is_err());
    }
}
