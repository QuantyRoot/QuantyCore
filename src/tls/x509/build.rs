//! Issuing certificates: a self-signed CA, and certificates it signs.
//! QuantyKube runs its own CA for the cluster, which is why this exists.

use super::cert::{key_usage, oid};
use super::der::{self, tag};
use super::keys::PrivateKey;
use super::Certificate;
use crate::tls::crypto::rand;
use crate::tls::crypto::sha2::{Hash, Sha256};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SanEntry {
    Dns(String),
    Ip(std::net::IpAddr),
}

/// What goes into a certificate. Times are Unix seconds.
#[derive(Clone, Debug)]
pub struct Params {
    pub common_name: String,
    pub san: Vec<SanEntry>,
    pub not_before: i64,
    pub not_after: i64,
    /// `Some(path_len)` for a CA, `None` for an end entity.
    pub ca: Option<Option<u64>>,
    pub server_auth: bool,
    pub client_auth: bool,
    /// KeyUsage for a CA instead of keyCertSign and cRLSign.
    pub ca_key_usage: Option<u16>,
    /// Permitted and excluded subtrees, for a CA.
    pub name_constraints: Option<(Vec<SanEntry>, Vec<SanEntry>)>,
}

impl Params {
    pub fn end_entity(
        common_name: &str,
        san: Vec<SanEntry>,
        not_before: i64,
        not_after: i64,
    ) -> Params {
        Params {
            common_name: common_name.into(),
            san,
            not_before,
            not_after,
            ca: None,
            server_auth: true,
            client_auth: true,
            name_constraints: None,
            ca_key_usage: None,
        }
    }

    pub fn ca(common_name: &str, not_before: i64, not_after: i64) -> Params {
        Params {
            common_name: common_name.into(),
            san: Vec::new(),
            not_before,
            not_after,
            ca: Some(None),
            server_auth: false,
            client_auth: false,
            name_constraints: None,
            ca_key_usage: None,
        }
    }
}

pub(crate) fn name(common_name: &str) -> Vec<u8> {
    let mut atv = der::wrap(tag::OID, oid::COMMON_NAME);
    der::write(&mut atv, tag::UTF8_STRING, common_name.as_bytes());
    der::wrap(
        tag::SEQUENCE,
        &der::wrap(tag::SET, &der::wrap(tag::SEQUENCE, &atv)),
    )
}

fn time(out: &mut Vec<u8>, t: i64) {
    let (y, mo, d) = civil_from_days(t.div_euclid(86400));
    let s = t.rem_euclid(86400);
    let (h, mi, se) = (s / 3600, s % 3600 / 60, s % 60);
    if (1950..2050).contains(&y) {
        let v = format!("{:02}{mo:02}{d:02}{h:02}{mi:02}{se:02}Z", y % 100);
        der::write(out, tag::UTC_TIME, v.as_bytes());
    } else {
        let v = format!("{y:04}{mo:02}{d:02}{h:02}{mi:02}{se:02}Z");
        der::write(out, tag::GENERALIZED_TIME, v.as_bytes());
    }
}

/// The inverse of `cert::days_from_civil` (Howard Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

fn key_id(spki: &[u8]) -> Vec<u8> {
    Sha256::digest(spki)[..20].to_vec()
}

fn extension(out: &mut Vec<u8>, id: &[u8], critical: bool, value: &[u8]) {
    let mut e = der::wrap(tag::OID, id);
    if critical {
        der::write(&mut e, tag::BOOLEAN, &[0xff]);
    }
    der::write(&mut e, tag::OCTET_STRING, value);
    der::write(out, tag::SEQUENCE, &e);
}

/// Who signs: the issuer's subject Name, its key identifier, and its key.
pub struct Issuer<'a> {
    pub name: Vec<u8>,
    pub key_id: Vec<u8>,
    pub key: &'a PrivateKey,
}

impl<'a> Issuer<'a> {
    pub fn from_certificate(
        cert_der: &[u8],
        key: &'a PrivateKey,
    ) -> Result<Issuer<'a>, &'static str> {
        let c = Certificate::parse(cert_der).map_err(|e| e.0)?;
        Ok(Issuer {
            key_id: c.ski.clone().unwrap_or_else(|| key_id(&c.spki.der)),
            name: c.subject,
            key,
        })
    }
}

/// A certificate for `subject_spki` with `p`, signed by `issuer`, or
/// self-signed when `issuer` is `None` (then `self_key` signs).
pub fn issue(
    p: &Params,
    subject_spki: &[u8],
    issuer: Option<&Issuer>,
    self_key: &PrivateKey,
) -> std::io::Result<Vec<u8>> {
    let mut serial = [0u8; 16];
    rand::fill(&mut serial)?;
    serial[0] &= 0x7f;
    serial[0] |= 0x01;
    let subject = name(&p.common_name);
    let ski = key_id(&der_spki_key(subject_spki));
    let (issuer_name, aki, key) = match issuer {
        Some(i) => (i.name.clone(), i.key_id.clone(), i.key),
        None => (subject.clone(), ski.clone(), self_key),
    };
    let (alg, _) = key.sign_x509(b"");

    let mut exts = Vec::new();
    match p.ca {
        Some(path_len) => {
            let mut bc = Vec::new();
            der::write(&mut bc, tag::BOOLEAN, &[0xff]);
            if let Some(n) = path_len {
                der::write_unsigned(&mut bc, &n.to_be_bytes());
            }
            extension(
                &mut exts,
                oid::BASIC_CONSTRAINTS,
                true,
                &der::wrap(tag::SEQUENCE, &bc),
            );
            let ku = p
                .ca_key_usage
                .unwrap_or(key_usage::KEY_CERT_SIGN | key_usage::CRL_SIGN);
            extension(&mut exts, oid::KEY_USAGE, true, &key_usage_bits(ku));
        }
        None => {
            extension(
                &mut exts,
                oid::BASIC_CONSTRAINTS,
                true,
                &der::wrap(tag::SEQUENCE, &[]),
            );
            extension(
                &mut exts,
                oid::KEY_USAGE,
                true,
                &key_usage_bits(key_usage::DIGITAL_SIGNATURE),
            );
            let mut eku = Vec::new();
            if p.server_auth {
                der::write(&mut eku, tag::OID, oid::KP_SERVER_AUTH);
            }
            if p.client_auth {
                der::write(&mut eku, tag::OID, oid::KP_CLIENT_AUTH);
            }
            if !eku.is_empty() {
                extension(
                    &mut exts,
                    oid::EXT_KEY_USAGE,
                    false,
                    &der::wrap(tag::SEQUENCE, &eku),
                );
            }
        }
    }
    if let Some((permitted, excluded)) = &p.name_constraints {
        let subtrees = |list: &[SanEntry]| {
            let mut out = Vec::new();
            for s in list {
                let mut st = Vec::new();
                match s {
                    SanEntry::Dns(d) => der::write(&mut st, 0x82, d.as_bytes()),
                    SanEntry::Ip(std::net::IpAddr::V4(a)) => {
                        let mut v = a.octets().to_vec();
                        v.extend_from_slice(&[255, 255, 255, 255]);
                        der::write(&mut st, 0x87, &v)
                    }
                    SanEntry::Ip(std::net::IpAddr::V6(a)) => {
                        let mut v = a.octets().to_vec();
                        v.extend_from_slice(&[255; 16]);
                        der::write(&mut st, 0x87, &v)
                    }
                }
                der::write(&mut out, tag::SEQUENCE, &st);
            }
            out
        };
        let mut nc = Vec::new();
        if !permitted.is_empty() {
            der::write(&mut nc, tag::context_constructed(0), &subtrees(permitted));
        }
        if !excluded.is_empty() {
            der::write(&mut nc, tag::context_constructed(1), &subtrees(excluded));
        }
        extension(
            &mut exts,
            oid::NAME_CONSTRAINTS,
            true,
            &der::wrap(tag::SEQUENCE, &nc),
        );
    }
    if !p.san.is_empty() {
        let mut names = Vec::new();
        for s in &p.san {
            match s {
                SanEntry::Dns(d) => der::write(&mut names, 0x82, d.to_ascii_lowercase().as_bytes()),
                SanEntry::Ip(std::net::IpAddr::V4(a)) => der::write(&mut names, 0x87, &a.octets()),
                SanEntry::Ip(std::net::IpAddr::V6(a)) => der::write(&mut names, 0x87, &a.octets()),
            }
        }
        extension(
            &mut exts,
            oid::SUBJECT_ALT_NAME,
            false,
            &der::wrap(tag::SEQUENCE, &names),
        );
    }
    extension(
        &mut exts,
        oid::SUBJECT_KEY_ID,
        false,
        &der::wrap(tag::OCTET_STRING, &ski),
    );
    extension(
        &mut exts,
        oid::AUTHORITY_KEY_ID,
        false,
        &der::wrap(tag::SEQUENCE, &der::wrap(tag::context(0), &aki)),
    );

    let mut tbs = Vec::new();
    der::write(
        &mut tbs,
        tag::context_constructed(0),
        &der::wrap(tag::INTEGER, &[2]),
    );
    der::write_unsigned(&mut tbs, &serial);
    tbs.extend_from_slice(&alg);
    tbs.extend_from_slice(&issuer_name);
    let mut validity = Vec::new();
    time(&mut validity, p.not_before);
    time(&mut validity, p.not_after);
    der::write(&mut tbs, tag::SEQUENCE, &validity);
    tbs.extend_from_slice(&subject);
    tbs.extend_from_slice(subject_spki);
    der::write(
        &mut tbs,
        tag::context_constructed(3),
        &der::wrap(tag::SEQUENCE, &exts),
    );
    let tbs = der::wrap(tag::SEQUENCE, &tbs);

    let (alg, sig) = key.sign_x509(&tbs);
    let mut cert = tbs;
    cert.extend_from_slice(&alg);
    let mut bits = vec![0];
    bits.extend_from_slice(&sig);
    der::write(&mut cert, tag::BIT_STRING, &bits);
    Ok(der::wrap(tag::SEQUENCE, &cert))
}

/// KeyUsage as a DER BIT STRING: bit 0 is the top bit of the first
/// byte, and trailing zero bits are left out.
fn key_usage_bits(ku: u16) -> Vec<u8> {
    let mut bytes = [0u8; 2];
    for i in 0..16 {
        if ku & (1 << i) != 0 {
            bytes[i / 8] |= 0x80 >> (i % 8);
        }
    }
    let n = if bytes[1] != 0 { 2 } else { 1 };
    let mut v = vec![bytes[n - 1].trailing_zeros() as u8];
    v.extend_from_slice(&bytes[..n]);
    der::wrap(tag::BIT_STRING, &v)
}

/// The key bits of a SubjectPublicKeyInfo, which RFC 5280 4.2.1.2 method
/// (1) hashes into the key identifier.
fn der_spki_key(spki: &[u8]) -> Vec<u8> {
    let mut d = der::Der::new(spki);
    d.sequence()
        .and_then(|mut s| {
            s.sequence()?;
            s.bit_string_bytes().map(|b| b.to_vec())
        })
        .unwrap_or_else(|_| spki.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates_round_trip() {
        for t in [
            0i64,
            951782400,
            2524607999,
            2524608000,
            32503680000,
            -631152000,
        ] {
            let mut out = Vec::new();
            time(&mut out, t);
            let (y, m, d) = civil_from_days(t.div_euclid(86400));
            assert_eq!(
                super::super::cert::days_from_civil(y, m, d),
                t.div_euclid(86400)
            );
        }
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(11016), (2000, 2, 29));
    }
}
