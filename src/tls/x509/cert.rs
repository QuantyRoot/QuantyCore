//! X.509 v3 certificates (RFC 5280 section 4), parsed into what path
//! validation needs and nothing more.

use super::der::{named_bits, tag, Der, DerError};

pub mod oid {
    pub const RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];
    pub const SHA256_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b];
    pub const SHA384_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
    pub const SHA512_WITH_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];
    pub const RSA_PSS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
    pub const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    pub const P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    pub const P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
    pub const ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
    pub const ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
    pub const ECDSA_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04];
    pub const ED25519: &[u8] = &[0x2b, 0x65, 0x70];

    pub const BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
    pub const KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
    pub const EXT_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];
    pub const SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];
    pub const NAME_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x1e];
    pub const SUBJECT_KEY_ID: &[u8] = &[0x55, 0x1d, 0x0e];
    pub const AUTHORITY_KEY_ID: &[u8] = &[0x55, 0x1d, 0x23];
    pub const CERTIFICATE_POLICIES: &[u8] = &[0x55, 0x1d, 0x20];
    pub const POLICY_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x24];
    pub const INHIBIT_ANY_POLICY: &[u8] = &[0x55, 0x1d, 0x36];

    pub const KP_SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
    pub const KP_CLIENT_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02];
    pub const ANY_EKU: &[u8] = &[0x55, 0x1d, 0x25, 0x00];

    pub const COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
}

pub mod key_usage {
    pub const DIGITAL_SIGNATURE: u16 = 1 << 0;
    pub const KEY_ENCIPHERMENT: u16 = 1 << 2;
    pub const KEY_AGREEMENT: u16 = 1 << 4;
    pub const KEY_CERT_SIGN: u16 = 1 << 5;
    pub const CRL_SIGN: u16 = 1 << 6;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GeneralName {
    Dns(String),
    Ip(Vec<u8>),
    /// directoryName: a whole Name, as DER.
    Directory(Vec<u8>),
    /// rfc822Name, URI, and the rest, by context tag. Kept only so that
    /// name constraints of those kinds can be refused instead of skipped.
    Other(u8),
}

#[derive(Clone, Debug, Default)]
pub struct NameConstraints {
    pub permitted: Option<Vec<GeneralName>>,
    pub excluded: Vec<GeneralName>,
}

/// The subject public key: algorithm, curve if any, and key bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Spki {
    pub algorithm: Vec<u8>,
    pub curve: Option<Vec<u8>>,
    pub key: Vec<u8>,
    pub der: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Certificate {
    pub der: Vec<u8>,
    pub tbs: Vec<u8>,
    pub version: u8,
    pub serial: Vec<u8>,
    /// The signature algorithm, as the whole AlgorithmIdentifier DER.
    pub sig_alg: Vec<u8>,
    pub signature: Vec<u8>,
    pub issuer: Vec<u8>,
    pub subject: Vec<u8>,
    pub not_before: i64,
    pub not_after: i64,
    pub spki: Spki,
    pub ca: Option<(bool, Option<u64>)>,
    pub key_usage: Option<u16>,
    pub eku: Option<Vec<Vec<u8>>>,
    pub san: Option<Vec<GeneralName>>,
    pub name_constraints: Option<NameConstraints>,
    pub ski: Option<Vec<u8>>,
    pub aki: Option<Vec<u8>>,
}

type R<T> = Result<T, DerError>;

impl Certificate {
    pub fn parse(der: &[u8]) -> R<Certificate> {
        let mut outer = Der::new(der);
        let mut cert = outer.sequence()?;
        outer.end()?;
        let (tbs_body, tbs) = cert.expect_whole(tag::SEQUENCE)?;
        let (_, sig_alg) = cert.expect_whole(tag::SEQUENCE)?;
        let signature = cert.bit_string_bytes()?;
        cert.end()?;

        let mut t = Der::new(tbs_body);
        let version = match t.optional(tag::context_constructed(0))? {
            Some(v) => {
                let mut d = Der::new(v);
                let n = d.small_unsigned()?;
                d.end()?;
                match n {
                    1 | 2 => n as u8 + 1,
                    // DER forbids encoding the default.
                    _ => return Err(DerError("version")),
                }
            }
            None => 1,
        };
        let serial = t.integer()?.to_vec();
        let (_, inner_alg) = t.expect_whole(tag::SEQUENCE)?;
        if inner_alg != sig_alg {
            return Err(DerError("signature algorithms disagree"));
        }
        let (_, issuer) = t.expect_whole(tag::SEQUENCE)?;
        let mut validity = t.sequence()?;
        let not_before = time(&mut validity)?;
        let not_after = time(&mut validity)?;
        validity.end()?;
        let (_, subject) = t.expect_whole(tag::SEQUENCE)?;
        let spki = parse_spki(t.read().and_then(|(tg, _, w)| {
            if tg == tag::SEQUENCE {
                Ok(w)
            } else {
                Err(DerError("SubjectPublicKeyInfo"))
            }
        })?)?;
        // issuerUniqueID and subjectUniqueID, obsolete and ignored.
        t.optional(tag::context(1))?;
        t.optional(tag::context(2))?;
        let mut c = Certificate {
            der: der.to_vec(),
            tbs: tbs.to_vec(),
            version,
            serial,
            sig_alg: sig_alg.to_vec(),
            signature: signature.to_vec(),
            issuer: issuer.to_vec(),
            subject: subject.to_vec(),
            not_before,
            not_after,
            spki,
            ca: None,
            key_usage: None,
            eku: None,
            san: None,
            name_constraints: None,
            ski: None,
            aki: None,
        };
        if let Some(exts) = t.optional(tag::context_constructed(3))? {
            if version != 3 {
                return Err(DerError("extensions in a certificate before v3"));
            }
            c.extensions(exts)?;
        }
        t.end()?;
        Ok(c)
    }

    fn extensions(&mut self, data: &[u8]) -> R<()> {
        let mut outer = Der::new(data);
        let mut list = outer.sequence()?;
        outer.end()?;
        if list.is_empty() {
            return Err(DerError("empty extensions"));
        }
        let mut seen: Vec<&[u8]> = Vec::new();
        while !list.is_empty() {
            let mut e = list.sequence()?;
            let id = e.oid()?;
            let critical = if e.peek_tag() == Some(tag::BOOLEAN) {
                let c = e.boolean()?;
                if !c {
                    return Err(DerError("critical FALSE encoded"));
                }
                true
            } else {
                false
            };
            let value = e.expect(tag::OCTET_STRING)?;
            e.end()?;
            if seen.contains(&id) {
                return Err(DerError("duplicate extension"));
            }
            seen.push(id);
            let mut v = Der::new(value);
            match id {
                oid::BASIC_CONSTRAINTS => {
                    let mut s = v.sequence()?;
                    let ca = if s.peek_tag() == Some(tag::BOOLEAN) {
                        let b = s.boolean()?;
                        if !b {
                            return Err(DerError("cA FALSE encoded"));
                        }
                        true
                    } else {
                        false
                    };
                    let len = if s.is_empty() {
                        None
                    } else {
                        Some(s.small_unsigned()?)
                    };
                    s.end()?;
                    self.ca = Some((ca, len));
                }
                oid::KEY_USAGE => {
                    let bits = named_bits(v.expect(tag::BIT_STRING)?)?;
                    if bits == 0 {
                        return Err(DerError("empty KeyUsage"));
                    }
                    self.key_usage = Some(bits);
                }
                oid::EXT_KEY_USAGE => {
                    let mut s = v.sequence()?;
                    let mut list = Vec::new();
                    while !s.is_empty() {
                        list.push(s.oid()?.to_vec());
                    }
                    if list.is_empty() {
                        return Err(DerError("empty ExtendedKeyUsage"));
                    }
                    self.eku = Some(list);
                }
                oid::SUBJECT_ALT_NAME => {
                    let names = general_names(v.sequence()?)?;
                    if names.is_empty() {
                        return Err(DerError("empty SubjectAltName"));
                    }
                    for n in &names {
                        match n {
                            GeneralName::Dns(d) if !super::name::valid_dns(d, true) => {
                                return Err(DerError("invalid dNSName in SubjectAltName"))
                            }
                            GeneralName::Ip(a) if a.len() != 4 && a.len() != 16 => {
                                return Err(DerError("invalid iPAddress in SubjectAltName"))
                            }
                            _ => {}
                        }
                    }
                    // RFC 5280 4.2.1.6: with an empty subject the SAN
                    // carries the identity and must be critical.
                    if !critical && self.subject == [0x30, 0x00] {
                        return Err(DerError(
                            "SubjectAltName not critical with an empty subject",
                        ));
                    }
                    self.san = Some(names);
                }
                oid::NAME_CONSTRAINTS => {
                    if !critical {
                        return Err(DerError("NameConstraints not critical"));
                    }
                    let mut s = v.sequence()?;
                    let mut nc = NameConstraints::default();
                    if let Some(p) = s.optional(tag::context_constructed(0))? {
                        nc.permitted = Some(subtrees(p)?);
                    }
                    if let Some(x) = s.optional(tag::context_constructed(1))? {
                        nc.excluded = subtrees(x)?;
                    }
                    s.end()?;
                    if nc.permitted.is_none() && nc.excluded.is_empty() {
                        return Err(DerError("empty NameConstraints"));
                    }
                    self.name_constraints = Some(nc);
                }
                oid::SUBJECT_KEY_ID | oid::AUTHORITY_KEY_ID if critical => {
                    return Err(DerError("key identifier marked critical"))
                }
                oid::POLICY_CONSTRAINTS if !critical => {
                    return Err(DerError("PolicyConstraints not critical"))
                }
                oid::SUBJECT_KEY_ID => self.ski = Some(v.expect(tag::OCTET_STRING)?.to_vec()),
                oid::AUTHORITY_KEY_ID => {
                    let mut s = v.sequence()?;
                    self.aki = s.optional(tag::context(0))?.map(|k| k.to_vec());
                    continue;
                }
                // Policies are not evaluated; a critical policy extension
                // could change what the certificate may be used for, and
                // is refused below like any other unknown critical one.
                _ if critical => return Err(DerError("unknown critical extension")),
                _ => continue,
            }
            v.end()?;
        }
        Ok(())
    }

    /// The common name of the subject, for messages only; names are
    /// matched against subjectAltName alone.
    pub fn subject_cn(&self) -> Option<String> {
        let mut d = Der::new(&self.subject);
        let mut name = d.sequence().ok()?;
        while !name.is_empty() {
            let mut set = Der::new(name.expect(tag::SET).ok()?);
            while !set.is_empty() {
                let mut atv = set.sequence().ok()?;
                let id = atv.oid().ok()?;
                let (_, v, _) = atv.read().ok()?;
                if id == oid::COMMON_NAME {
                    return String::from_utf8(v.to_vec()).ok();
                }
            }
        }
        None
    }

    pub fn is_self_issued(&self) -> bool {
        self.issuer == self.subject
    }
}

pub(crate) fn parse_spki(der: &[u8]) -> R<Spki> {
    let mut outer = Der::new(der);
    let mut s = outer.sequence()?;
    let mut alg = s.sequence()?;
    let algorithm = alg.oid()?.to_vec();
    let curve = match alg.peek_tag() {
        Some(tag::OID) => Some(alg.oid()?.to_vec()),
        Some(tag::NULL) => {
            if !alg.expect(tag::NULL)?.is_empty() {
                return Err(DerError("NULL"));
            }
            None
        }
        _ => None,
    };
    alg.end()?;
    let key = s.bit_string_bytes()?.to_vec();
    s.end()?;
    Ok(Spki {
        algorithm,
        curve,
        key,
        der: der.to_vec(),
    })
}

pub(crate) fn general_names(mut s: Der) -> R<Vec<GeneralName>> {
    let mut out = Vec::new();
    while !s.is_empty() {
        out.push(general_name(&mut s)?);
    }
    Ok(out)
}

fn general_name(s: &mut Der) -> R<GeneralName> {
    let (t, v, _) = s.read()?;
    Ok(match t {
        0x82 => {
            let name = std::str::from_utf8(v).map_err(|_| DerError("dNSName"))?;
            if !name.is_ascii() {
                return Err(DerError("dNSName"));
            }
            GeneralName::Dns(name.to_ascii_lowercase())
        }
        0x87 => GeneralName::Ip(v.to_vec()),
        0xa4 => {
            let mut d = Der::new(v);
            let (_, name) = d.expect_whole(tag::SEQUENCE)?;
            d.end()?;
            GeneralName::Directory(name.to_vec())
        }
        other => GeneralName::Other(other & 0x1f),
    })
}

fn subtrees(data: &[u8]) -> R<Vec<GeneralName>> {
    let mut d = Der::new(data);
    let mut out = Vec::new();
    while !d.is_empty() {
        let mut st = d.sequence()?;
        let base = general_name(&mut st)?;
        // A dNSName constraint is a host name or empty; the leading dot
        // form belongs to URI constraints.
        if let GeneralName::Dns(n) = &base {
            if !n.is_empty() && !super::name::valid_dns(n, false) {
                return Err(DerError("invalid dNSName constraint"));
            }
        }
        // minimum and maximum: RFC 5280 requires the defaults, which DER
        // leaves out.
        if !st.is_empty() {
            return Err(DerError("GeneralSubtree minimum or maximum"));
        }
        out.push(base);
    }
    if out.is_empty() {
        return Err(DerError("empty GeneralSubtrees"));
    }
    Ok(out)
}

/// UTCTime or GeneralizedTime as Unix seconds, in the forms RFC 5280
/// 4.1.2.5 allows: seconds present, Zulu, no fractions; UTCTime until
/// 2049, GeneralizedTime from 2050.
fn time(d: &mut Der) -> R<i64> {
    let (t, v, _) = d.read()?;
    let s = std::str::from_utf8(v).map_err(|_| DerError("time"))?;
    let digits = |r: std::ops::Range<usize>| -> R<i64> {
        let part = s.get(r).ok_or(DerError("time"))?;
        if !part.bytes().all(|b| b.is_ascii_digit()) {
            return Err(DerError("time"));
        }
        part.parse().map_err(|_| DerError("time"))
    };
    let (year, rest) = match t {
        tag::UTC_TIME if s.len() == 13 => {
            let yy = digits(0..2)?;
            (if yy < 50 { 2000 + yy } else { 1900 + yy }, 2)
        }
        tag::GENERALIZED_TIME if s.len() == 15 => (digits(0..4)?, 4),
        _ => return Err(DerError("time")),
    };
    if !s.ends_with('Z') {
        return Err(DerError("time zone"));
    }
    let month = digits(rest..rest + 2)?;
    let day = digits(rest + 2..rest + 4)?;
    let hour = digits(rest + 4..rest + 6)?;
    let min = digits(rest + 6..rest + 8)?;
    let sec = digits(rest + 8..rest + 10)?;
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let mdays = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if !(1..=12).contains(&month)
        || day < 1
        || day > mdays[month as usize - 1]
        || hour > 23
        || min > 59
        || sec > 59
    {
        return Err(DerError("time out of range"));
    }
    Ok(days_from_civil(year, month, day) * 86400 + hour * 3600 + min * 60 + sec)
}

/// Days since 1970-01-01 (Howard Hinnant's algorithm).
pub fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times() {
        let mut d = Der::new(b"\x17\x0d491231235959Z");
        assert_eq!(time(&mut d).unwrap(), 2524607999);
        let mut d = Der::new(b"\x17\x0d500101000000Z");
        assert_eq!(time(&mut d).unwrap(), -631152000);
        let mut d = Der::new(b"\x18\x0f20240229120000Z");
        assert_eq!(time(&mut d).unwrap(), 1709208000);
        assert!(time(&mut Der::new(b"\x18\x0f20230229120000Z")).is_err());
        assert!(time(&mut Der::new(b"\x17\x0b4912312359Z")).is_err());
        assert!(time(&mut Der::new(b"\x18\x1120240229120000.5Z")).is_err());
    }
}
