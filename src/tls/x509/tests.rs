//! Path validation on chains issued here: root, intermediate, leaf, each
//! broken in one way at a time.

#![cfg(test)]

use super::build::{issue, Issuer, Params, SanEntry};
use super::name::ServerName;
use super::path::{verify_chain, CertError, RootStore, Usage};
use super::{Certificate, PrivateKey};

const NOW: i64 = 1_800_000_000;
const DAY: i64 = 86400;

struct Pki {
    root_key: PrivateKey,
    root: Vec<u8>,
    inter_key: PrivateKey,
    inter: Vec<u8>,
    leaf_key: PrivateKey,
}

fn key(seed: u8) -> PrivateKey {
    PrivateKey::Ed25519(crate::tls::crypto::ed25519::SigningKey::from_seed(
        &[seed; 32],
    ))
}

fn pki_with(inter: impl FnOnce(&mut Params)) -> Pki {
    let root_key = key(1);
    let root = issue(
        &Params::ca("Root", NOW - 10 * DAY, NOW + 3650 * DAY),
        &root_key.public_spki(),
        None,
        &root_key,
    )
    .unwrap();
    let inter_key = key(2);
    let mut p = Params::ca("Intermediate", NOW - 10 * DAY, NOW + 365 * DAY);
    inter(&mut p);
    let ri = Issuer::from_certificate(&root, &root_key).unwrap();
    let inter = issue(&p, &inter_key.public_spki(), Some(&ri), &inter_key).unwrap();
    Pki {
        root_key,
        root,
        inter_key,
        inter,
        leaf_key: key(3),
    }
}

impl Pki {
    fn leaf(&self, edit: impl FnOnce(&mut Params)) -> Vec<u8> {
        let mut p = Params::end_entity(
            "leaf",
            vec![
                SanEntry::Dns("www.example.com".into()),
                SanEntry::Ip("10.0.0.1".parse().unwrap()),
            ],
            NOW - DAY,
            NOW + 90 * DAY,
        );
        edit(&mut p);
        let i = Issuer::from_certificate(&self.inter, &self.inter_key).unwrap();
        issue(&p, &self.leaf_key.public_spki(), Some(&i), &self.leaf_key).unwrap()
    }

    fn roots(&self) -> RootStore {
        let mut r = RootStore::new();
        r.add_der(&self.root).unwrap();
        r
    }

    fn check(&self, leaf: Vec<u8>, name: &str) -> Result<(), CertError> {
        verify_chain(
            &self.roots(),
            &[leaf, self.inter.clone()],
            Some(&ServerName::parse(name).unwrap()),
            Usage::Server,
            NOW,
        )
        .map(|_| ())
    }
}

#[test]
#[cfg_attr(not(unix), ignore = "needs operating system randomness (ADR-040)")]
fn a_good_chain_and_its_names() {
    let p = pki_with(|_| {});
    assert_eq!(p.check(p.leaf(|_| {}), "www.example.com"), Ok(()));
    assert_eq!(p.check(p.leaf(|_| {}), "WWW.Example.com."), Ok(()));
    assert_eq!(p.check(p.leaf(|_| {}), "10.0.0.1"), Ok(()));
    assert_eq!(
        p.check(p.leaf(|_| {}), "example.com"),
        Err(CertError::NameMismatch)
    );
    assert_eq!(
        p.check(p.leaf(|_| {}), "10.0.0.2"),
        Err(CertError::NameMismatch)
    );
    let wild = p.leaf(|l| l.san = vec![SanEntry::Dns("*.example.com".into())]);
    assert_eq!(p.check(wild.clone(), "api.example.com"), Ok(()));
    assert_eq!(
        p.check(wild, "a.b.example.com"),
        Err(CertError::NameMismatch)
    );
}

#[test]
#[cfg_attr(not(unix), ignore = "needs operating system randomness (ADR-040)")]
fn time_bounds() {
    let p = pki_with(|_| {});
    assert_eq!(
        p.check(p.leaf(|l| l.not_after = NOW - 1), "www.example.com"),
        Err(CertError::Expired)
    );
    assert_eq!(
        p.check(p.leaf(|l| l.not_before = NOW + 1), "www.example.com"),
        Err(CertError::NotYetValid)
    );
    let p = pki_with(|i| i.not_after = NOW - 1);
    assert_eq!(
        p.check(p.leaf(|_| {}), "www.example.com"),
        Err(CertError::Expired)
    );
}

#[test]
#[cfg_attr(not(unix), ignore = "needs operating system randomness (ADR-040)")]
fn issuers_must_be_trusted_cas() {
    let p = pki_with(|_| {});
    // No path to a root.
    let r = verify_chain(
        &RootStore::new(),
        &[p.leaf(|_| {}), p.inter.clone()],
        None,
        Usage::Server,
        NOW,
    );
    assert_eq!(r.unwrap_err(), CertError::UnknownIssuer);
    // The intermediate missing from what the peer sent.
    let r = verify_chain(&p.roots(), &[p.leaf(|_| {})], None, Usage::Server, NOW);
    assert_eq!(r.unwrap_err(), CertError::UnknownIssuer);
    // An "intermediate" that is an end entity.
    let p = pki_with(|i| i.ca = None);
    assert_eq!(
        p.check(p.leaf(|_| {}), "www.example.com"),
        Err(CertError::NotCa)
    );
    // A CA certificate presented as the leaf.
    let p = pki_with(|_| {});
    assert_eq!(
        p.check(p.leaf(|l| l.ca = Some(None)), "www.example.com"),
        Err(CertError::CaAsEndEntity)
    );
}

#[test]
#[cfg_attr(not(unix), ignore = "needs operating system randomness (ADR-040)")]
fn signatures_are_checked() {
    let p = pki_with(|_| {});
    let mut leaf = p.leaf(|_| {});
    let n = leaf.len();
    leaf[n - 1] ^= 1;
    assert_eq!(
        p.check(leaf, "www.example.com"),
        Err(CertError::BadSignature)
    );
    // An intermediate with the same name, signed by another key.
    let other = key(9);
    let forged = issue(
        &Params::ca("Intermediate", NOW - DAY, NOW + DAY),
        &p.inter_key.public_spki(),
        Some(&Issuer {
            name: Certificate::parse(&p.root).unwrap().subject,
            key_id: vec![1; 20],
            key: &other,
        }),
        &other,
    )
    .unwrap();
    let r = verify_chain(
        &p.roots(),
        &[p.leaf(|_| {}), forged],
        None,
        Usage::Server,
        NOW,
    );
    assert_eq!(r.unwrap_err(), CertError::BadSignature);
    let _ = &p.root_key;
}

#[test]
#[cfg_attr(not(unix), ignore = "needs operating system randomness (ADR-040)")]
fn purpose_and_path_length() {
    let p = pki_with(|_| {});
    let client_only = p.leaf(|l| l.server_auth = false);
    assert_eq!(
        p.check(client_only.clone(), "www.example.com"),
        Err(CertError::ExtendedKeyUsage)
    );
    let r = verify_chain(
        &p.roots(),
        &[client_only, p.inter.clone()],
        None,
        Usage::Client,
        NOW,
    );
    assert!(r.is_ok());
    // pathLen 0 on the intermediate: a leaf below it is fine.
    let p = pki_with(|i| i.ca = Some(Some(0)));
    assert_eq!(p.check(p.leaf(|_| {}), "www.example.com"), Ok(()));
    // A second intermediate below one with pathLen 0 is not.
    let k2 = key(4);
    let i1 = Issuer::from_certificate(&p.inter, &p.inter_key).unwrap();
    let inter2 = issue(
        &Params::ca("Second", NOW - DAY, NOW + DAY),
        &k2.public_spki(),
        Some(&i1),
        &k2,
    )
    .unwrap();
    let i2 = Issuer::from_certificate(&inter2, &k2).unwrap();
    let leaf = issue(
        &Params::end_entity(
            "leaf",
            vec![SanEntry::Dns("www.example.com".into())],
            NOW - DAY,
            NOW + DAY,
        ),
        &p.leaf_key.public_spki(),
        Some(&i2),
        &k2,
    )
    .unwrap();
    let r = verify_chain(
        &p.roots(),
        &[leaf, inter2, p.inter.clone()],
        None,
        Usage::Server,
        NOW,
    );
    assert_eq!(r.unwrap_err(), CertError::PathLength);
}

#[test]
#[cfg_attr(not(unix), ignore = "needs operating system randomness (ADR-040)")]
fn name_constraints() {
    let p = pki_with(|i| {
        i.name_constraints = Some((
            vec![SanEntry::Dns("example.com".into())],
            vec![SanEntry::Dns("bad.example.com".into())],
        ))
    });
    assert_eq!(
        p.check(
            p.leaf(|l| l.san = vec![SanEntry::Dns("www.example.com".into())]),
            "www.example.com"
        ),
        Ok(())
    );
    let outside = p.leaf(|l| l.san = vec![SanEntry::Dns("www.example.org".into())]);
    assert!(matches!(
        p.check(outside, "www.example.org"),
        Err(CertError::NameConstraint(_))
    ));
    let excluded = p.leaf(|l| l.san = vec![SanEntry::Dns("bad.example.com".into())]);
    assert!(matches!(
        p.check(excluded, "bad.example.com"),
        Err(CertError::NameConstraint(_))
    ));
    // A wildcard that would also stand for the excluded name.
    let wild = p.leaf(|l| l.san = vec![SanEntry::Dns("*.example.com".into())]);
    assert!(matches!(
        p.check(wild, "ok.example.com"),
        Err(CertError::NameConstraint(_))
    ));

    let p = pki_with(|i| {
        i.name_constraints = Some((vec![SanEntry::Ip("10.0.0.1".parse().unwrap())], vec![]))
    });
    assert_eq!(
        p.check(
            p.leaf(|l| l.san = vec![SanEntry::Ip("10.0.0.1".parse().unwrap())]),
            "10.0.0.1"
        ),
        Ok(())
    );
    let other_ip = p.leaf(|l| l.san = vec![SanEntry::Ip("10.0.0.2".parse().unwrap())]);
    assert!(matches!(
        p.check(other_ip, "10.0.0.2"),
        Err(CertError::NameConstraint(_))
    ));
}

#[test]
#[cfg_attr(not(unix), ignore = "needs operating system randomness (ADR-040)")]
fn a_path_longer_than_six_is_refused() {
    // A valid chain with eight intermediates: every signature is right,
    // only the length is not.
    let p = pki_with(|_| {});
    let keys: Vec<PrivateKey> = (0..8).map(|i| key(50 + i)).collect();
    let mut certs = vec![p.inter.clone()];
    let mut issuer = Issuer::from_certificate(&p.inter, &p.inter_key).unwrap();
    for (i, k) in keys.iter().enumerate() {
        let c = issue(
            &Params::ca(&format!("Level {i}"), NOW - DAY, NOW + DAY),
            &k.public_spki(),
            Some(&issuer),
            &keys[i.saturating_sub(1)],
        )
        .unwrap();
        certs.push(c.clone());
        issuer = Issuer::from_certificate(&certs[certs.len() - 1], k).unwrap();
    }
    let leaf = issue(
        &Params::end_entity(
            "leaf",
            vec![SanEntry::Dns("www.example.com".into())],
            NOW - DAY,
            NOW + DAY,
        ),
        &p.leaf_key.public_spki(),
        Some(&issuer),
        &keys[7],
    )
    .unwrap();
    let mut chain = vec![leaf];
    chain.extend(certs.into_iter().rev());
    let r = verify_chain(&p.roots(), &chain, None, Usage::Server, NOW);
    assert_eq!(r.unwrap_err(), CertError::TooComplex);
}

#[test]
#[cfg_attr(not(unix), ignore = "needs operating system randomness (ADR-040)")]
fn an_issuer_without_key_cert_sign() {
    let p = pki_with(|i| i.ca_key_usage = Some(super::cert::key_usage::DIGITAL_SIGNATURE));
    assert_eq!(
        p.check(p.leaf(|_| {}), "www.example.com"),
        Err(CertError::KeyUsage)
    );
}

#[test]
fn parse_every_system_root() {
    let Ok(text) = std::fs::read_to_string("/etc/ssl/certs/ca-certificates.crt") else {
        return;
    };
    let mut store = RootStore::new();
    let (ok, bad) = store.add_pem(&text).unwrap();
    eprintln!("system roots: {ok} parsed, {bad} refused");
    assert!(ok > 50 && bad == 0);
}

#[test]
#[ignore]
fn dump_for_openssl() {
    let dir = std::env::var("QUANTY_DUMP").unwrap();
    let p = pki_with(|_| {});
    let leaf = p.leaf(|_| {});
    for (name, der) in [("root", &p.root), ("inter", &p.inter), ("leaf", &leaf)] {
        std::fs::write(
            format!("{dir}/{name}.pem"),
            super::pem::encode("CERTIFICATE", der),
        )
        .unwrap();
    }
}

#[test]
#[ignore]
fn verify_openssl_chain() {
    let dir = std::env::var("QUANTY_OPENSSL_CHAIN").unwrap();
    let read = |f: &str| std::fs::read_to_string(format!("{dir}/{f}")).unwrap();
    let mut roots = RootStore::new();
    assert_eq!(roots.add_pem(&read("ca.pem")).unwrap(), (1, 0));
    let leaf = super::pem::decode_all(&read("leaf.pem"), "CERTIFICATE")
        .unwrap()
        .remove(0);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let name = ServerName::parse("svc.example.test").unwrap();
    verify_chain(
        &roots,
        std::slice::from_ref(&leaf),
        Some(&name),
        Usage::Server,
        now,
    )
    .unwrap();
    let other = ServerName::parse("other.example.test").unwrap();
    assert_eq!(
        verify_chain(&roots, &[leaf], Some(&other), Usage::Server, now).unwrap_err(),
        CertError::NameMismatch
    );
    PrivateKey::from_pem(&read("leaf.key")).unwrap();
}

/// A certificate assembled by hand, to break rules the builder keeps.
fn raw_cert(exts: &[u8], outer_alg: Option<&[u8]>) -> Vec<u8> {
    raw_cert_serial(exts, outer_alg, &[1])
}

fn raw_cert_serial(exts: &[u8], outer_alg: Option<&[u8]>, serial: &[u8]) -> Vec<u8> {
    use super::der::{self, tag};
    let k = key(1);
    let (alg, _) = k.sign_x509(b"");
    let mut tbs = Vec::new();
    der::write(
        &mut tbs,
        tag::context_constructed(0),
        &der::wrap(tag::INTEGER, &[2]),
    );
    der::write(&mut tbs, tag::INTEGER, serial);
    tbs.extend_from_slice(&alg);
    tbs.extend_from_slice(&super::build::name("x"));
    let mut v = Vec::new();
    der::write(&mut v, tag::UTC_TIME, b"300101000000Z");
    der::write(&mut v, tag::UTC_TIME, b"310101000000Z");
    der::write(&mut tbs, tag::SEQUENCE, &v);
    tbs.extend_from_slice(&super::build::name("x"));
    tbs.extend_from_slice(&k.public_spki());
    der::write(
        &mut tbs,
        tag::context_constructed(3),
        &der::wrap(tag::SEQUENCE, exts),
    );
    let tbs = der::wrap(tag::SEQUENCE, &tbs);
    let (_, sig) = k.sign_x509(&tbs);
    let mut c = tbs;
    c.extend_from_slice(outer_alg.unwrap_or(&alg));
    let mut bits = vec![0];
    bits.extend_from_slice(&sig);
    der::write(&mut c, tag::BIT_STRING, &bits);
    der::wrap(tag::SEQUENCE, &c)
}

fn ext(id: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    use super::der::{self, tag};
    let mut e = der::wrap(tag::OID, id);
    if critical {
        der::write(&mut e, tag::BOOLEAN, &[0xff]);
    }
    der::write(&mut e, tag::OCTET_STRING, value);
    der::wrap(tag::SEQUENCE, &e)
}

#[test]
fn parser_refuses_what_rfc_5280_forbids() {
    use super::cert::oid;
    use super::der::{self, tag};
    let san = ext(
        oid::SUBJECT_ALT_NAME,
        false,
        &der::wrap(tag::SEQUENCE, &der::wrap(0x82, b"a.test")),
    );
    assert!(Certificate::parse(&raw_cert(&san, None)).is_ok());

    let twice = [san.clone(), san.clone()].concat();
    assert_eq!(
        Certificate::parse(&raw_cert(&twice, None)).unwrap_err().0,
        "duplicate extension"
    );

    let unknown = [0x2a, 0x03, 0x04];
    assert!(Certificate::parse(&raw_cert(&ext(&unknown, false, &[5, 0]), None)).is_ok());
    assert_eq!(
        Certificate::parse(&raw_cert(&ext(&unknown, true, &[5, 0]), None))
            .unwrap_err()
            .0,
        "unknown critical extension"
    );

    let mut other_alg = der::wrap(tag::OID, oid::ED25519);
    der::write(&mut other_alg, tag::NULL, &[]);
    let other_alg = der::wrap(tag::SEQUENCE, &other_alg);
    assert_eq!(
        Certificate::parse(&raw_cert(&san, Some(&other_alg)))
            .unwrap_err()
            .0,
        "signature algorithms disagree"
    );
}

#[test]
#[cfg_attr(not(unix), ignore = "needs operating system randomness (ADR-040)")]
fn wide_search_hits_the_signature_budget() {
    // Two levels of sixteen candidates each, all really signing the level
    // below and none leading anywhere: 16 times 16 signature checks, at
    // depth two. Only the budget stops this.
    let p = pki_with(|_| {});
    let mut chain = vec![p.leaf(|_| {})];
    let middle = Issuer {
        name: super::build::name("Middle"),
        key_id: vec![7; 20],
        key: &p.inter_key,
    };
    let nowhere = Issuer {
        name: super::build::name("Nowhere"),
        key_id: vec![8; 20],
        key: &p.inter_key,
    };
    for _ in 0..16 {
        chain.push(
            issue(
                &Params::ca("Intermediate", NOW - DAY, NOW + DAY),
                &p.inter_key.public_spki(),
                Some(&middle),
                &p.inter_key,
            )
            .unwrap(),
        );
        chain.push(
            issue(
                &Params::ca("Middle", NOW - DAY, NOW + DAY),
                &p.inter_key.public_spki(),
                Some(&nowhere),
                &p.inter_key,
            )
            .unwrap(),
        );
    }
    let r = verify_chain(&p.roots(), &chain, None, Usage::Server, NOW);
    assert_eq!(r.unwrap_err(), CertError::TooComplex);
}

#[test]
fn serial_numbers_must_be_positive_and_short() {
    use super::cert::oid;
    use super::der::{self, tag};
    let san = ext(
        oid::SUBJECT_ALT_NAME,
        false,
        &der::wrap(tag::SEQUENCE, &der::wrap(0x82, b"a.test")),
    );
    let check = |serial: &[u8]| {
        let c = raw_cert_serial(&san, None, serial);
        verify_chain(&RootStore::new(), &[c], None, Usage::Server, 1_900_000_000)
    };
    assert_eq!(
        check(&[0]).unwrap_err(),
        CertError::Malformed("serial number")
    );
    assert_eq!(
        check(&[0xff]).unwrap_err(),
        CertError::Malformed("serial number")
    );
    assert_eq!(
        check(&[0x7f; 21]).unwrap_err(),
        CertError::Malformed("serial number")
    );
    // Twenty octets, and twenty with a sign byte in front, are fine; the
    // chain then fails for want of a root, which is later.
    assert_eq!(check(&[0x7f; 20]).unwrap_err(), CertError::UnknownIssuer);
    let mut signed = vec![0];
    signed.extend_from_slice(&[0x80; 20]);
    assert_eq!(check(&signed).unwrap_err(), CertError::UnknownIssuer);
}
