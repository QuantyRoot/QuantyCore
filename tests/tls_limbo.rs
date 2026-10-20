//! Path validation against x509-limbo (github.com/C2SP/x509-limbo,
//! Apache 2.0): thousands of chains from RFC 5280, webpki, the BetterTLS
//! name constraint suite and known CVEs, each with the expected verdict.
//! CI checks the suite out at a pinned commit and points `QUANTY_LIMBO`
//! at its `limbo.json`.
//!
//! A chain this crate accepts that limbo says must fail is a security bug
//! and fails the test. A chain it refuses that limbo accepts is counted:
//! some are algorithms not built yet, the rest must be listed in
//! `REFUSED_ON_PURPOSE` with the reason.

mod tls_common;

use quantycore::tls::x509::{pem, verify_chain, CertError, RootStore, ServerName, Usage};
use tls_common::{load, Json};

/// Cases where this crate is stricter than limbo expects, deliberately.
/// Matched by prefix.
const REFUSED_ON_PURPOSE: &[(&str, &str)] = &[
    (
        "rfc5280::ca-as-leaf",
        "a CA certificate is never accepted as the end entity (ADR-024)",
    ),
    (
        "pathlen::validation-ignores-pathlen-in-leaf",
        "the leaf here is a CA certificate, refused as above",
    ),
    (
        "rfc5280::nc::nc-permits-email-",
        "email name constraints are not evaluated and fail closed (ADR-024)",
    ),
    (
        "webpki::nc::permitted-dns-match-noncritical",
        "RFC 5280 requires NameConstraints to be critical; limbo's rfc5280 twin of this case expects the refusal",
    ),
];

/// Cases where this crate accepts what limbo refuses, deliberately, all
/// of them rules for what a CA may issue rather than for what a
/// validator must check. Matched by prefix.
const ACCEPTED_ON_PURPOSE: &[(&str, &str)] = &[
    (
        "webpki::cn::",
        "the common name is never used as a host name, so its agreement with the SAN does not matter",
    ),
    (
        "rfc5280::aki::leaf-missing-aki",
        "issuers are found by name and checked by signature; the key identifier is only a hint",
    ),
    ("rfc5280::aki::intermediate-missing-aki", "as above"),
    ("rfc5280::aki::cross-signed-root-missing-aki", "as above"),
    ("rfc5280::ski::", "as above, for the subject key identifier"),
    (
        "webpki::aki::root-with-aki-",
        "a trust anchor is a subject and a key; its own extensions are not evaluated",
    ),
    (
        "rfc5280::root-missing-basic-constraints",
        "as above; older roots in system stores are v1 without extensions",
    ),
    ("rfc5280::root-non-critical-basic-constraints", "as above"),
    (
        "webpki::san::san-critical-with-nonempty-subject",
        "RFC 5280 says SHOULD be non-critical, not MUST",
    ),
    (
        "webpki::san::public-suffix-",
        "wildcards over public suffixes need the public suffix list, which is not built",
    ),
    (
        "webpki::malformed-aia",
        "the AIA extension is not used, so its contents are not parsed",
    ),
];

fn time(s: &str) -> i64 {
    // RFC 3339 with an explicit zero offset, as limbo writes it.
    let n = |r: std::ops::Range<usize>| s[r].parse::<i64>().unwrap();
    let (y, m, d) = (n(0..4), n(5..7), n(8..10));
    let (hh, mm, ss) = (n(11..13), n(14..16), n(17..19));
    assert!(
        s.ends_with("+00:00") || s.ends_with('Z'),
        "time zone in {s}"
    );
    let y2 = if m <= 2 { y - 1 } else { y };
    let era = y2.div_euclid(400);
    let yoe = y2 - era * 400;
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
    let days = era * 146097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719468;
    days * 86400 + hh * 3600 + mm * 60 + ss
}

/// The certificates under `key`, which is one PEM string or a list of
/// them.
fn pems(j: &Json, key: &str) -> Vec<Vec<u8>> {
    let texts: Vec<&[u8]> = match j.get(key) {
        Some(Json::String(s)) => vec![s],
        Some(Json::Array(a)) => a.iter().map(|p| p.as_bytes().unwrap()).collect(),
        _ => Vec::new(),
    };
    texts
        .into_iter()
        .flat_map(|p| pem::decode_all(std::str::from_utf8(p).unwrap(), "CERTIFICATE").unwrap())
        .collect()
}

#[test]
fn limbo() {
    let Some(path) = std::env::var_os("QUANTY_LIMBO") else {
        if std::env::var_os("QUANTY_VECTORS_REQUIRED").is_some() {
            panic!("QUANTY_LIMBO not set but QUANTY_VECTORS_REQUIRED is");
        }
        eprintln!("QUANTY_LIMBO not set, limbo not run");
        return;
    };
    let doc = load(std::path::Path::new(&path));
    let (mut agree, mut skipped, mut unsupported) = (0, 0, 0);
    let mut false_accepts = Vec::new();
    let mut false_rejects = Vec::new();
    for t in doc.list("testcases") {
        let id = t.str("id");
        let features: Vec<&str> = t
            .get("features")
            .and_then(Json::as_array)
            .unwrap_or(&[])
            .iter()
            .map(|f| std::str::from_utf8(f.as_bytes().unwrap()).unwrap())
            .collect();
        // CRLs and ML-DSA are not built; limbo's verdicts for those depend
        // on them.
        // max_chain_depth is a setting of the validator under test that
        // this API does not have; its limit is fixed (ADR-024). Pedantic
        // cases are CA/Browser Forum issuance rules that limbo itself
        // marks as optional for validators.
        if features.iter().any(|f| {
            matches!(*f, "has-crl" | "has-mldsa" | "max-chain-depth") || f.starts_with("pedantic-")
        }) {
            skipped += 1;
            continue;
        }
        let usage = match t.str("validation_kind") {
            "SERVER" => Usage::Server,
            _ => Usage::Client,
        };
        let name = match t.get("expected_peer_name") {
            Some(n @ Json::Object(_)) => match n.str("kind") {
                "DNS" | "IP" => match ServerName::parse(n.str("value")) {
                    Some(s) => Some(s),
                    None => {
                        // A reference name that is not a valid host name
                        // cannot be asked for in the first place.
                        if t.str("expected_result") == "SUCCESS" {
                            false_rejects.push((id.to_string(), CertError::NameMismatch));
                        } else {
                            agree += 1;
                        }
                        continue;
                    }
                },
                _ => {
                    skipped += 1;
                    continue;
                }
            },
            _ => None,
        };
        let mut roots = RootStore::new();
        for der in pems(t, "trusted_certs") {
            let _ = roots.add_der(&der);
        }
        let mut chain = pems(t, "peer_certificate");
        chain.extend(pems(t, "untrusted_intermediates"));
        let now = match t.get("validation_time") {
            Some(Json::String(s)) => time(std::str::from_utf8(s).unwrap()),
            _ => 1_700_000_000,
        };
        let r = verify_chain(&roots, &chain, name.as_ref(), usage, now);
        let expected = t.str("expected_result") == "SUCCESS";
        match (r, expected) {
            (Err(CertError::UnsupportedAlgorithm), _) => unsupported += 1,
            (Ok(_), true) | (Err(_), false) => agree += 1,
            (Ok(_), false) => {
                if !ACCEPTED_ON_PURPOSE.iter().any(|(p, _)| id.starts_with(p)) {
                    false_accepts.push(id.to_string());
                }
            }
            (Err(e), true) => {
                if !REFUSED_ON_PURPOSE.iter().any(|(p, _)| id.starts_with(p)) {
                    false_rejects.push((id.to_string(), e));
                }
            }
        }
    }
    eprintln!(
        "limbo: {agree} agree, {} accepted wrongly, {} refused wrongly, {unsupported} unsupported algorithm, {skipped} skipped",
        false_accepts.len(),
        false_rejects.len()
    );
    for (id, e) in &false_rejects {
        eprintln!("  refused: {id}: {e:?}");
    }
    for id in &false_accepts {
        eprintln!("  ACCEPTED: {id}");
    }
    assert!(
        false_accepts.is_empty(),
        "{} chains accepted that must fail",
        false_accepts.len()
    );
    assert!(
        false_rejects.is_empty(),
        "{} chains refused that should pass",
        false_rejects.len()
    );
    assert!(agree > 1000, "limbo incomplete");
}
