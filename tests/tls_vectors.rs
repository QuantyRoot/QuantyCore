//! The primitives against the published vector suites, too large to keep
//! in the repository:
//!
//! - NIST ACVP (github.com/usnistgov/ACVP-Server, public domain), the
//!   validation vectors of the CMVP, under `gen-val/json-files`, located by
//!   `QUANTY_ACVP`.
//! - Project Wycheproof (github.com/C2SP/wycheproof, Apache 2.0), edge
//!   cases collected from real bugs, under `testvectors_v1`, located by
//!   `QUANTY_WYCHEPROOF`.
//!
//! CI checks both out at pinned commits. Every test counts what it ran and
//! fails on a count that is too low, so a renamed file cannot make it
//! pass on nothing.

mod tls_common;

use quantycore::tls::crypto::hkdf;
use quantycore::tls::crypto::hmac::hmac;
use quantycore::tls::crypto::sha2::HashAlg;
use tls_common::{load, suite, Json};

fn acvp(name: &str) -> Option<Json> {
    let root = suite("QUANTY_ACVP")?;
    Some(load(&root.join(name).join("internalProjection.json")))
}

fn wycheproof(name: &str) -> Option<Json> {
    let root = suite("QUANTY_WYCHEPROOF")?;
    Some(load(&root.join(name)))
}

fn sha(alg: HashAlg) -> &'static str {
    match alg {
        HashAlg::Sha256 => "256",
        HashAlg::Sha384 => "384",
        HashAlg::Sha512 => "512",
    }
}

const HASHES: [HashAlg; 3] = [HashAlg::Sha256, HashAlg::Sha384, HashAlg::Sha512];

/// AFT covers every message length from 0 to several blocks, which is
/// where padding bugs live. MCT chains 100,000 hashes so any single wrong
/// bit propagates.
#[test]
fn acvp_sha2_aft_and_mct() {
    for alg in HASHES {
        let Some(doc) = acvp(&format!("SHA2-{}-1.0", sha(alg))) else {
            return;
        };
        let (mut aft, mut mct) = (0, 0);
        for group in doc.list("testGroups") {
            for t in group.list("tests") {
                let id = t.num("tcId");
                match group.str("testType") {
                    "AFT" => {
                        let len = t.num("len") as usize;
                        // Some suites include messages that end inside a
                        // byte. Nothing here hashes bits, so those are not
                        // run.
                        if !len.is_multiple_of(8) {
                            continue;
                        }
                        let msg = &t.hex("msg")[..len / 8];
                        assert_eq!(alg.digest(msg), t.hex("md"), "{alg:?} AFT {id}");
                        aft += 1;
                    }
                    "MCT" => {
                        let seed_len = t.num("len") as usize / 8;
                        let alternate = match group.str("mctVersion") {
                            "standard" => false,
                            "alternate" => true,
                            v => panic!("MCT version {v}"),
                        };
                        let mut seed = t.hex("msg");
                        for (j, r) in t.list("resultsArray").iter().enumerate() {
                            let mut md = [seed.clone(), seed.clone(), seed.clone()];
                            for _ in 0..1000 {
                                let mut m = md.concat();
                                // The alternate method keeps every message
                                // at the seed's length, so the seed can be
                                // longer than one digest.
                                if alternate {
                                    m.resize(seed_len, 0);
                                }
                                let next = alg.digest(&m);
                                md = [md[1].clone(), md[2].clone(), next];
                            }
                            seed = md[2].clone();
                            assert_eq!(seed, r.hex("md"), "{alg:?} MCT round {j}");
                            mct += 1;
                        }
                    }
                    "LDT" => {}
                    other => panic!("unknown test type {other}"),
                }
            }
        }
        eprintln!("SHA-{}: {aft} AFT, {mct} MCT rounds", sha(alg));
        assert!(
            aft >= 120 && mct == 100,
            "SHA-{} suite incomplete",
            sha(alg)
        );
    }
}

/// Messages of 1 to 8 GiB, which is past 2^32 bits and so catches a
/// 32-bit length counter. Minutes of work, so only when asked for.
#[test]
fn acvp_sha2_large_messages() {
    if std::env::var_os("QUANTY_ACVP_LDT").is_none() {
        eprintln!("QUANTY_ACVP_LDT not set, large messages not hashed");
        return;
    }
    for alg in HASHES {
        let Some(doc) = acvp(&format!("SHA2-{}-1.0", sha(alg))) else {
            return;
        };
        let mut n = 0;
        for group in doc.list("testGroups") {
            if group.str("testType") != "LDT" {
                continue;
            }
            for t in group.list("tests") {
                let large = t.get("largeMsg").unwrap();
                assert_eq!(large.str("expansionTechnique"), "repeating");
                let unit = large.hex("content");
                assert_eq!(large.num("contentLength") as usize, unit.len() * 8);
                let total = large.num("fullLength") / 8;
                let block: Vec<u8> = unit.iter().copied().cycle().take(1 << 20).collect();
                let mut h = alg.new_hasher();
                let mut left = total;
                while left > 0 {
                    let k = left.min(block.len() as u64) as usize;
                    h.update(&block[..k]);
                    left -= k as u64;
                }
                assert_eq!(h.finish(), t.hex("md"), "{alg:?} LDT {}", t.num("tcId"));
                n += 1;
            }
        }
        assert!(n >= 4, "SHA-{} LDT incomplete", sha(alg));
    }
}

/// Keys from shorter than the hash to longer than the block, and tags
/// truncated as FIPS 198-1 allows.
#[test]
fn acvp_hmac() {
    for alg in HASHES {
        let Some(doc) = acvp(&format!("HMAC-SHA2-{}-2.0", sha(alg))) else {
            return;
        };
        let mut n = 0;
        let mut long_keys = 0;
        for group in doc.list("testGroups") {
            for t in group.list("tests") {
                let key = &t.hex("key")[..t.num("keyLen") as usize / 8];
                let msg = &t.hex("msg")[..t.num("msgLen") as usize / 8];
                let want = t.hex("mac");
                assert_eq!(want.len() * 8, t.num("macLen") as usize);
                let got = hmac(alg, key, msg);
                assert_eq!(&got[..want.len()], &want[..], "{alg:?} {}", t.num("tcId"));
                n += 1;
                long_keys += (key.len() > alg.block_len()) as usize;
            }
        }
        eprintln!(
            "HMAC-SHA-{}: {n} cases, {long_keys} keys over a block",
            sha(alg)
        );
        assert!(
            n >= 100 && long_keys > 0,
            "HMAC-SHA-{} incomplete",
            sha(alg)
        );
    }
}

/// Includes the empty salt and the 255 block limit, both as accepted
/// maxima and as rejected sizes one past it.
#[test]
fn wycheproof_hkdf() {
    for alg in HASHES {
        let Some(doc) = wycheproof(&format!("hkdf_sha{}_test.json", sha(alg))) else {
            return;
        };
        let (mut valid, mut invalid) = (0, 0);
        for group in doc.list("testGroups") {
            for t in group.list("tests") {
                let prk = hkdf::extract(alg, &t.hex("salt"), &t.hex("ikm"));
                let okm = hkdf::expand(alg, prk.expose(), &t.hex("info"), t.num("size") as usize);
                let id = t.num("tcId");
                match t.str("result") {
                    "valid" => {
                        assert_eq!(okm.expect("valid").expose(), t.hex("okm"), "{alg:?} {id}");
                        valid += 1;
                    }
                    "invalid" => {
                        assert!(okm.is_none(), "{alg:?} {id} should be refused");
                        invalid += 1;
                    }
                    r => panic!("result {r}"),
                }
            }
        }
        assert!(
            valid >= 50 && invalid >= 1,
            "Wycheproof HKDF-SHA-{}",
            sha(alg)
        );
    }
}
