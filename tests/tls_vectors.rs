//! The primitives against the published vector suites, too large to keep
//! in the repository:
//!
//! - NIST ACVP (github.com/usnistgov/ACVP-Server, public domain), the
//!   validation vectors of the CMVP, under `gen-val/json-files`, located by
//!   `QUANTY_ACVP`.
//! - NIST CAVP (csrc.nist.gov, public domain), the older response files,
//!   for algorithms where they cover more lengths than ACVP; the zip
//!   files are pinned by SHA-256. Located by `QUANTY_CAVP`.
//! - Project Wycheproof (github.com/C2SP/wycheproof, Apache 2.0), edge
//!   cases collected from real bugs, under `testvectors_v1`, located by
//!   `QUANTY_WYCHEPROOF`.
//!
//! CI checks both out at pinned commits. Every test counts what it ran and
//! fails on a count that is too low, so a renamed file cannot make it
//! pass on nothing.

mod tls_common;

use quantycore::tls::crypto::aead::{Aead, AeadError};
use quantycore::tls::crypto::chacha20poly1305::ChaCha20Poly1305;
use quantycore::tls::crypto::gcm::AesGcm;
use quantycore::tls::crypto::hkdf;
use quantycore::tls::crypto::hmac::hmac;
use quantycore::tls::crypto::sha2::HashAlg;
use tls_common::{load, rsp, suite, Json};

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

/// Checks one AEAD case both ways: sealing gives exactly the expected
/// ciphertext and tag, and opening gives the plaintext back. For a case
/// that must be rejected, opening fails and leaves the input untouched.
fn aead_case<A: Aead>(
    a: &A,
    nonce: &[u8],
    aad: &[u8],
    plain: &[u8],
    sealed: &[u8],
    valid: bool,
    at: &str,
) {
    let nonce: &[u8; 12] = nonce.try_into().unwrap();
    if valid {
        let mut buf = plain.to_vec();
        a.seal(nonce, aad, &mut buf);
        assert_eq!(buf, sealed, "seal {at}");
    }
    let mut buf = sealed.to_vec();
    let r = a.open(nonce, aad, &mut buf);
    if valid {
        assert_eq!(r, Ok(()), "open {at}");
        assert_eq!(buf, plain, "open {at}");
    } else {
        assert_eq!(r, Err(AeadError), "open {at} should fail");
        assert_eq!(buf, sealed, "failed open changed the buffer, {at}");
    }
}

/// Every plaintext and AAD length CAVP generates, which is where the
/// partial block and counter handling of GCM go wrong, and the decryption
/// files' cases with a corrupted tag.
#[test]
fn cavp_aes_gcm() {
    let Some(root) = suite("QUANTY_CAVP") else {
        return;
    };
    for bits in [128, 256] {
        let (mut enc, mut dec, mut fail) = (0, 0, 0);
        for (file, decrypt) in [
            (format!("gcmEncryptExtIV{bits}.rsp"), false),
            (format!("gcmDecrypt{bits}.rsp"), true),
        ] {
            for r in rsp(&root.join("gcm").join(&file)) {
                if r.param("IVlen") != "96" || r.param("Taglen") != "128" {
                    continue;
                }
                let at = format!("{file} Count {}", r.get("Count").unwrap());
                let gcm = AesGcm::new(&r.hex("Key"));
                let mut sealed = r.hex("CT");
                sealed.extend(r.hex("Tag"));
                let valid = !r.has_flag("FAIL");
                let plain = if valid { r.hex("PT") } else { Vec::new() };
                aead_case(
                    &gcm,
                    &r.hex("IV"),
                    &r.hex("AAD"),
                    &plain,
                    &sealed,
                    valid,
                    &at,
                );
                match (decrypt, valid) {
                    (false, _) => enc += 1,
                    (true, true) => dec += 1,
                    (true, false) => fail += 1,
                }
            }
        }
        eprintln!("AES-{bits}-GCM: {enc} encrypt, {dec} decrypt, {fail} forged");
        assert!(
            enc >= 350 && dec >= 150 && fail >= 150,
            "CAVP AES-{bits}-GCM"
        );
    }
}

fn wycheproof_aead<A: Aead>(file: &str, key_sizes: &[u64]) {
    let Some(doc) = wycheproof(file) else {
        return;
    };
    let (mut valid, mut invalid) = (0, 0);
    for group in doc.list("testGroups") {
        // TLS nonces are always 96 bits, and AES-192 is not built.
        if group.num("ivSize") != 96 || !key_sizes.contains(&group.num("keySize")) {
            continue;
        }
        assert_eq!(group.num("tagSize"), 128);
        for t in group.list("tests") {
            let a = A::new(&t.hex("key"));
            let mut sealed = t.hex("ct");
            sealed.extend(t.hex("tag"));
            let ok = match t.str("result") {
                "valid" => true,
                "invalid" => false,
                r => panic!("result {r}"),
            };
            let at = format!("{file} tcId {}", t.num("tcId"));
            aead_case(
                &a,
                &t.hex("iv"),
                &t.hex("aad"),
                &t.hex("msg"),
                &sealed,
                ok,
                &at,
            );
            if ok {
                valid += 1;
            } else {
                invalid += 1;
            }
        }
    }
    eprintln!("{file}: {valid} valid, {invalid} invalid");
    assert!(valid >= 30 && invalid >= 30, "{file} incomplete");
}

#[test]
fn wycheproof_aes_gcm() {
    wycheproof_aead::<AesGcm>("aes_gcm_test.json", &[128, 256]);
}

#[test]
fn wycheproof_chacha20_poly1305() {
    wycheproof_aead::<ChaCha20Poly1305>("chacha20_poly1305_test.json", &[256]);
}
