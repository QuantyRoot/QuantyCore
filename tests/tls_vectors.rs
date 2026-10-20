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
use quantycore::tls::crypto::ec::{self, Curve};
use quantycore::tls::crypto::ed25519;
use quantycore::tls::crypto::gcm::AesGcm;
use quantycore::tls::crypto::hkdf;
use quantycore::tls::crypto::hmac::hmac;
use quantycore::tls::crypto::sha2::HashAlg;
use quantycore::tls::crypto::x25519;
use quantycore::tls::x509::der::ecdsa_signature;
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

/// Twist points, non-canonical encodings of u and the edge cases of the
/// ladder all compute the RFC 7748 function; low order points must give
/// the all-zero secret, which the key agreement then refuses.
#[test]
fn wycheproof_x25519() {
    let Some(doc) = wycheproof("x25519_test.json") else {
        return;
    };
    let (mut n, mut zero) = (0, 0);
    for group in doc.list("testGroups") {
        for t in group.list("tests") {
            let at = t.num("tcId");
            let private: [u8; 32] = t.hex("private").try_into().unwrap();
            let public: [u8; 32] = t.hex("public").try_into().unwrap();
            let shared = t.hex("shared");
            assert_ne!(
                t.str("result"),
                "invalid",
                "tcId {at}: no invalid cases expected"
            );
            assert_eq!(
                x25519::x25519(&private, &public).to_vec(),
                shared,
                "tcId {at}"
            );
            let dh = x25519::PrivateKey::from_bytes(&private).diffie_hellman(&public);
            if shared == [0; 32] {
                assert!(dh.is_none(), "tcId {at}: zero secret accepted");
                zero += 1;
            } else {
                assert_eq!(dh.unwrap().expose(), &shared[..], "tcId {at}");
            }
            n += 1;
        }
    }
    eprintln!("X25519: {n} cases, {zero} with a zero secret");
    assert!(n >= 500 && zero >= 20, "Wycheproof X25519 incomplete");
}

/// Signatures with S at or above the group order, non-canonical point
/// encodings, and points of small order, next to valid ones.
#[test]
fn wycheproof_ed25519() {
    let Some(doc) = wycheproof("ed25519_test.json") else {
        return;
    };
    let (mut valid, mut invalid) = (0, 0);
    for group in doc.list("testGroups") {
        let pk: [u8; 32] = group
            .get("publicKey")
            .unwrap()
            .hex("pk")
            .try_into()
            .unwrap();
        for t in group.list("tests") {
            let ok = ed25519::verify(&pk, &t.hex("msg"), &t.hex("sig"));
            match t.str("result") {
                "valid" => {
                    assert!(ok, "tcId {} rejected", t.num("tcId"));
                    valid += 1;
                }
                "invalid" => {
                    assert!(!ok, "tcId {} accepted", t.num("tcId"));
                    invalid += 1;
                }
                r => panic!("result {r}"),
            }
        }
    }
    eprintln!("Ed25519: {valid} valid, {invalid} invalid");
    assert!(
        valid >= 80 && invalid >= 60,
        "Wycheproof Ed25519 incomplete"
    );
}

fn curve_of(name: &str) -> Option<Curve> {
    match name {
        "secp256r1" | "P-256" => Some(Curve::P256),
        "secp384r1" | "P-384" => Some(Curve::P384),
        _ => None,
    }
}

fn hash_of(name: &str) -> Option<HashAlg> {
    match name {
        "SHA-256" => Some(HashAlg::Sha256),
        "SHA-384" => Some(HashAlg::Sha384),
        "SHA-512" => Some(HashAlg::Sha512),
        _ => None,
    }
}

/// Points on the twist, at infinity, with coordinates at or above p, and
/// compressed points, which are refused here even where Wycheproof would
/// accept them because TLS 1.3 never sends them.
#[test]
fn wycheproof_ecdh() {
    for file in [
        "ecdh_secp256r1_ecpoint_test.json",
        "ecdh_secp384r1_ecpoint_test.json",
    ] {
        let Some(doc) = wycheproof(file) else {
            return;
        };
        let (mut valid, mut refused) = (0, 0);
        for group in doc.list("testGroups") {
            let curve = curve_of(group.str("curve")).unwrap();
            for t in group.list("tests") {
                let id = t.num("tcId");
                let d = t.hex("private");
                let d = &d[d.len().saturating_sub(curve.size())..];
                let mut padded = vec![0u8; curve.size() - d.len()];
                padded.extend_from_slice(d);
                let k = ec::SecretKey::from_bytes(curve, &padded).unwrap();
                let got = k.diffie_hellman(&t.hex("public"));
                match (t.str("result"), got) {
                    ("valid", Some(s)) => {
                        assert_eq!(s.expose(), &t.hex("shared")[..], "{file} {id}");
                        valid += 1;
                    }
                    ("valid", None) => panic!("{file} {id}: valid point refused"),
                    ("invalid", Some(_)) => panic!("{file} {id}: invalid point accepted"),
                    ("acceptable", Some(s)) => {
                        assert_eq!(s.expose(), &t.hex("shared")[..], "{file} {id}")
                    }
                    (_, None) => refused += 1,
                    (r, _) => panic!("result {r}"),
                }
            }
        }
        eprintln!("{file}: {valid} valid, {refused} refused");
        assert!(valid >= 300 && refused >= 15, "{file} incomplete");
    }
}

#[test]
fn wycheproof_ecdsa() {
    let files = [
        ("ecdsa_secp256r1_sha256_test.json", false),
        ("ecdsa_secp256r1_sha256_p1363_test.json", true),
        ("ecdsa_secp256r1_sha512_test.json", false),
        ("ecdsa_secp384r1_sha384_test.json", false),
        ("ecdsa_secp384r1_sha384_p1363_test.json", true),
        ("ecdsa_secp384r1_sha512_test.json", false),
        ("ecdsa_secp384r1_sha256_test.json", false),
    ];
    for (file, p1363) in files {
        let Some(doc) = wycheproof(file) else {
            return;
        };
        let (mut valid, mut invalid) = (0, 0);
        for group in doc.list("testGroups") {
            let key = group.get("publicKey").unwrap();
            let curve = curve_of(key.str("curve")).unwrap();
            let hash = hash_of(group.str("sha")).unwrap();
            let q = key.hex("uncompressed");
            for t in group.list("tests") {
                let sig = t.hex("sig");
                let h = hash.digest(&t.hex("msg"));
                let ok = if p1363 {
                    sig.len() == 2 * curve.size()
                        && ec::verify_prehashed(
                            curve,
                            &q,
                            &h,
                            &sig[..curve.size()],
                            &sig[curve.size()..],
                        )
                } else {
                    ecdsa_signature(&sig)
                        .is_some_and(|(r, s)| ec::verify_prehashed(curve, &q, &h, r, s))
                };
                let id = t.num("tcId");
                match t.str("result") {
                    "valid" => {
                        assert!(ok, "{file} {id} rejected");
                        valid += 1;
                    }
                    "invalid" => {
                        assert!(!ok, "{file} {id} accepted");
                        invalid += 1;
                    }
                    _ => {}
                }
            }
        }
        eprintln!("{file}: {valid} valid, {invalid} invalid");
        assert!(valid >= 1 && invalid >= 1, "{file} incomplete");
    }
}

/// NIST's SigVer file: per curve and hash, signatures that verify and
/// signatures broken in the message, the key, r or s.
#[test]
fn cavp_ecdsa_sigver() {
    let Some(root) = suite("QUANTY_CAVP") else {
        return;
    };
    let mut n = 0;
    for r in rsp(&root.join("ecdsa/186-4ecdsatestvectors/SigVer.rsp")) {
        let section = &r.params[0].0;
        let mut parts = section.split(',');
        let (Some(curve), Some(hash)) = (
            parts.next().and_then(curve_of),
            parts.next().and_then(hash_of),
        ) else {
            continue;
        };
        let Some(result) = r.get("Result") else {
            continue;
        };
        let mut q = vec![4u8];
        let pad = |v: Vec<u8>| {
            let mut out = vec![0u8; curve.size() - v.len()];
            out.extend(v);
            out
        };
        q.extend(pad(r.hex("Qx")));
        q.extend(pad(r.hex("Qy")));
        let h = hash.digest(&r.hex("Msg"));
        let ok = ec::verify_prehashed(curve, &q, &h, &r.hex("R"), &r.hex("S"));
        assert_eq!(
            ok,
            result.starts_with('P'),
            "{section} {:?}",
            r.get("Msg").map(|m| &m[..16])
        );
        n += 1;
    }
    eprintln!("CAVP ECDSA SigVer: {n} cases");
    assert!(n >= 90, "SigVer incomplete");
}

fn rsa_public(group: &Json) -> quantycore::tls::crypto::rsa::PublicKey {
    let k = group.get("publicKey").unwrap();
    quantycore::tls::crypto::rsa::PublicKey::new(&k.hex("modulus"), &k.hex("publicExponent"))
        .unwrap()
}

/// PKCS#1 v1.5 verification: signatures with wrong padding, wrong
/// DigestInfo, trailing data and other Bleichenbacher style forgeries.
#[test]
fn wycheproof_rsa_pkcs1_verify() {
    for bits in [2048, 3072, 4096] {
        for sha in ["sha256", "sha512"] {
            let file = format!("rsa_signature_{bits}_{sha}_test.json");
            let Some(doc) = wycheproof(&file) else {
                return;
            };
            let (mut valid, mut invalid) = (0, 0);
            for group in doc.list("testGroups") {
                let key = rsa_public(group);
                let hash = hash_of(group.str("sha")).unwrap();
                for t in group.list("tests") {
                    let ok = key.verify_pkcs1(hash, &t.hex("msg"), &t.hex("sig"));
                    match t.str("result") {
                        "valid" => {
                            assert!(ok, "{file} {} rejected", t.num("tcId"));
                            // The same value one byte longer is not a
                            // signature of the modulus's length (RFC 8017
                            // 8.2.2 step 1).
                            let mut longer = vec![0u8];
                            longer.extend(t.hex("sig"));
                            assert!(
                                !key.verify_pkcs1(hash, &t.hex("msg"), &longer),
                                "{file} {} longer",
                                t.num("tcId")
                            );
                            valid += 1;
                        }
                        "invalid" => {
                            assert!(!ok, "{file} {} accepted", t.num("tcId"));
                            invalid += 1;
                        }
                        _ => {}
                    }
                }
            }
            assert!(
                valid >= 1 && invalid >= 50,
                "{file}: {valid} valid, {invalid} invalid"
            );
        }
    }
}

#[test]
fn wycheproof_rsa_pss_verify() {
    let files = [
        "rsa_pss_2048_sha256_mgf1_32_test.json",
        "rsa_pss_3072_sha256_mgf1_32_test.json",
        "rsa_pss_4096_sha256_mgf1_32_test.json",
        "rsa_pss_4096_sha512_mgf1_64_test.json",
        "rsa_pss_2048_sha256_mgf1_0_test.json",
    ];
    for file in files {
        let Some(doc) = wycheproof(file) else {
            return;
        };
        let (mut valid, mut invalid) = (0, 0);
        for group in doc.list("testGroups") {
            let key = rsa_public(group);
            let hash = hash_of(group.str("sha")).unwrap();
            assert_eq!(group.str("mgfSha"), group.str("sha"));
            let salt = group.num("sLen") as usize;
            for t in group.list("tests") {
                let ok = key.verify_pss(hash, &t.hex("msg"), &t.hex("sig"), salt);
                match t.str("result") {
                    "valid" => {
                        assert!(ok, "{file} {} rejected", t.num("tcId"));
                        valid += 1;
                    }
                    "invalid" => {
                        assert!(!ok, "{file} {} accepted", t.num("tcId"));
                        invalid += 1;
                    }
                    _ => {}
                }
            }
        }
        assert!(
            valid >= 1 && invalid >= 10,
            "{file}: {valid} valid, {invalid} invalid"
        );
    }
}

/// PKCS#1 v1.5 signatures are deterministic, so signing with the suite's
/// private keys must give exactly its signatures.
#[test]
fn wycheproof_rsa_pkcs1_sign() {
    use quantycore::tls::x509::PrivateKey;
    let mut n = 0;
    for bits in [2048, 3072, 4096] {
        let file = format!("rsa_pkcs1_{bits}_sig_gen_test.json");
        let Some(doc) = wycheproof(&file) else {
            return;
        };
        for group in doc.list("testGroups") {
            let Some(hash) = hash_of(group.str("sha")) else {
                continue;
            };
            let Ok(PrivateKey::Rsa(key, _)) = PrivateKey::from_pkcs8(&group.hex("privateKeyPkcs8"))
            else {
                panic!("{file}: key does not load");
            };
            for t in group.list("tests") {
                if t.str("result") != "valid" {
                    continue;
                }
                let sig = key.sign_pkcs1(hash, &t.hex("msg")).unwrap();
                assert_eq!(sig, t.hex("sig"), "{file} {}", t.num("tcId"));
                n += 1;
            }
        }
    }
    eprintln!("RSA PKCS#1 signatures generated: {n}");
    assert!(n >= 20, "too few RSA signing cases");
}

#[test]
fn acvp_sha3() {
    use quantycore::tls::crypto::sha3::{sha3_256, sha3_512};
    type Digest = fn(&[u8]) -> Vec<u8>;
    let algs: [(&str, Digest); 2] = [
        ("SHA3-256-2.0", |m| sha3_256(m).to_vec()),
        ("SHA3-512-2.0", |m| sha3_512(m).to_vec()),
    ];
    for (name, f) in algs {
        let Some(doc) = acvp(name) else {
            return;
        };
        let (mut aft, mut mct) = (0, 0);
        for group in doc.list("testGroups") {
            for t in group.list("tests") {
                match group.str("testType") {
                    "AFT" => {
                        let len = t.num("len") as usize;
                        if !len.is_multiple_of(8) {
                            continue;
                        }
                        assert_eq!(
                            f(&t.hex("msg")[..len / 8]),
                            t.hex("md"),
                            "{name} {}",
                            t.num("tcId")
                        );
                        aft += 1;
                    }
                    // SHA-3's Monte Carlo test chains single digests, not
                    // three as SHA-2's does.
                    "MCT" => {
                        let mut md = t.hex("msg");
                        for (j, r) in t.list("resultsArray").iter().enumerate() {
                            for _ in 0..1000 {
                                md = f(&md);
                            }
                            assert_eq!(md, r.hex("md"), "{name} MCT round {j}");
                            mct += 1;
                        }
                    }
                    "LDT" => {}
                    other => panic!("unknown test type {other}"),
                }
            }
        }
        eprintln!("{name}: {aft} AFT, {mct} MCT rounds");
        assert!(aft >= 80 && mct == 100, "{name} incomplete");
    }
}

#[test]
fn acvp_shake() {
    use quantycore::tls::crypto::sha3::{shake128, shake256};
    type Xof = fn(&[u8], &mut [u8]);
    let algs: [(&str, Xof); 2] = [("SHAKE-128-1.0", shake128), ("SHAKE-256-1.0", shake256)];
    for (name, f) in algs {
        let Some(doc) = acvp(name) else {
            return;
        };
        let (mut aft, mut mct) = (0, 0);
        for group in doc.list("testGroups") {
            for t in group.list("tests") {
                match group.str("testType") {
                    "AFT" | "VOT" => {
                        let (len, out_len) = (t.num("len") as usize, t.num("outLen") as usize);
                        if !len.is_multiple_of(8) || !out_len.is_multiple_of(8) {
                            continue;
                        }
                        let mut out = vec![0u8; out_len / 8];
                        f(&t.hex("msg")[..len / 8], &mut out);
                        assert_eq!(out, t.hex("md"), "{name} {}", t.num("tcId"));
                        aft += 1;
                    }
                    // The output length of each step comes from the last
                    // 16 bits of the step before.
                    "MCT" => {
                        let min = group.num("minOutLen") as usize / 8;
                        let max = group.num("maxOutLen") as usize / 8;
                        let mut md = t.hex("msg");
                        let mut out_len = max;
                        for (j, r) in t.list("resultsArray").iter().enumerate() {
                            for _ in 0..1000 {
                                let mut m = md.clone();
                                m.resize(16, 0);
                                md = vec![0u8; out_len];
                                f(&m, &mut md);
                                let right = u16::from_be_bytes([md[md.len() - 2], md[md.len() - 1]])
                                    as usize;
                                out_len = min + right % (max - min + 1);
                            }
                            assert_eq!(md, r.hex("md"), "{name} MCT round {j}");
                            mct += 1;
                        }
                    }
                    "LDT" => {}
                    other => panic!("unknown test type {other}"),
                }
            }
        }
        eprintln!("{name}: {aft} AFT and VOT, {mct} MCT rounds");
        assert!(aft >= 200 && mct == 100, "{name} incomplete");
    }
}

#[test]
fn acvp_mlkem() {
    use quantycore::tls::crypto::mlkem::{encapsulate_with, DecapsulationKey};
    let Some(keygen) = acvp("ML-KEM-keyGen-FIPS203") else {
        return;
    };
    let mut n = 0;
    for group in keygen.list("testGroups") {
        if group.str("parameterSet") != "ML-KEM-768" {
            continue;
        }
        for t in group.list("tests") {
            let d: [u8; 32] = t.hex("d").try_into().unwrap();
            let z: [u8; 32] = t.hex("z").try_into().unwrap();
            let k = DecapsulationKey::from_seed(&d, &z);
            assert_eq!(
                k.encapsulation_key(),
                t.hex("ek"),
                "keyGen {}",
                t.num("tcId")
            );
            assert_eq!(k.to_bytes(), t.hex("dk"), "keyGen {}", t.num("tcId"));
            n += 1;
        }
    }
    let doc = acvp("ML-KEM-encapDecap-FIPS203").unwrap();
    for group in doc.list("testGroups") {
        if group.str("parameterSet") != "ML-KEM-768" {
            continue;
        }
        for t in group.list("tests") {
            let id = t.num("tcId");
            match group.str("function") {
                "encapsulation" => {
                    let m: [u8; 32] = t.hex("m").try_into().unwrap();
                    let (c, k) = encapsulate_with(&t.hex("ek"), &m).unwrap();
                    assert_eq!(c, t.hex("c"), "encapsulation {id}");
                    assert_eq!(k.expose(), t.hex("k"), "encapsulation {id}");
                }
                "decapsulation" => {
                    let dk = DecapsulationKey::from_bytes(&t.hex("dk")).unwrap();
                    let k = dk.decapsulate(&t.hex("c")).unwrap();
                    assert_eq!(k.expose(), t.hex("k"), "decapsulation {id}");
                }
                "encapsulationKeyCheck" => {
                    let ok = encapsulate_with(&t.hex("ek"), &[0; 32]).is_some();
                    assert_eq!(
                        ok,
                        t.get("testPassed").unwrap().as_bool().unwrap(),
                        "ek check {id}"
                    );
                }
                "decapsulationKeyCheck" => {
                    let ok = DecapsulationKey::from_bytes(&t.hex("dk")).is_some();
                    assert_eq!(
                        ok,
                        t.get("testPassed").unwrap().as_bool().unwrap(),
                        "dk check {id}"
                    );
                }
                f => panic!("function {f}"),
            }
            n += 1;
        }
    }
    eprintln!("ML-KEM-768: {n} ACVP cases");
    assert!(n >= 25 + 25 + 10 + 20, "ACVP ML-KEM-768 incomplete");
}

#[test]
fn wycheproof_mlkem() {
    use quantycore::tls::crypto::mlkem::{encapsulate_with, DecapsulationKey};
    let Some(doc) = wycheproof("mlkem_768_test.json") else {
        return;
    };
    let (mut valid, mut invalid) = (0, 0);
    for group in doc.list("testGroups") {
        for t in group.list("tests") {
            let id = t.num("tcId");
            let seed = t.hex("seed");
            let k = (seed.len() == 64).then(|| {
                DecapsulationKey::from_seed(
                    &seed[..32].try_into().unwrap(),
                    &seed[32..].try_into().unwrap(),
                )
            });
            let got = k.as_ref().and_then(|k| k.decapsulate(&t.hex("c")));
            match t.str("result") {
                "valid" => {
                    let k = k.unwrap();
                    assert_eq!(k.encapsulation_key(), t.hex("ek"), "tcId {id}");
                    assert_eq!(got.unwrap().expose(), t.hex("K"), "tcId {id}");
                    valid += 1;
                }
                "invalid" => {
                    assert!(got.is_none(), "tcId {id} accepted");
                    invalid += 1;
                }
                r => panic!("result {r}"),
            }
        }
    }
    let encaps = wycheproof("mlkem_768_encaps_test.json").unwrap();
    for group in encaps.list("testGroups") {
        for t in group.list("tests") {
            let id = t.num("tcId");
            let m: [u8; 32] = t.hex("m").try_into().unwrap();
            let got = encapsulate_with(&t.hex("ek"), &m);
            match t.str("result") {
                "valid" => {
                    let (c, k) = got.unwrap();
                    assert_eq!(
                        (c, k.expose().to_vec()),
                        (t.hex("c"), t.hex("K")),
                        "tcId {id}"
                    );
                    valid += 1;
                }
                "invalid" => {
                    assert!(got.is_none(), "encaps tcId {id} accepted");
                    invalid += 1;
                }
                r => panic!("result {r}"),
            }
        }
    }
    let decaps = wycheproof("mlkem_768_semi_expanded_decaps_test.json").unwrap();
    for group in decaps.list("testGroups") {
        for t in group.list("tests") {
            let id = t.num("tcId");
            let got =
                DecapsulationKey::from_bytes(&t.hex("dk")).and_then(|k| k.decapsulate(&t.hex("c")));
            match t.str("result") {
                "valid" => {
                    assert_eq!(got.unwrap().expose(), t.hex("K"), "decaps tcId {id}");
                    valid += 1;
                }
                "invalid" => {
                    assert!(got.is_none(), "decaps tcId {id} accepted");
                    invalid += 1;
                }
                r => panic!("result {r}"),
            }
        }
    }
    eprintln!("ML-KEM-768: {valid} valid, {invalid} invalid");
    assert!(
        valid >= 290 && invalid >= 170,
        "Wycheproof ML-KEM-768 incomplete"
    );
}
