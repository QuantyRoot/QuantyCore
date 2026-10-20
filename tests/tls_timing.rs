//! A statistical timing test in the style of dudect (Reparaz, Balasch and
//! Verbauwhede, "Dude, is my code constant time?", 2017).
//!
//! Each primitive runs on two classes of secret input, one fixed and one
//! random, in random order. If its running time depends on the secret,
//! the two distributions of measured times differ, and Welch's t-test
//! finds the difference once there are enough samples. dudect's
//! threshold is |t| > 4.5; a value that far out does not come from noise.
//!
//! Timing on a shared machine is noisy, and noise can only make |t|
//! larger when it hits one class more than the other, which random
//! interleaving prevents. A function is reported as leaking only if two
//! independent runs both cross the threshold.
//!
//! These take minutes and need a quiet machine, so they are ignored by
//! default and run in their own CI job with `--ignored`. The first test
//! is the counter check: a comparison that returns at the first
//! differing byte has to be caught, or the harness proves nothing.

use quantycore::tls::crypto::aead::Aead;
use quantycore::tls::crypto::aes::Aes;
use quantycore::tls::crypto::chacha20poly1305::ChaCha20Poly1305;
use quantycore::tls::crypto::ct;
use quantycore::tls::crypto::ed25519::SigningKey;
use quantycore::tls::crypto::gcm::AesGcm;
use quantycore::tls::crypto::rand;
use quantycore::tls::crypto::x25519;
use std::hint::black_box;
use std::time::Instant;

const THRESHOLD: f64 = 4.5;

/// The sample count, scaled by `QUANTY_TIMING_SCALE` for a closer look.
fn samples(n: usize) -> usize {
    let scale: usize = std::env::var("QUANTY_TIMING_SCALE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    n * scale
}

/// Welch's t statistic of two samples.
fn welch(a: &[f64], b: &[f64]) -> f64 {
    let mean = |x: &[f64]| x.iter().sum::<f64>() / x.len() as f64;
    let var =
        |x: &[f64], m: f64| x.iter().map(|v| (v - m).powi(2)).sum::<f64>() / (x.len() - 1) as f64;
    let (ma, mb) = (mean(a), mean(b));
    let (va, vb) = (var(a, ma), var(b, mb));
    (ma - mb) / (va / a.len() as f64 + vb / b.len() as f64).sqrt()
}

/// The largest |t| over the uncropped data and the data cropped at
/// several percentiles, as dudect does: cropping removes the long tail of
/// interrupts, which otherwise hides small differences.
fn max_t(fixed: &[f64], random: &[f64]) -> f64 {
    let mut all: Vec<f64> = fixed.iter().chain(random).copied().collect();
    all.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let mut best = welch(fixed, random).abs();
    for pct in [0.5, 0.75, 0.9, 0.95, 0.99] {
        let cut = all[((all.len() - 1) as f64 * pct) as usize];
        let f: Vec<f64> = fixed.iter().copied().filter(|&v| v <= cut).collect();
        let r: Vec<f64> = random.iter().copied().filter(|&v| v <= cut).collect();
        if f.len() > 100 && r.len() > 100 {
            best = best.max(welch(&f, &r).abs());
        }
    }
    best
}

/// Measures `run` on inputs made by `make(class)`, class 0 fixed and class
/// 1 random, `samples` times in random order, each sample timing `batch`
/// calls so that fast functions rise above the clock's resolution.
fn measure<I>(
    samples: usize,
    batch: usize,
    mut make: impl FnMut(bool) -> I,
    mut run: impl FnMut(&I),
) -> f64 {
    let mut coin = vec![0u8; samples];
    rand::fill(&mut coin).unwrap();
    let inputs: Vec<(bool, I)> = coin
        .iter()
        .map(|c| (c & 1 == 1, make(c & 1 == 1)))
        .collect();
    let (mut fixed, mut random) = (Vec::new(), Vec::new());
    for (class, input) in &inputs {
        let t = Instant::now();
        for _ in 0..batch {
            run(input);
        }
        let ns = t.elapsed().as_nanos() as f64;
        if *class {
            random.push(ns);
        } else {
            fixed.push(ns);
        }
    }
    max_t(&fixed, &random)
}

/// Runs a measurement twice and fails only if both cross the threshold.
fn check(name: &str, mut m: impl FnMut() -> f64) {
    let first = m();
    eprintln!("{name}: |t| = {first:.2}");
    if first > THRESHOLD {
        let second = m();
        eprintln!("{name}: |t| = {second:.2} (second run)");
        assert!(
            second <= THRESHOLD,
            "{name} leaks timing: |t| = {first:.1} and {second:.1}"
        );
    }
}

fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::fill(&mut b).unwrap();
    b
}

/// The comparison every C programmer writes first.
fn leaky_eq(a: &[u8], b: &[u8]) -> bool {
    for (x, y) in a.iter().zip(b) {
        if x != y {
            return false;
        }
    }
    a.len() == b.len()
}

#[test]
#[ignore]
fn counter_check_finds_an_early_exit() {
    // Class 0 equals the reference, class 1 differs in the first byte: the
    // early exit makes class 1 much faster.
    let reference = [0x42u8; 256];
    let t = measure(
        20_000,
        50,
        |r| {
            let mut v = reference;
            if r {
                v[0] ^= 1 | random::<1>()[0];
            }
            v
        },
        |v| {
            black_box(leaky_eq(black_box(&reference), black_box(v)));
        },
    );
    eprintln!("leaky comparison: |t| = {t:.2}");
    assert!(
        t > THRESHOLD,
        "the harness does not see an early exit, |t| = {t:.2}"
    );
}

#[test]
#[ignore]
fn ct_eq() {
    let reference = [0x42u8; 256];
    check("ct::eq", || {
        measure(
            20_000,
            50,
            |r| {
                let mut v = reference;
                if r {
                    v[0] ^= 1 | random::<1>()[0];
                }
                v
            },
            |v| {
                black_box(ct::eq(black_box(&reference), black_box(v)));
            },
        )
    });
}

#[test]
#[ignore]
fn aes_block() {
    let aes = Aes::new(&random::<16>());
    check("AES-128 block", || {
        measure(
            20_000,
            10,
            |r| if r { random::<64>() } else { [0u8; 64] },
            |b| {
                let mut x = *b;
                aes.encrypt4(black_box(&mut x));
                black_box(x);
            },
        )
    });
}

#[test]
#[ignore]
fn aes_key_schedule() {
    check("AES-256 key schedule", || {
        measure(
            10_000,
            2,
            |r| if r { random::<32>() } else { [0u8; 32] },
            |k| {
                black_box(Aes::new(black_box(k)));
            },
        )
    });
}

#[test]
#[ignore]
fn gcm_seal() {
    let gcm = AesGcm::new(&random::<16>());
    check("AES-GCM seal", || {
        measure(
            10_000,
            2,
            |r| if r { random::<256>() } else { [0u8; 256] },
            |p| {
                let mut buf = p.to_vec();
                gcm.seal(&[0; 12], b"", black_box(&mut buf));
                black_box(buf);
            },
        )
    });
}

#[test]
#[ignore]
fn chacha20_poly1305_open() {
    // Opening checks the tag over secret-keyed data; the class decides the
    // key.
    check("ChaCha20-Poly1305 key", || {
        measure(
            10_000,
            2,
            |r| {
                let key = if r { random::<32>() } else { [0u8; 32] };
                let a = ChaCha20Poly1305::new(&key);
                let mut buf = vec![0u8; 256];
                a.seal(&[0; 12], b"", &mut buf);
                (a, buf)
            },
            |(a, buf)| {
                let mut b = buf.clone();
                black_box(a.open(&[0; 12], b"", black_box(&mut b)).is_ok());
            },
        )
    });
}

#[test]
#[ignore]
fn x25519_scalar() {
    let u = x25519::BASE_POINT;
    check("X25519 scalar", || {
        measure(
            2_000,
            1,
            |r| if r { random::<32>() } else { [0u8; 32] },
            |k| {
                black_box(x25519::x25519(black_box(k), &u));
            },
        )
    });
}

#[test]
#[ignore]
fn ed25519_sign() {
    check("Ed25519 signing key", || {
        measure(
            samples(10_000),
            1,
            |r| SigningKey::from_seed(&if r { random::<32>() } else { [0u8; 32] }),
            |k| {
                black_box(k.sign(black_box(b"message")));
            },
        )
    });
}

#[test]
#[ignore]
fn p256_ecdh_scalar() {
    use quantycore::tls::crypto::ec::{Curve, SecretKey};
    let peer = SecretKey::generate(Curve::P256).unwrap().public_key();
    // The fixed class is the scalar 1, the smallest valid one.
    let mut one = [0u8; 32];
    one[31] = 1;
    check("P-256 ECDH scalar", || {
        measure(
            samples(2_000),
            1,
            |r| {
                SecretKey::from_bytes(
                    Curve::P256,
                    &if r {
                        SecretKey::generate(Curve::P256)
                            .unwrap()
                            .to_bytes()
                            .try_into()
                            .unwrap()
                    } else {
                        one
                    },
                )
                .unwrap()
            },
            |k| {
                black_box(k.diffie_hellman(black_box(&peer)));
            },
        )
    });
}

#[test]
#[ignore]
fn p384_ecdsa_sign() {
    use quantycore::tls::crypto::ec::{Curve, SecretKey};
    use quantycore::tls::crypto::sha2::HashAlg;
    let mut one = [0u8; 48];
    one[47] = 1;
    let h = HashAlg::Sha384.digest(b"message");
    check("P-384 ECDSA signing key", || {
        measure(
            samples(1_000),
            1,
            |r| {
                let d: [u8; 48] = if r {
                    SecretKey::generate(Curve::P384)
                        .unwrap()
                        .to_bytes()
                        .try_into()
                        .unwrap()
                } else {
                    one
                };
                SecretKey::from_bytes(Curve::P384, &d).unwrap()
            },
            |k| {
                black_box(k.sign_prehashed(black_box(&h), HashAlg::Sha384));
            },
        )
    });
}
