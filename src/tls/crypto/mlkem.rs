//! ML-KEM-768 (FIPS 203), the post-quantum half of X25519MLKEM768.
//!
//! Coefficients are kept fully reduced in `[0, q)`. Every reduction is a
//! multiplication and a masked subtraction, never a division: a compiler
//! may turn `x / q` into a division instruction whose time depends on
//! `x`, which is how KyberSlash recovered keys from implementations that
//! divided secret values. The only branches on data are in the rejection
//! sampling of the public matrix.

use super::ct::{self, Secret};
use super::rand;
use super::sha3::{sha3_256, sha3_512, Keccak};

const N: usize = 256;
const Q: u32 = 3329;
const K: usize = 3;
const ETA1: usize = 2;
const ETA2: usize = 2;
const DU: usize = 10;
const DV: usize = 4;

pub const ENCAPSULATION_KEY_LEN: usize = 384 * K + 32;
pub const DECAPSULATION_KEY_LEN: usize = 768 * K + 96;
pub const CIPHERTEXT_LEN: usize = 32 * (DU * K + DV);
pub const SHARED_SECRET_LEN: usize = 32;

type Poly = [u16; N];

/// `a - q` if that is not negative, else `a`, for `a < 2q`.
fn csub(a: u32) -> u16 {
    let b = a.wrapping_sub(Q);
    let keep = 0u32.wrapping_sub(b >> 31);
    (b.wrapping_add(Q & keep)) as u16
}

/// `x mod q` by Barrett reduction, for any `x < 2^32`.
fn reduce(x: u32) -> u16 {
    let t = ((x as u64 * 1_290_167) >> 32) as u32;
    csub(x - t * Q)
}

fn add(a: u16, b: u16) -> u16 {
    csub(a as u32 + b as u32)
}

fn sub(a: u16, b: u16) -> u16 {
    csub(a as u32 + Q - b as u32)
}

fn mul(a: u16, b: u16) -> u16 {
    reduce(a as u32 * b as u32)
}

const fn pow17(mut e: u32) -> u16 {
    let mut r: u32 = 1;
    let mut b: u32 = 17;
    while e > 0 {
        if e & 1 == 1 {
            r = r * b % Q;
        }
        b = b * b % Q;
        e >>= 1;
    }
    r as u16
}

const fn bitrev7(i: u32) -> u32 {
    let mut r = 0;
    let mut k = 0;
    while k < 7 {
        r |= ((i >> k) & 1) << (6 - k);
        k += 1;
    }
    r
}

/// 17^BitRev7(i), the twiddle factors of the NTT.
const ZETAS: [u16; 128] = {
    let mut z = [0u16; 128];
    let mut i = 0;
    while i < 128 {
        z[i] = pow17(bitrev7(i as u32));
        i += 1;
    }
    z
};

/// 17^(2 BitRev7(i) + 1), for the products in the NTT domain.
const GAMMAS: [u16; 128] = {
    let mut g = [0u16; 128];
    let mut i = 0;
    while i < 128 {
        g[i] = pow17(2 * bitrev7(i as u32) + 1);
        i += 1;
    }
    g
};

/// Algorithm 9.
fn ntt(f: &mut Poly) {
    let mut i = 1;
    let mut len = 128;
    while len >= 2 {
        for start in (0..N).step_by(2 * len) {
            let zeta = ZETAS[i];
            i += 1;
            for j in start..start + len {
                let t = mul(zeta, f[j + len]);
                f[j + len] = sub(f[j], t);
                f[j] = add(f[j], t);
            }
        }
        len /= 2;
    }
}

/// Algorithm 10.
fn inv_ntt(f: &mut Poly) {
    let mut i = 127;
    let mut len = 2;
    while len <= 128 {
        for start in (0..N).step_by(2 * len) {
            let zeta = ZETAS[i];
            i -= 1;
            for j in start..start + len {
                let t = f[j];
                f[j] = add(t, f[j + len]);
                f[j + len] = mul(zeta, sub(f[j + len], t));
            }
        }
        len *= 2;
    }
    for c in f.iter_mut() {
        *c = mul(*c, 3303);
    }
}

/// Algorithms 11 and 12: `acc += f * g` in the NTT domain.
fn mul_acc(acc: &mut Poly, f: &Poly, g: &Poly) {
    for i in 0..128 {
        let (a0, a1, b0, b1) = (f[2 * i], f[2 * i + 1], g[2 * i], g[2 * i + 1]);
        let c0 = add(mul(a0, b0), mul(mul(a1, b1), GAMMAS[i]));
        let c1 = add(mul(a0, b1), mul(a1, b0));
        acc[2 * i] = add(acc[2 * i], c0);
        acc[2 * i + 1] = add(acc[2 * i + 1], c1);
    }
}

/// Algorithm 5 for `d` bits per coefficient.
fn encode(f: &Poly, d: usize, out: &mut Vec<u8>) {
    let mut acc: u32 = 0;
    let mut bits = 0;
    for &c in f {
        acc |= (c as u32) << bits;
        bits += d;
        while bits >= 8 {
            out.push(acc as u8);
            acc >>= 8;
            bits -= 8;
        }
    }
}

/// Algorithm 6 without the final reduction: the raw `d`-bit values.
fn decode_raw(b: &[u8], d: usize) -> Poly {
    debug_assert_eq!(b.len(), 32 * d);
    let mut f = [0u16; N];
    let mut acc: u32 = 0;
    let mut bits = 0;
    let mut it = b.iter();
    for c in f.iter_mut() {
        while bits < d {
            acc |= (*it.next().unwrap() as u32) << bits;
            bits += 8;
        }
        *c = (acc & ((1 << d) - 1)) as u16;
        acc >>= d;
        bits -= d;
    }
    f
}

/// ByteDecode_12, reducing each value mod q (at most one subtraction,
/// since the values are below 4096 < 2q).
fn decode12(b: &[u8]) -> Poly {
    let mut f = decode_raw(b, 12);
    for c in f.iter_mut() {
        *c = csub(*c as u32);
    }
    f
}

/// Compress_d: round(2^d x / q) mod 2^d, the division done as a
/// multiplication that is exact for every numerator below 2^23.
fn compress(f: &mut Poly, d: usize) {
    for c in f.iter_mut() {
        let n = ((*c as u64) << d) + (Q as u64 / 2);
        let quotient = (n * 2_580_335) >> 33;
        *c = (quotient & ((1 << d) - 1)) as u16;
    }
}

/// Decompress_d: round(q y / 2^d).
fn decompress(f: &mut Poly, d: usize) {
    for c in f.iter_mut() {
        *c = ((*c as u32 * Q + (1 << (d - 1))) >> d) as u16;
    }
}

/// Algorithm 7, on public input: rejection sampling may branch.
fn sample_ntt(rho: &[u8], j: u8, i: u8) -> Poly {
    let mut x = Keccak::shake128();
    x.update(rho);
    x.update(&[j, i]);
    let mut f = [0u16; N];
    let mut n = 0;
    let mut buf = [0u8; 168];
    while n < N {
        x.squeeze(&mut buf);
        for c in buf.chunks(3) {
            let d1 = c[0] as u16 | ((c[1] as u16 & 15) << 8);
            let d2 = (c[1] as u16 >> 4) | ((c[2] as u16) << 4);
            if (d1 as u32) < Q && n < N {
                f[n] = d1;
                n += 1;
            }
            if (d2 as u32) < Q && n < N {
                f[n] = d2;
                n += 1;
            }
        }
    }
    f
}

/// Algorithm 8 for eta = 2, from PRF output of 128 bytes.
fn cbd2(b: &[u8]) -> Poly {
    let mut f = [0u16; N];
    for (i, &byte) in b.iter().enumerate() {
        for h in 0..2 {
            let v = (byte >> (4 * h)) as u32;
            let x = (v & 1) + ((v >> 1) & 1);
            let y = ((v >> 2) & 1) + ((v >> 3) & 1);
            f[2 * i + h] = csub(x + Q - y);
        }
    }
    f
}

/// PRF_eta(s, b) and the noise polynomial sampled from it.
fn noise(sigma: &[u8], nonce: u8, eta: usize) -> Poly {
    debug_assert_eq!(eta, 2);
    let mut x = Keccak::shake256();
    x.update(sigma);
    x.update(&[nonce]);
    let mut b = [0u8; 64 * 2];
    x.squeeze(&mut b);
    let f = cbd2(&b);
    ct::wipe(&mut b);
    f
}

fn matrix(rho: &[u8]) -> [[Poly; K]; K] {
    let mut a = [[[0u16; N]; K]; K];
    for (i, row) in a.iter_mut().enumerate() {
        for (j, e) in row.iter_mut().enumerate() {
            *e = sample_ntt(rho, j as u8, i as u8);
        }
    }
    a
}

/// Algorithm 13: the K-PKE key pair from the seed `d`.
fn pke_keygen(d: &[u8; 32]) -> (Vec<u8>, Secret) {
    let mut seed = d.to_vec();
    seed.push(K as u8);
    let g = Secret::new(sha3_512(&seed).to_vec());
    ct::wipe(&mut seed);
    let (rho, sigma) = g.expose().split_at(32);
    let a = matrix(rho);
    let mut s = [[0u16; N]; K];
    let mut e = [[0u16; N]; K];
    for (i, p) in s.iter_mut().enumerate() {
        *p = noise(sigma, i as u8, ETA1);
        ntt(p);
    }
    for (i, p) in e.iter_mut().enumerate() {
        *p = noise(sigma, (K + i) as u8, ETA1);
        ntt(p);
    }
    let mut ek = Vec::with_capacity(ENCAPSULATION_KEY_LEN);
    for i in 0..K {
        let mut t = e[i];
        for j in 0..K {
            mul_acc(&mut t, &a[i][j], &s[j]);
        }
        encode(&t, 12, &mut ek);
    }
    ek.extend_from_slice(rho);
    let mut dk = Vec::with_capacity(384 * K);
    for p in &s {
        encode(p, 12, &mut dk);
    }
    wipe_polys(&mut s);
    wipe_polys(&mut e);
    (ek, Secret::new(dk))
}

fn wipe_polys(p: &mut [Poly]) {
    for f in p.iter_mut() {
        for c in f.iter_mut() {
            *c = 0;
        }
    }
    std::hint::black_box(p);
}

/// Algorithm 14. `ek` has passed the modulus check.
fn pke_encrypt(ek: &[u8], m: &[u8; 32], r: &[u8]) -> Vec<u8> {
    let (t_bytes, rho) = ek.split_at(384 * K);
    let a = matrix(rho);
    let mut y = [[0u16; N]; K];
    for (i, p) in y.iter_mut().enumerate() {
        *p = noise(r, i as u8, ETA1);
        ntt(p);
    }
    let mut c = Vec::with_capacity(CIPHERTEXT_LEN);
    for i in 0..K {
        let mut u = [0u16; N];
        for (row, yj) in a.iter().zip(&y) {
            mul_acc(&mut u, &row[i], yj);
        }
        inv_ntt(&mut u);
        let e1 = noise(r, (K + i) as u8, ETA2);
        for (x, e) in u.iter_mut().zip(e1) {
            *x = add(*x, e);
        }
        compress(&mut u, DU);
        encode(&u, DU, &mut c);
    }
    let mut v = [0u16; N];
    for (i, t) in t_bytes.chunks(384).enumerate() {
        mul_acc(&mut v, &decode12(t), &y[i]);
    }
    inv_ntt(&mut v);
    let e2 = noise(r, (2 * K) as u8, ETA2);
    let mut mu = decode_raw(m, 1);
    decompress(&mut mu, 1);
    for ((x, e), m) in v.iter_mut().zip(e2).zip(mu) {
        *x = add(add(*x, e), m);
    }
    compress(&mut v, DV);
    encode(&v, DV, &mut c);
    wipe_polys(&mut y);
    c
}

/// Algorithm 15.
fn pke_decrypt(dk: &[u8], c: &[u8]) -> [u8; 32] {
    let (c1, c2) = c.split_at(32 * DU * K);
    let mut acc = [0u16; N];
    for (cu, s) in c1.chunks(32 * DU).zip(dk.chunks(384)) {
        let mut u = decode_raw(cu, DU);
        decompress(&mut u, DU);
        ntt(&mut u);
        let mut s = decode12(s);
        mul_acc(&mut acc, &s, &u);
        wipe_polys(std::slice::from_mut(&mut s));
    }
    inv_ntt(&mut acc);
    let mut w = decode_raw(c2, DV);
    decompress(&mut w, DV);
    for (x, a) in w.iter_mut().zip(acc) {
        *x = sub(*x, a);
    }
    compress(&mut w, 1);
    let mut m = Vec::with_capacity(32);
    encode(&w, 1, &mut m);
    wipe_polys(std::slice::from_mut(&mut w));
    wipe_polys(std::slice::from_mut(&mut acc));
    let out: [u8; 32] = m[..].try_into().unwrap();
    ct::wipe(&mut m);
    out
}

/// The modulus check of FIPS 203 7.2: every coefficient of the key is
/// below q, so that decoding and encoding it again gives the same bytes.
fn ek_is_valid(ek: &[u8]) -> bool {
    ek.len() == ENCAPSULATION_KEY_LEN
        && ek[..384 * K]
            .chunks(384)
            .all(|p| decode_raw(p, 12).iter().all(|&c| (c as u32) < Q))
}

/// A decapsulation key: dk_pke, ek, H(ek) and z, as FIPS 203 lays it out.
pub struct DecapsulationKey {
    dk: Secret,
}

impl DecapsulationKey {
    pub fn generate() -> std::io::Result<DecapsulationKey> {
        let mut seed = [0u8; 64];
        rand::fill(&mut seed)?;
        let d: [u8; 32] = seed[..32].try_into().unwrap();
        let z: [u8; 32] = seed[32..].try_into().unwrap();
        ct::wipe(&mut seed);
        Ok(DecapsulationKey::from_seed(&d, &z))
    }

    /// Algorithm 16, ML-KEM.KeyGen_internal.
    pub fn from_seed(d: &[u8; 32], z: &[u8; 32]) -> DecapsulationKey {
        let (ek, dk_pke) = pke_keygen(d);
        let mut dk = dk_pke.expose().to_vec();
        dk.extend_from_slice(&ek);
        dk.extend_from_slice(&sha3_256(&ek));
        dk.extend_from_slice(z);
        DecapsulationKey {
            dk: Secret::new(dk),
        }
    }

    /// A key in the FIPS 203 encoding, after the hash check of 7.3.
    pub fn from_bytes(dk: &[u8]) -> Option<DecapsulationKey> {
        if dk.len() != DECAPSULATION_KEY_LEN {
            return None;
        }
        let ek = &dk[384 * K..768 * K + 32];
        if !ct::eq(&sha3_256(ek), &dk[768 * K + 32..768 * K + 64]) || !ek_is_valid(ek) {
            return None;
        }
        Some(DecapsulationKey {
            dk: Secret::new(dk.to_vec()),
        })
    }

    pub fn to_bytes(&self) -> &[u8] {
        self.dk.expose()
    }

    pub fn encapsulation_key(&self) -> &[u8] {
        &self.dk.expose()[384 * K..768 * K + 32]
    }

    /// Algorithm 18, ML-KEM.Decaps_internal. A ciphertext that does not
    /// re-encrypt to itself gives the implicit rejection key J(z || c),
    /// chosen without a branch.
    pub fn decapsulate(&self, c: &[u8]) -> Option<Secret> {
        if c.len() != CIPHERTEXT_LEN {
            return None;
        }
        let dk = self.dk.expose();
        let (dk_pke, rest) = dk.split_at(384 * K);
        let (ek, rest) = rest.split_at(384 * K + 32);
        let (h, z) = rest.split_at(32);
        let mut m = pke_decrypt(dk_pke, c);
        let mut gin = m.to_vec();
        gin.extend_from_slice(h);
        let g = Secret::new(sha3_512(&gin).to_vec());
        ct::wipe(&mut gin);
        let (k, r) = g.expose().split_at(32);
        let mut j = Keccak::shake256();
        j.update(z);
        j.update(c);
        let mut reject = [0u8; 32];
        j.squeeze(&mut reject);
        let c2 = pke_encrypt(ek, &m, r);
        ct::wipe(&mut m);
        let diff = c2.iter().zip(c).fold(0u8, |acc, (x, y)| acc | (x ^ y));
        let same = ct::eq_mask_u8(std::hint::black_box(diff), 0);
        let mut out = reject.to_vec();
        ct::select_into(same, &mut out, k);
        ct::wipe(&mut reject);
        Some(Secret::new(out))
    }
}

/// Algorithm 17 with the randomness `m` given, ML-KEM.Encaps_internal.
/// For tests against fixed vectors; `encapsulate` draws `m`.
pub fn encapsulate_with(ek: &[u8], m: &[u8; 32]) -> Option<(Vec<u8>, Secret)> {
    if !ek_is_valid(ek) {
        return None;
    }
    let mut gin = m.to_vec();
    gin.extend_from_slice(&sha3_256(ek));
    let g = Secret::new(sha3_512(&gin).to_vec());
    ct::wipe(&mut gin);
    let (k, r) = g.expose().split_at(32);
    let c = pke_encrypt(ek, m, r);
    Some((c, Secret::new(k.to_vec())))
}

/// Encapsulates a fresh shared secret to `ek`. None for a key that fails
/// the modulus check.
pub fn encapsulate(ek: &[u8]) -> std::io::Result<Option<(Vec<u8>, Secret)>> {
    let mut m = [0u8; 32];
    rand::fill(&mut m)?;
    let r = encapsulate_with(ek, &m);
    ct::wipe(&mut m);
    Ok(r)
}

impl std::fmt::Debug for DecapsulationKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("DecapsulationKey(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reductions_are_exact() {
        for x in (0..4 * Q * Q).chain([u32::MAX - 1, u32::MAX]) {
            assert_eq!(reduce(x) as u32, x % Q, "{x}");
        }
        for a in 0..2 * Q {
            assert_eq!(csub(a) as u32, a % Q);
        }
        for d in [1, 4, 10, 11] {
            for x in 0..Q as u16 {
                let mut f = [x; N];
                compress(&mut f, d);
                let exact = ((((x as u64) << d) as f64 / Q as f64).round() as u64) % (1 << d);
                assert_eq!(f[0] as u64, exact, "d {d} x {x}");
            }
        }
    }

    #[test]
    fn ntt_round_trip_and_product() {
        let mut f = [0u16; N];
        for (i, c) in f.iter_mut().enumerate() {
            *c = (i as u16 * 37 + 5) % Q as u16;
        }
        let orig = f;
        ntt(&mut f);
        inv_ntt(&mut f);
        assert_eq!(f, orig);

        // x times x^255 is x^256 = -1 in Z_q[X]/(X^256 + 1).
        let (mut a, mut b) = ([0u16; N], [0u16; N]);
        a[1] = 1;
        b[255] = 1;
        ntt(&mut a);
        ntt(&mut b);
        let mut p = [0u16; N];
        mul_acc(&mut p, &a, &b);
        inv_ntt(&mut p);
        let mut want = [0u16; N];
        want[0] = Q as u16 - 1;
        assert_eq!(p, want);
    }

    #[test]
    fn round_trip_and_implicit_rejection() {
        let k = DecapsulationKey::from_seed(&[1; 32], &[2; 32]);
        let (c, s) = encapsulate_with(k.encapsulation_key(), &[3; 32]).unwrap();
        assert_eq!(c.len(), CIPHERTEXT_LEN);
        assert_eq!(k.decapsulate(&c).unwrap().expose(), s.expose());
        let mut bad = c.clone();
        bad[100] ^= 1;
        let r = k.decapsulate(&bad).unwrap();
        assert_ne!(r.expose(), s.expose());
        let mut j = [0u8; 32];
        let mut x = Keccak::shake256();
        x.update(&[2; 32]);
        x.update(&bad);
        x.squeeze(&mut j);
        assert_eq!(r.expose(), j);
        assert!(DecapsulationKey::from_bytes(k.to_bytes()).is_some());
    }
}
