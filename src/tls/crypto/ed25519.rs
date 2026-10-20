//! Ed25519 signatures (RFC 8032).
//!
//! Points are in extended coordinates on the twisted Edwards curve with
//! the complete addition law of Hisil, Wong, Carter and Dawson, so
//! doubling is addition with itself and no input is a special case.
//! Multiplication by a secret scalar adds in every step and keeps or
//! drops the sum with a conditional move; multiplication in verification
//! only ever sees public values. Scalars modulo the group order L are
//! reduced one bit at a time with a masked subtraction: slower than
//! the usual Barrett reduction, but short enough to check by reading.

use super::ct::{self, Secret};
use super::field25519::Fe;
use super::sha2::{Hash, Sha512};
use std::sync::OnceLock;

#[derive(Clone, Copy)]
struct Point {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

/// The curve constant d = -121665/121666.
fn d() -> &'static Fe {
    static D: OnceLock<Fe> = OnceLock::new();
    D.get_or_init(|| {
        Fe::ZERO
            .sub(&Fe::from_small(121665))
            .mul(&Fe::from_small(121666).invert())
    })
}

fn d2() -> &'static Fe {
    static D2: OnceLock<Fe> = OnceLock::new();
    D2.get_or_init(|| d().add(d()))
}

impl Point {
    const IDENTITY: Point = Point {
        x: Fe::ZERO,
        y: Fe::ONE,
        z: Fe::ONE,
        t: Fe::ZERO,
    };

    fn add(&self, o: &Point) -> Point {
        let a = self.y.sub(&self.x).mul(&o.y.sub(&o.x));
        let b = self.y.add(&self.x).mul(&o.y.add(&o.x));
        let c = self.t.mul(d2()).mul(&o.t);
        let dd = self.z.add(&self.z).mul(&o.z);
        let e = b.sub(&a);
        let f = dd.sub(&c);
        let g = dd.add(&c);
        let h = b.add(&a);
        Point {
            x: e.mul(&f),
            y: g.mul(&h),
            t: e.mul(&h),
            z: f.mul(&g),
        }
    }

    fn neg(&self) -> Point {
        Point {
            x: Fe::ZERO.sub(&self.x),
            y: self.y,
            z: self.z,
            t: Fe::ZERO.sub(&self.t),
        }
    }

    fn encode(&self) -> [u8; 32] {
        let zi = self.z.invert();
        let x = self.x.mul(&zi).to_bytes();
        let mut y = self.y.mul(&zi).to_bytes();
        y[31] |= (x[0] & 1) << 7;
        y
    }

    /// RFC 8032 5.1.3, refusing non-canonical y and the x = 0 point with
    /// the sign bit set.
    fn decode(b: &[u8; 32]) -> Option<Point> {
        let sign = b[31] >> 7;
        let mut yb = *b;
        yb[31] &= 0x7f;
        let y = Fe::from_bytes(&yb);
        if y.to_bytes() != yb {
            return None;
        }
        let yy = y.square();
        let u = yy.sub(&Fe::ONE);
        let v = d().mul(&yy).add(&Fe::ONE);
        let v3 = v.square().mul(&v);
        let v7 = v3.square().mul(&v);
        let mut x = u.mul(&v3).mul(&u.mul(&v7).pow_p58());
        let vxx = v.mul(&x.square());
        if vxx.to_bytes() == u.to_bytes() {
        } else if vxx.to_bytes() == Fe::ZERO.sub(&u).to_bytes() {
            x = x.mul(sqrt_m1());
        } else {
            return None;
        }
        let xb = x.to_bytes();
        if xb == [0; 32] && sign == 1 {
            return None;
        }
        if xb[0] & 1 != sign {
            x = Fe::ZERO.sub(&x);
        }
        Some(Point {
            x,
            y,
            z: Fe::ONE,
            t: x.mul(&y),
        })
    }

    fn cmove(&mut self, o: &Point, bit: u64) {
        for (a, b) in [
            (&mut self.x, &o.x),
            (&mut self.y, &o.y),
            (&mut self.z, &o.z),
            (&mut self.t, &o.t),
        ] {
            let mut tmp = *b;
            Fe::cswap(a, &mut tmp, bit);
        }
    }

    /// `[k]P` for a secret `k`, the same additions for every scalar.
    fn mul_ct(&self, k: &[u8; 32]) -> Point {
        let mut r = Point::IDENTITY;
        for i in (0..256).rev() {
            r = r.add(&r);
            let sum = r.add(self);
            r.cmove(&sum, ((k[i / 8] >> (i % 8)) & 1) as u64);
        }
        r
    }
}

/// 2^((p-1)/4), a square root of -1. (p-1)/4 is 2^253 - 5, which is
/// twice (p-5)/8 = 2^252 - 3, plus one.
fn sqrt_m1() -> &'static Fe {
    static S: OnceLock<Fe> = OnceLock::new();
    S.get_or_init(|| {
        let two = Fe::from_small(2);
        two.pow_p58().square().mul(&two)
    })
}

fn base() -> &'static Point {
    static B: OnceLock<Point> = OnceLock::new();
    B.get_or_init(|| {
        let mut enc = [0x66u8; 32];
        enc[0] = 0x58;
        Point::decode(&enc).expect("base point")
    })
}

/// L = 2^252 + 27742317777372353535851937790883648493, little endian.
const L: [u64; 4] = [
    0x5812631a5cf5d3ed,
    0x14def9dea2f79cd6,
    0x0000000000000000,
    0x1000000000000000,
];

/// `x mod L` for a little endian number of any length, one bit at a time:
/// `r = 2r + bit`, then subtract L if that did not borrow. `r` stays
/// below 2L < 2^254, so four limbs hold it.
fn reduce(x: &[u8]) -> [u64; 4] {
    let mut r = [0u64; 4];
    for i in (0..x.len() * 8).rev() {
        let bit = ((x[i / 8] >> (i % 8)) & 1) as u64;
        let mut carry = bit;
        for limb in r.iter_mut() {
            let next = *limb >> 63;
            *limb = (*limb << 1) | carry;
            carry = next;
        }
        let mut s = [0u64; 4];
        let mut borrow = 0u64;
        for j in 0..4 {
            let (d1, b1) = r[j].overflowing_sub(L[j]);
            let (d2, b2) = d1.overflowing_sub(borrow);
            s[j] = d2;
            borrow = (b1 | b2) as u64;
        }
        // Without black_box the optimizer sees that the mask is all ones
        // or zero and turns the selection into a branch on the borrow,
        // which the timing test caught: zero scalars reduced twice as
        // fast as random ones.
        let keep_s = std::hint::black_box(borrow).wrapping_sub(1);
        for j in 0..4 {
            r[j] = (r[j] & !keep_s) | (s[j] & keep_s);
        }
    }
    r
}

fn to_bytes(r: &[u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (o, l) in out.as_chunks_mut::<8>().0.iter_mut().zip(r) {
        *o = l.to_le_bytes();
    }
    out
}

/// `(a * b + c) mod L` for scalars already below 2^256.
fn mul_add(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
    let limbs = |x: &[u8; 32]| -> [u64; 4] {
        core::array::from_fn(|i| u64::from_le_bytes(x[8 * i..8 * i + 8].try_into().unwrap()))
    };
    let (a, b, c) = (limbs(a), limbs(b), limbs(c));
    let mut wide = [0u64; 9];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let t = wide[i + j] as u128 + a[i] as u128 * b[j] as u128 + carry;
            wide[i + j] = t as u64;
            carry = t >> 64;
        }
        wide[i + 4] = carry as u64;
    }
    let mut carry = 0u128;
    for i in 0..9 {
        let t = wide[i] as u128 + if i < 4 { c[i] as u128 } else { 0 } + carry;
        wide[i] = t as u64;
        carry = t >> 64;
    }
    let mut bytes = [0u8; 72];
    for (o, l) in bytes.as_chunks_mut::<8>().0.iter_mut().zip(wide) {
        *o = l.to_le_bytes();
    }
    let out = to_bytes(&reduce(&bytes));
    ct::wipe(&mut bytes);
    out
}

fn hash_mod_l(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha512::default();
    for p in parts {
        h.update(p);
    }
    let mut d = h.finish();
    let r = to_bytes(&reduce(&d));
    ct::wipe(&mut d);
    r
}

pub struct SigningKey {
    seed: Secret,
    scalar: Secret,
    prefix: Secret,
    public: [u8; 32],
}

impl SigningKey {
    /// From the 32-byte private key of RFC 8032.
    pub fn from_seed(seed: &[u8; 32]) -> SigningKey {
        let mut h = Sha512::digest(seed);
        let mut a = [0u8; 32];
        a.copy_from_slice(&h[..32]);
        a[0] &= 248;
        a[31] &= 127;
        a[31] |= 64;
        let public = base().mul_ct(&a).encode();
        let prefix = Secret::from(&h[32..]);
        // The clamped value is used as a multiplier for the base point as
        // it is; for S it is reduced modulo L.
        let scalar = Secret::new(to_bytes(&reduce(&a)).to_vec());
        ct::wipe(&mut a);
        ct::wipe(&mut h);
        SigningKey {
            seed: Secret::from(&seed[..]),
            scalar,
            prefix,
            public,
        }
    }

    pub fn generate() -> std::io::Result<SigningKey> {
        let mut seed = [0u8; 32];
        super::rand::fill(&mut seed)?;
        let k = SigningKey::from_seed(&seed);
        ct::wipe(&mut seed);
        Ok(k)
    }

    pub fn seed(&self) -> &[u8] {
        self.seed.expose()
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.public
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        let r = hash_mod_l(&[self.prefix.expose(), msg]);
        let big_r = base().mul_ct(&r).encode();
        let k = hash_mod_l(&[&big_r, &self.public, msg]);
        let s = mul_add(&k, self.scalar.expose().try_into().unwrap(), &r);
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&big_r);
        sig[32..].copy_from_slice(&s);
        sig
    }
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ed25519::SigningKey")
    }
}

/// RFC 8032 5.1.7 with the cofactorless equation `[S]B = R + [k]A`,
/// checked as `encode([S]B - [k]A) == R`. S must be below L, which rules
/// out the malleable second encoding of every signature.
pub fn verify(public: &[u8; 32], msg: &[u8], sig: &[u8]) -> bool {
    let Ok(sig) = <[u8; 64]>::try_from(sig) else {
        return false;
    };
    let Some(a) = Point::decode(public) else {
        return false;
    };
    let s: [u8; 32] = sig[32..].try_into().unwrap();
    if to_bytes(&reduce(&s)) != s {
        return false;
    }
    let k = hash_mod_l(&[&sig[..32], public, msg]);
    let check = base().mul_ct(&s).add(&a.mul_ct(&k).neg());
    check.encode()[..] == sig[..32]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.split_whitespace().collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // RFC 8032 7.1, tests 1, 2 and 3: empty, one byte and two byte
    // messages.
    #[test]
    fn rfc_8032() {
        let cases = [
            (
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155
                 5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
            (
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da
                 085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
            (
                "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                "af82",
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac
                 18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            ),
        ];
        for (seed, public, msg, sig) in cases {
            let k = SigningKey::from_seed(&hex(seed).try_into().unwrap());
            assert_eq!(k.public_key().to_vec(), hex(public));
            assert_eq!(k.sign(&hex(msg)).to_vec(), hex(sig));
            assert!(verify(&k.public_key(), &hex(msg), &hex(sig)));
            let mut bad = hex(sig);
            bad[0] ^= 1;
            assert!(!verify(&k.public_key(), &hex(msg), &bad));
        }
    }

    #[test]
    fn s_at_or_above_l_is_refused() {
        let k = SigningKey::from_seed(&[1; 32]);
        let sig = k.sign(b"m");
        // S + L is the same value modulo L and an accepted signature if
        // the range check is missing.
        let mut s = [0u64; 4];
        for (i, l) in s.iter_mut().enumerate() {
            *l = u64::from_le_bytes(sig[32 + 8 * i..40 + 8 * i].try_into().unwrap());
        }
        let mut carry = 0u128;
        for i in 0..4 {
            let t = s[i] as u128 + L[i] as u128 + carry;
            s[i] = t as u64;
            carry = t >> 64;
        }
        let mut forged = sig;
        forged[32..].copy_from_slice(&to_bytes(&s));
        assert!(verify(&k.public_key(), b"m", &sig));
        assert!(!verify(&k.public_key(), b"m", &forged));
    }
}
