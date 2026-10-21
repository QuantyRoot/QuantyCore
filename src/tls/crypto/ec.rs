//! The NIST curves P-256 and P-384: ECDH and ECDSA.
//!
//! Field and scalar arithmetic is Montgomery multiplication over a fixed
//! number of 64-bit limbs, with the final subtraction done by a masked
//! selection. Points are projective, added with the complete formulas of
//! Renes, Costello and Batina ("Complete addition formulas for prime
//! order elliptic curves", 2016, algorithm 4 for a = -3), which have no
//! exceptional cases, so doubling is addition with itself and the point
//! at infinity needs no special handling. Scalar multiplication doubles
//! and adds in every step and keeps the sum with a conditional move.

// Limb arithmetic walks several arrays by the same index; written with
// iterators it no longer reads like the algorithms it implements.
#![allow(clippy::needless_range_loop)]

use super::ct;
use super::hmac::Hmac;
use super::sha2::HashAlg;
use std::hint::black_box;
use std::sync::OnceLock;

/// Up to six limbs: P-384.
const MAX: usize = 6;
type Limbs = [u64; MAX];

/// Arithmetic modulo an odd prime of `n` limbs, values in Montgomery form.
struct Mont {
    n: usize,
    p: Limbs,
    p_inv: u64,
    r2: Limbs,
    one: Limbs,
}

impl Mont {
    fn new(p: &[u64]) -> Mont {
        let n = p.len();
        let mut pl = [0u64; MAX];
        pl[..n].copy_from_slice(p);
        // -p^-1 mod 2^64 by Newton's iteration, each step doubling the
        // correct low bits.
        let mut inv = 1u64;
        for _ in 0..6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(pl[0].wrapping_mul(inv)));
        }
        let mut m = Mont {
            n,
            p: pl,
            p_inv: inv.wrapping_neg(),
            r2: [0; MAX],
            one: [0; MAX],
        };
        // R^2 mod p, from 1 by 2 * 64n doublings modulo p.
        let mut x = [0u64; MAX];
        x[0] = 1;
        for _ in 0..2 * 64 * n {
            x = m.add(&x, &x);
        }
        m.r2 = x;
        let mut one = [0u64; MAX];
        one[0] = 1;
        m.one = m.to_mont(&one);
        m
    }

    /// `t - p` if `t >= p` (or the carry `hi` is set), else `t`.
    fn reduce_once(&self, t: &Limbs, hi: u64) -> Limbs {
        let mut d = [0u64; MAX];
        let mut borrow = 0u64;
        for i in 0..self.n {
            let (a, b1) = t[i].overflowing_sub(self.p[i]);
            let (a, b2) = a.overflowing_sub(borrow);
            d[i] = a;
            borrow = (b1 | b2) as u64;
        }
        let take_d = black_box(hi | (borrow ^ 1)).wrapping_neg();
        let mut out = [0u64; MAX];
        for i in 0..self.n {
            out[i] = (t[i] & !take_d) | (d[i] & take_d);
        }
        out
    }

    fn add(&self, a: &Limbs, b: &Limbs) -> Limbs {
        let mut s = [0u64; MAX];
        let mut carry = 0u64;
        for i in 0..self.n {
            let (x, c1) = a[i].overflowing_add(b[i]);
            let (x, c2) = x.overflowing_add(carry);
            s[i] = x;
            carry = (c1 | c2) as u64;
        }
        self.reduce_once(&s, carry)
    }

    fn sub(&self, a: &Limbs, b: &Limbs) -> Limbs {
        let mut d = [0u64; MAX];
        let mut borrow = 0u64;
        for i in 0..self.n {
            let (x, b1) = a[i].overflowing_sub(b[i]);
            let (x, b2) = x.overflowing_sub(borrow);
            d[i] = x;
            borrow = (b1 | b2) as u64;
        }
        let mask = black_box(borrow).wrapping_neg();
        let mut carry = 0u64;
        for i in 0..self.n {
            let (x, c1) = d[i].overflowing_add(self.p[i] & mask);
            let (x, c2) = x.overflowing_add(carry);
            d[i] = x;
            carry = (c1 | c2) as u64;
        }
        d
    }

    /// Montgomery multiplication, CIOS form: `a * b / R mod p`.
    fn mul(&self, a: &Limbs, b: &Limbs) -> Limbs {
        let n = self.n;
        let mut t = [0u64; MAX + 2];
        for i in 0..n {
            let mut c = 0u64;
            for j in 0..n {
                let s = t[j] as u128 + a[j] as u128 * b[i] as u128 + c as u128;
                t[j] = s as u64;
                c = (s >> 64) as u64;
            }
            let s = t[n] as u128 + c as u128;
            t[n] = s as u64;
            t[n + 1] = (s >> 64) as u64;
            let m = t[0].wrapping_mul(self.p_inv);
            let s = t[0] as u128 + m as u128 * self.p[0] as u128;
            let mut c = (s >> 64) as u64;
            for j in 1..n {
                let s = t[j] as u128 + m as u128 * self.p[j] as u128 + c as u128;
                t[j - 1] = s as u64;
                c = (s >> 64) as u64;
            }
            let s = t[n] as u128 + c as u128;
            t[n - 1] = s as u64;
            t[n] = t[n + 1] + (s >> 64) as u64;
        }
        let mut lo = [0u64; MAX];
        lo[..n].copy_from_slice(&t[..n]);
        self.reduce_once(&lo, t[n])
    }

    fn to_mont(&self, a: &Limbs) -> Limbs {
        self.mul(a, &self.r2)
    }

    fn out_of_mont(&self, a: &Limbs) -> Limbs {
        let mut one = [0u64; MAX];
        one[0] = 1;
        self.mul(a, &one)
    }

    /// `a^(p-2)`, the inverse for nonzero `a`, by square and multiply
    /// over the bits of the public exponent.
    fn invert(&self, a: &Limbs) -> Limbs {
        let mut e = self.p;
        e[0] -= 2;
        let mut r = self.one;
        for i in (0..64 * self.n).rev() {
            r = self.mul(&r, &r);
            if (e[i / 64] >> (i % 64)) & 1 == 1 {
                r = self.mul(&r, a);
            }
        }
        r
    }

    /// Big endian bytes to limbs, `None` unless the value is below p.
    fn parse_be(&self, b: &[u8]) -> Option<Limbs> {
        let x = be_to_limbs(b, self.n)?;
        lt(&x, &self.p, self.n).then_some(x)
    }

    fn to_be(&self, a: &Limbs) -> Vec<u8> {
        limbs_to_be(a, self.n)
    }

    fn is_zero(&self, a: &Limbs) -> bool {
        a[..self.n].iter().fold(0u64, |acc, &x| acc | x) == 0
    }
}

fn be_to_limbs(b: &[u8], n: usize) -> Option<Limbs> {
    if b.len() != 8 * n {
        return None;
    }
    let mut x = [0u64; MAX];
    for i in 0..n {
        let off = 8 * (n - 1 - i);
        x[i] = u64::from_be_bytes(b[off..off + 8].try_into().unwrap());
    }
    Some(x)
}

fn limbs_to_be(a: &Limbs, n: usize) -> Vec<u8> {
    let mut out = vec![0u8; 8 * n];
    for i in 0..n {
        let off = 8 * (n - 1 - i);
        out[off..off + 8].copy_from_slice(&a[i].to_be_bytes());
    }
    out
}

/// `a < b` on public values.
fn lt(a: &Limbs, b: &Limbs, n: usize) -> bool {
    for i in (0..n).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Curve {
    P256,
    P384,
}

struct Params {
    field: Mont,
    scalar: Mont,
    b: Limbs,
    gx: Limbs,
    gy: Limbs,
    hash: HashAlg,
}

fn params(c: Curve) -> &'static Params {
    static P256: OnceLock<Params> = OnceLock::new();
    static P384: OnceLock<Params> = OnceLock::new();
    let hexl = |s: &str| -> Vec<u64> {
        let b: Vec<u8> = (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect();
        let n = b.len() / 8;
        be_to_limbs(&b, n).unwrap()[..n].to_vec()
    };
    let make = |p: &str, n: &str, b: &str, gx: &str, gy: &str, hash| {
        let field = Mont::new(&hexl(p));
        let scalar = Mont::new(&hexl(n));
        let to = |s: &str| {
            let mut x = [0u64; MAX];
            let v = hexl(s);
            x[..v.len()].copy_from_slice(&v);
            field.to_mont(&x)
        };
        let (b, gx, gy) = (to(b), to(gx), to(gy));
        Params {
            field,
            scalar,
            b,
            gx,
            gy,
            hash,
        }
    };
    match c {
        Curve::P256 => P256.get_or_init(|| {
            make(
                "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
                "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
                "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
                "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
                "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
                HashAlg::Sha256,
            )
        }),
        Curve::P384 => P384.get_or_init(|| {
            make(
                "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
                "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973",
                "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
                "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
                "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
                HashAlg::Sha384,
            )
        }),
    }
}

impl Curve {
    /// Bytes of a field element or scalar.
    pub fn size(self) -> usize {
        8 * params(self).field.n
    }

    pub fn hash(self) -> HashAlg {
        params(self).hash
    }
}

#[derive(Clone, Copy)]
struct Point {
    x: Limbs,
    y: Limbs,
    z: Limbs,
}

impl Point {
    fn identity(f: &Mont) -> Point {
        Point {
            x: [0; MAX],
            y: f.one,
            z: [0; MAX],
        }
    }

    fn cmove(&mut self, o: &Point, bit: u64) {
        let m = black_box(bit).wrapping_neg();
        for (a, b) in [
            (&mut self.x, &o.x),
            (&mut self.y, &o.y),
            (&mut self.z, &o.z),
        ] {
            for i in 0..MAX {
                a[i] ^= m & (a[i] ^ b[i]);
            }
        }
    }
}

/// Complete addition for a = -3 (Renes, Costello, Batina, algorithm 4).
fn add(c: &Params, p: &Point, q: &Point) -> Point {
    let f = &c.field;
    let (x1, y1, z1, x2, y2, z2) = (&p.x, &p.y, &p.z, &q.x, &q.y, &q.z);
    let mut t0 = f.mul(x1, x2);
    let mut t1 = f.mul(y1, y2);
    let mut t2 = f.mul(z1, z2);
    let mut t3 = f.add(x1, y1);
    let mut t4 = f.add(x2, y2);
    t3 = f.mul(&t3, &t4);
    t4 = f.add(&t0, &t1);
    t3 = f.sub(&t3, &t4);
    t4 = f.add(y1, z1);
    let mut x3 = f.add(y2, z2);
    t4 = f.mul(&t4, &x3);
    x3 = f.add(&t1, &t2);
    t4 = f.sub(&t4, &x3);
    x3 = f.add(x1, z1);
    let mut y3 = f.add(x2, z2);
    x3 = f.mul(&x3, &y3);
    y3 = f.add(&t0, &t2);
    y3 = f.sub(&x3, &y3);
    let mut z3 = f.mul(&c.b, &t2);
    x3 = f.sub(&y3, &z3);
    z3 = f.add(&x3, &x3);
    x3 = f.add(&x3, &z3);
    z3 = f.sub(&t1, &x3);
    x3 = f.add(&t1, &x3);
    y3 = f.mul(&c.b, &y3);
    t1 = f.add(&t2, &t2);
    t2 = f.add(&t1, &t2);
    y3 = f.sub(&y3, &t2);
    y3 = f.sub(&y3, &t0);
    t1 = f.add(&y3, &y3);
    y3 = f.add(&t1, &y3);
    t1 = f.add(&t0, &t0);
    t0 = f.add(&t1, &t0);
    t0 = f.sub(&t0, &t2);
    t1 = f.mul(&t4, &y3);
    t2 = f.mul(&t0, &y3);
    y3 = f.mul(&x3, &z3);
    y3 = f.add(&y3, &t2);
    x3 = f.mul(&t3, &x3);
    x3 = f.sub(&x3, &t1);
    z3 = f.mul(&t4, &z3);
    t1 = f.mul(&t3, &t0);
    z3 = f.add(&z3, &t1);
    Point {
        x: x3,
        y: y3,
        z: z3,
    }
}

/// `[k]P` with `k` as big endian bytes of the curve's size, the same
/// operations for every `k`.
fn mul(c: &Params, p: &Point, k: &[u8]) -> Point {
    let mut r = Point::identity(&c.field);
    for byte in k {
        for i in (0..8).rev() {
            r = add(c, &r, &r);
            let s = add(c, &r, p);
            r.cmove(&s, ((byte >> i) & 1) as u64);
        }
    }
    r
}

fn generator(c: &Params) -> Point {
    Point {
        x: c.gx,
        y: c.gy,
        z: c.field.one,
    }
}

/// Affine x and y as bytes, `None` for the point at infinity.
fn to_affine(c: &Params, p: &Point) -> Option<(Vec<u8>, Vec<u8>)> {
    let f = &c.field;
    if f.is_zero(&p.z) {
        return None;
    }
    let zi = f.invert(&p.z);
    let x = f.out_of_mont(&f.mul(&p.x, &zi));
    let y = f.out_of_mont(&f.mul(&p.y, &zi));
    Some((f.to_be(&x), f.to_be(&y)))
}

/// An uncompressed point `04 || x || y`, checked to be on the curve.
/// Compressed points are not accepted: TLS 1.3 sends only uncompressed
/// ones (RFC 8446 4.2.8.2).
fn decode_point(c: &Params, b: &[u8]) -> Option<Point> {
    let f = &c.field;
    let n = 8 * f.n;
    if b.len() != 1 + 2 * n || b[0] != 4 {
        return None;
    }
    let x = f.to_mont(&f.parse_be(&b[1..1 + n])?);
    let y = f.to_mont(&f.parse_be(&b[1 + n..])?);
    // y^2 = x^3 - 3x + b
    let rhs = {
        let x3 = f.mul(&f.mul(&x, &x), &x);
        let three_x = f.add(&f.add(&x, &x), &x);
        f.add(&f.sub(&x3, &three_x), &c.b)
    };
    if f.out_of_mont(&f.mul(&y, &y)) != f.out_of_mont(&rhs) {
        return None;
    }
    Some(Point { x, y, z: f.one })
}

fn encode_point(c: &Params, p: &Point) -> Option<Vec<u8>> {
    let (x, y) = to_affine(c, p)?;
    let mut out = vec![4u8];
    out.extend_from_slice(&x);
    out.extend_from_slice(&y);
    Some(out)
}

/// A scalar from big endian bytes: nonzero and below the group order.
fn scalar_ok(c: &Params, k: &[u8]) -> bool {
    match c.scalar.parse_be(k) {
        Some(x) => !c.scalar.is_zero(&x),
        None => false,
    }
}

/// An EC private key: a scalar in [1, n-1].
pub struct SecretKey {
    curve: Curve,
    d: ct::Secret,
}

impl SecretKey {
    pub fn from_bytes(curve: Curve, d: &[u8]) -> Option<SecretKey> {
        scalar_ok(params(curve), d).then(|| SecretKey {
            curve,
            d: ct::Secret::from(d),
        })
    }

    /// Rejection sampling: draws until the bytes are a valid scalar,
    /// which for both curves fails with probability below 2^-32.
    pub fn generate(curve: Curve) -> std::io::Result<SecretKey> {
        loop {
            let mut d = ct::Secret::zeroed(curve.size());
            super::rand::fill(d.expose_mut())?;
            if let Some(k) = SecretKey::from_bytes(curve, d.expose()) {
                return Ok(k);
            }
        }
    }

    pub fn curve(&self) -> Curve {
        self.curve
    }

    pub fn to_bytes(&self) -> &[u8] {
        self.d.expose()
    }

    /// The uncompressed public point.
    pub fn public_key(&self) -> Vec<u8> {
        let c = params(self.curve);
        encode_point(c, &mul(c, &generator(c), self.d.expose())).expect("d is in [1, n-1]")
    }

    /// ECDH: the x coordinate of `d * peer`. `None` if the peer's point
    /// is not on the curve.
    pub fn diffie_hellman(&self, peer: &[u8]) -> Option<ct::Secret> {
        let c = params(self.curve);
        let q = decode_point(c, peer)?;
        let (x, _) = to_affine(c, &mul(c, &q, self.d.expose()))?;
        Some(ct::Secret::new(x))
    }

    /// ECDSA over `hash` (already computed), with the nonce derived as in
    /// RFC 6979. Returns (r, s) as big endian bytes of the curve's size.
    pub fn sign_prehashed(&self, hash: &[u8], hash_alg: HashAlg) -> (Vec<u8>, Vec<u8>) {
        let c = params(self.curve);
        let sc = &c.scalar;
        let e = sc.to_mont(&bits_to_scalar(c, hash));
        let d = sc.to_mont(&be_to_limbs(self.d.expose(), sc.n).unwrap());
        let mut nonces = Rfc6979::new(
            self.d.expose(),
            &limbs_to_be(&sc.out_of_mont(&e), sc.n),
            hash_alg,
            self.curve,
        );
        loop {
            let k = nonces.next();
            if !scalar_ok(c, k.expose()) {
                continue;
            }
            let Some((rx, _)) = to_affine(c, &mul(c, &generator(c), k.expose())) else {
                continue;
            };
            let r = reduce_x(c, &rx);
            if sc.is_zero(&r) {
                continue;
            }
            let kk = sc.to_mont(&be_to_limbs(k.expose(), sc.n).unwrap());
            let ki = sc.invert(&kk);
            let rm = sc.to_mont(&r);
            let s = sc.out_of_mont(&sc.mul(&ki, &sc.add(&e, &sc.mul(&rm, &d))));
            if sc.is_zero(&s) {
                continue;
            }
            return (sc.to_be(&r), sc.to_be(&s));
        }
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ec::SecretKey({:?})", self.curve)
    }
}

/// The x coordinate of a point reduced modulo n. x < p, and p < 2n for
/// both curves, so one conditional subtraction suffices.
fn reduce_x(c: &Params, x: &[u8]) -> Limbs {
    let v = be_to_limbs(x, c.scalar.n).unwrap();
    c.scalar.reduce_once(&v, 0)
}

/// The leftmost bits of a hash as a scalar modulo n (FIPS 186-5 6.4.1).
fn bits_to_scalar(c: &Params, hash: &[u8]) -> Limbs {
    let size = 8 * c.scalar.n;
    let mut b = vec![0u8; size];
    if hash.len() >= size {
        b.copy_from_slice(&hash[..size]);
    } else {
        b[size - hash.len()..].copy_from_slice(hash);
    }
    let v = be_to_limbs(&b, c.scalar.n).unwrap();
    c.scalar.reduce_once(&v, 0)
}

/// The deterministic nonce generator of RFC 6979 3.2, an HMAC-DRBG keyed
/// with the private key and the message hash.
struct Rfc6979 {
    alg: HashAlg,
    k: Vec<u8>,
    v: Vec<u8>,
    size: usize,
}

impl Rfc6979 {
    fn new(x: &[u8], h: &[u8], alg: HashAlg, curve: Curve) -> Rfc6979 {
        let hl = alg.output_len();
        let mut s = Rfc6979 {
            alg,
            k: vec![0; hl],
            v: vec![1; hl],
            size: curve.size(),
        };
        for byte in [0u8, 1] {
            let mut m = Hmac::new(alg, &s.k);
            m.update(&s.v);
            m.update(&[byte]);
            m.update(x);
            m.update(h);
            s.k = m.finish();
            s.v = super::hmac::hmac(alg, &s.k, &s.v);
        }
        s
    }

    fn next(&mut self) -> ct::Secret {
        let mut t = Vec::new();
        while t.len() < self.size {
            self.v = super::hmac::hmac(self.alg, &self.k, &self.v);
            t.extend_from_slice(&self.v);
        }
        t.truncate(self.size);
        // Prepared for the next attempt in case this one is rejected.
        let mut m = Hmac::new(self.alg, &self.k);
        m.update(&self.v);
        m.update(&[0]);
        self.k = m.finish();
        self.v = super::hmac::hmac(self.alg, &self.k, &self.v);
        ct::Secret::new(t)
    }
}

impl Drop for Rfc6979 {
    fn drop(&mut self) {
        ct::wipe(&mut self.k);
        ct::wipe(&mut self.v);
    }
}

/// ECDSA verification of (r, s) over `hash` with the uncompressed point
/// `public`. Every input is public, but the same constant time
/// multiplication is used as for signing; there is one code path.
pub fn verify_prehashed(curve: Curve, public: &[u8], hash: &[u8], r: &[u8], s: &[u8]) -> bool {
    let c = params(curve);
    let sc = &c.scalar;
    let Some(q) = decode_point(c, public) else {
        return false;
    };
    let size = curve.size();
    let pad = |v: &[u8]| -> Option<Vec<u8>> {
        let v = &v[v.iter().take_while(|&&b| b == 0).count()..];
        (v.len() <= size).then(|| {
            let mut out = vec![0u8; size - v.len()];
            out.extend_from_slice(v);
            out
        })
    };
    let (Some(r), Some(s)) = (pad(r), pad(s)) else {
        return false;
    };
    if !scalar_ok(c, &r) || !scalar_ok(c, &s) {
        return false;
    }
    let e = sc.to_mont(&bits_to_scalar(c, hash));
    let rm = sc.to_mont(&be_to_limbs(&r, sc.n).unwrap());
    let si = sc.invert(&sc.to_mont(&be_to_limbs(&s, sc.n).unwrap()));
    let u1 = sc.to_be(&sc.out_of_mont(&sc.mul(&e, &si)));
    let u2 = sc.to_be(&sc.out_of_mont(&sc.mul(&rm, &si)));
    let p = add(c, &mul(c, &generator(c), &u1), &mul(c, &q, &u2));
    let Some((x, _)) = to_affine(c, &p) else {
        return false;
    };
    reduce_x(c, &x)[..sc.n] == be_to_limbs(&r, sc.n).unwrap()[..sc.n]
}

/// Whether `public` is an uncompressed point on the curve.
pub fn is_valid_point(curve: Curve, public: &[u8]) -> bool {
    decode_point(params(curve), public).is_some()
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

    // RFC 6979 A.2.5 (P-256) and A.2.6 (P-384), message "sample" with
    // SHA-256 and SHA-384: the public key and the deterministic
    // signatures.
    #[test]
    fn rfc_6979() {
        let cases = [
            (
                Curve::P256,
                "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721",
                "0460FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6\
                 7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299",
                HashAlg::Sha256,
                "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716",
                "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8",
            ),
            (
                Curve::P384,
                "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5",
                "04EC3A4E415B4E19A4568618029F427FA5DA9A8BC4AE92E02E06AAE5286B300C64DEF8F0EA9055866064A254515480BC13\
                 8015D9B72D7D57244EA8EF9AC0C621896708A59367F9DFB9F54CA84B3F1C9DB1288B231C3AE0D4FE7344FD2533264720",
                HashAlg::Sha384,
                "94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C81A648152E44ACF96E36DD1E80FABE46",
                "99EF4AEB15F178CEA1FE40DB2603138F130E740A19624526203B6351D0A3A94FA329C145786E679E7B82C71A38628AC8",
            ),
        ];
        for (curve, d, q, alg, r, s) in cases {
            let k = SecretKey::from_bytes(curve, &hex(d)).unwrap();
            assert_eq!(k.public_key(), hex(q), "{curve:?} public key");
            let h = alg.digest(b"sample");
            let (rr, ss) = k.sign_prehashed(&h, alg);
            assert_eq!(
                (rr.clone(), ss.clone()),
                (hex(r), hex(s)),
                "{curve:?} signature"
            );
            assert!(verify_prehashed(curve, &hex(q), &h, &rr, &ss));
            assert!(!verify_prehashed(
                curve,
                &hex(q),
                &alg.digest(b"samplf"),
                &rr,
                &ss
            ));
        }
    }

    #[test]
    #[cfg_attr(not(unix), ignore = "needs operating system randomness (ADR-041)")]
    fn ecdh_agrees_and_refuses_points_off_the_curve() {
        for curve in [Curve::P256, Curve::P384] {
            let a = SecretKey::generate(curve).unwrap();
            let b = SecretKey::generate(curve).unwrap();
            let ab = a.diffie_hellman(&b.public_key()).unwrap();
            let ba = b.diffie_hellman(&a.public_key()).unwrap();
            assert_eq!(ab.expose(), ba.expose());
            let mut bad = b.public_key();
            let last = bad.len() - 1;
            bad[last] ^= 1;
            assert!(a.diffie_hellman(&bad).is_none());
        }
    }
}
