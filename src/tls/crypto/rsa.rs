//! RSA signatures (RFC 8017): PKCS#1 v1.5 and PSS verification, PSS and
//! PKCS#1 v1.5 signing, for moduli of 2048 to 4096 bits.
//!
//! Arithmetic is Montgomery multiplication on numbers of the modulus's
//! fixed width. The private exponentiation uses a fixed 4-bit window and
//! reads every table entry for every lookup, keeping only the one it
//! needs with a mask. The message is blinded before it is exponentiated
//! and the signature is verified before it leaves.
//!
//! The Chinese remainder theorem is not used. It would make signing about
//! three times faster, and a single fault in one of its halves reveals a
//! factor of the modulus; one exponentiation modulo n has no such half.

// Limb arithmetic walks several arrays by the same index.
#![allow(clippy::needless_range_loop)]

use super::ct::{self, Secret};
use super::sha2::HashAlg;
use std::hint::black_box;

pub const MIN_BITS: usize = 2048;
pub const MAX_BITS: usize = 4096;

/// A number of a fixed number of limbs, least significant first.
type Num = Vec<u64>;

fn from_be(b: &[u8], n: usize) -> Option<Num> {
    let b = &b[b.iter().take_while(|&&x| x == 0).count()..];
    if b.len() > 8 * n {
        return None;
    }
    let mut out = vec![0u64; n];
    for (i, chunk) in b.rchunks(8).enumerate() {
        let mut w = [0u8; 8];
        w[8 - chunk.len()..].copy_from_slice(chunk);
        out[i] = u64::from_be_bytes(w);
    }
    Some(out)
}

fn to_be(a: &Num, len: usize) -> Vec<u8> {
    let mut full = Vec::with_capacity(a.len() * 8);
    for w in a.iter().rev() {
        full.extend_from_slice(&w.to_be_bytes());
    }
    full[full.len() - len..].to_vec()
}

fn bits(a: &Num) -> usize {
    for i in (0..a.len()).rev() {
        if a[i] != 0 {
            return 64 * i + 64 - a[i].leading_zeros() as usize;
        }
    }
    0
}

/// `a < b` for public values.
fn lt(a: &Num, b: &Num) -> bool {
    for i in (0..a.len()).rev() {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    false
}

/// Modular arithmetic for one odd modulus.
struct Modulus {
    m: Num,
    m_inv: u64,
    r2: Num,
    one: Num,
}

impl Modulus {
    fn new(m: Num) -> Modulus {
        let mut inv = 1u64;
        for _ in 0..6 {
            inv = inv.wrapping_mul(2u64.wrapping_sub(m[0].wrapping_mul(inv)));
        }
        let n = m.len();
        let mut md = Modulus {
            m,
            m_inv: inv.wrapping_neg(),
            r2: vec![0; n],
            one: vec![0; n],
        };
        // R mod m by doubling 1, then R^2 by doubling further.
        let mut x = vec![0u64; n];
        x[0] = 1;
        for _ in 0..64 * n {
            x = md.add(&x, &x);
        }
        md.one = x.clone();
        for _ in 0..64 * n {
            x = md.add(&x, &x);
        }
        md.r2 = x;
        md
    }

    fn sub_if_ge(&self, t: &Num, hi: u64) -> Num {
        let n = self.m.len();
        let mut d = vec![0u64; n];
        let mut borrow = 0u64;
        for i in 0..n {
            let (a, b1) = t[i].overflowing_sub(self.m[i]);
            let (a, b2) = a.overflowing_sub(borrow);
            d[i] = a;
            borrow = (b1 | b2) as u64;
        }
        let take = black_box(hi | (borrow ^ 1)).wrapping_neg();
        (0..n).map(|i| (t[i] & !take) | (d[i] & take)).collect()
    }

    fn add(&self, a: &Num, b: &Num) -> Num {
        let n = self.m.len();
        let mut s = vec![0u64; n];
        let mut c = 0u64;
        for i in 0..n {
            let (x, c1) = a[i].overflowing_add(b[i]);
            let (x, c2) = x.overflowing_add(c);
            s[i] = x;
            c = (c1 | c2) as u64;
        }
        self.sub_if_ge(&s, c)
    }

    /// `a * b / R mod m`, CIOS.
    fn mul(&self, a: &Num, b: &Num) -> Num {
        let n = self.m.len();
        let mut t = vec![0u64; n + 2];
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
            let q = t[0].wrapping_mul(self.m_inv);
            let s = t[0] as u128 + q as u128 * self.m[0] as u128;
            let mut c = (s >> 64) as u64;
            for j in 1..n {
                let s = t[j] as u128 + q as u128 * self.m[j] as u128 + c as u128;
                t[j - 1] = s as u64;
                c = (s >> 64) as u64;
            }
            let s = t[n] as u128 + c as u128;
            t[n - 1] = s as u64;
            t[n] = t[n + 1] + (s >> 64) as u64;
        }
        let hi = t[n];
        t.truncate(n);
        self.sub_if_ge(&t, hi)
    }

    fn to_mont(&self, a: &Num) -> Num {
        self.mul(a, &self.r2)
    }

    fn out_of_mont(&self, a: &Num) -> Num {
        let mut one = vec![0u64; self.m.len()];
        one[0] = 1;
        self.mul(a, &one)
    }

    /// `a^e mod m` for a public exponent, plain square and multiply.
    fn pow_public(&self, a: &Num, e: &Num) -> Num {
        let am = self.to_mont(a);
        let mut r = self.one.clone();
        for i in (0..bits(e)).rev() {
            r = self.mul(&r, &r);
            if (e[i / 64] >> (i % 64)) & 1 == 1 {
                r = self.mul(&r, &am);
            }
        }
        self.out_of_mont(&r)
    }

    /// `a^e mod m` for a secret exponent: a fixed 4-bit window over all
    /// `64 * e.len()` bits, every table entry read for every lookup.
    fn pow_secret(&self, a: &Num, e: &Num) -> Num {
        let n = self.m.len();
        let am = self.to_mont(a);
        let mut table = vec![self.one.clone(), am.clone()];
        for i in 2..16 {
            table.push(self.mul(&table[i - 1], &am));
        }
        let mut r = self.one.clone();
        for w in (0..e.len() * 16).rev() {
            for _ in 0..4 {
                r = self.mul(&r, &r);
            }
            let idx = ((e[w / 16] >> (4 * (w % 16))) & 15) as u32;
            let mut sel = vec![0u64; n];
            for (j, entry) in table.iter().enumerate() {
                let mask = ct::eq_mask_u32(j as u32, idx) as u64;
                let mask = mask | (mask << 32);
                for k in 0..n {
                    sel[k] |= entry[k] & mask;
                }
            }
            r = self.mul(&r, &sel);
        }
        for t in table.iter_mut() {
            ct::wipe_u64(t);
        }
        self.out_of_mont(&r)
    }
}

/// An RSA public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey {
    n: Num,
    e: Num,
    bytes: usize,
}

impl PublicKey {
    /// From big endian modulus and exponent. Refuses moduli outside 2048
    /// to 4096 bits and exponents that are even, 1, or above 2^32.
    pub fn new(n: &[u8], e: &[u8]) -> Option<PublicKey> {
        let limbs = n.len().div_ceil(8);
        let nn = from_be(n, limbs)?;
        let b = bits(&nn);
        // A modulus whose length is not a whole number of bytes comes from
        // no key generator in use; refusing it, as webpki does, also keeps
        // the PSS encoding at the modulus length.
        if !(MIN_BITS..=MAX_BITS).contains(&b) || !b.is_multiple_of(8) || nn[0] & 1 == 0 {
            return None;
        }
        let limbs = b.div_ceil(64);
        let nn = from_be(n, limbs)?;
        let ee = from_be(e, limbs)?;
        let eb = bits(&ee);
        if ee[0] & 1 == 0 || !(2..=33).contains(&eb) {
            return None;
        }
        Some(PublicKey {
            n: nn,
            e: ee,
            bytes: b.div_ceil(8),
        })
    }

    pub fn bits(&self) -> usize {
        bits(&self.n)
    }

    pub fn modulus(&self) -> Vec<u8> {
        to_be(&self.n, self.bytes)
    }

    pub fn exponent(&self) -> Vec<u8> {
        let e = to_be(&self.e, self.bytes);
        e[e.iter().take_while(|&&b| b == 0).count()..].to_vec()
    }

    /// `s^e mod n`, for a signature of exactly the modulus's length and
    /// below the modulus.
    fn open(&self, sig: &[u8]) -> Option<Vec<u8>> {
        if sig.len() != self.bytes {
            return None;
        }
        let s = from_be(sig, self.n.len())?;
        if !lt(&s, &self.n) {
            return None;
        }
        let m = Modulus::new(self.n.clone());
        Some(to_be(&m.pow_public(&s, &self.e), self.bytes))
    }

    /// RSASSA-PKCS1-v1_5 (RFC 8017 8.2.2). The expected encoding is built
    /// and compared whole, never parsed: parsing the padding is how
    /// Bleichenbacher's 2006 forgery worked.
    pub fn verify_pkcs1(&self, hash: HashAlg, msg: &[u8], sig: &[u8]) -> bool {
        let Some(em) = self.open(sig) else {
            return false;
        };
        match pkcs1_encode(hash, msg, self.bytes) {
            Some(want) => ct::eq(&em, &want),
            None => false,
        }
    }

    /// RSASSA-PSS (RFC 8017 9.1.2) with MGF1 over the same hash and the
    /// given salt length.
    pub fn verify_pss(&self, hash: HashAlg, msg: &[u8], sig: &[u8], salt_len: usize) -> bool {
        let Some(em) = self.open(sig) else {
            return false;
        };
        let em_bits = self.bits() - 1;
        let em_len = em_bits.div_ceil(8);
        // With a modulus of 8k+1 bits the encoding is a byte shorter and
        // the first byte of the opened value must be zero.
        let em = if em_len < em.len() {
            if em[0] != 0 {
                return false;
            }
            &em[1..]
        } else {
            &em[..]
        };
        pss_verify(hash, &hash.digest(msg), em, em_bits, salt_len)
    }
}

fn digest_info(hash: HashAlg) -> &'static [u8] {
    match hash {
        HashAlg::Sha256 => &[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x01, 0x05, 0x00, 0x04, 0x20,
        ],
        HashAlg::Sha384 => &[
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x02, 0x05, 0x00, 0x04, 0x30,
        ],
        HashAlg::Sha512 => &[
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
            0x03, 0x05, 0x00, 0x04, 0x40,
        ],
    }
}

/// EMSA-PKCS1-v1_5: `00 01 FF..FF 00 DigestInfo H`.
fn pkcs1_encode(hash: HashAlg, msg: &[u8], len: usize) -> Option<Vec<u8>> {
    let di = digest_info(hash);
    let h = hash.digest(msg);
    let t_len = di.len() + h.len();
    if len < t_len + 11 {
        return None;
    }
    let mut em = vec![0xffu8; len];
    em[0] = 0;
    em[1] = 1;
    em[len - t_len - 1] = 0;
    em[len - t_len..len - h.len()].copy_from_slice(di);
    em[len - h.len()..].copy_from_slice(&h);
    Some(em)
}

fn mgf1(hash: HashAlg, seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + hash.output_len());
    let mut counter = 0u32;
    while out.len() < len {
        let mut h = hash.new_hasher();
        h.update(seed);
        h.update(&counter.to_be_bytes());
        out.extend(h.finish());
        counter += 1;
    }
    out.truncate(len);
    out
}

fn pss_verify(hash: HashAlg, m_hash: &[u8], em: &[u8], em_bits: usize, salt_len: usize) -> bool {
    let h_len = hash.output_len();
    let em_len = em.len();
    if em_len < h_len + salt_len + 2 || em[em_len - 1] != 0xbc {
        return false;
    }
    let (masked_db, rest) = em.split_at(em_len - h_len - 1);
    let h = &rest[..h_len];
    let unused = 8 * em_len - em_bits;
    if masked_db[0] >> (8 - unused) != 0 {
        return false;
    }
    let mut db: Vec<u8> = masked_db
        .iter()
        .zip(mgf1(hash, h, masked_db.len()))
        .map(|(a, b)| a ^ b)
        .collect();
    db[0] &= 0xff >> unused;
    let ps_len = em_len - h_len - salt_len - 2;
    if db[..ps_len].iter().any(|&b| b != 0) || db[ps_len] != 1 {
        return false;
    }
    let salt = &db[ps_len + 1..];
    let mut m = hash.new_hasher();
    m.update(&[0u8; 8]);
    m.update(m_hash);
    m.update(salt);
    ct::eq(&m.finish(), h)
}

fn pss_encode(hash: HashAlg, m_hash: &[u8], em_bits: usize, salt: &[u8]) -> Vec<u8> {
    let h_len = hash.output_len();
    let em_len = em_bits.div_ceil(8);
    let mut m = hash.new_hasher();
    m.update(&[0u8; 8]);
    m.update(m_hash);
    m.update(salt);
    let h = m.finish();
    let mut db = vec![0u8; em_len - h_len - 1];
    let ps_len = db.len() - salt.len() - 1;
    db[ps_len] = 1;
    db[ps_len + 1..].copy_from_slice(salt);
    for (d, k) in db.iter_mut().zip(mgf1(hash, &h, em_len - h_len - 1)) {
        *d ^= k;
    }
    db[0] &= 0xff >> (8 * em_len - em_bits);
    let mut em = db;
    em.extend_from_slice(&h);
    em.push(0xbc);
    em
}

/// An RSA private key: the public key, the private exponent and
/// phi(n), which the blinding needs to invert the blinding factor.
pub struct PrivateKey {
    public: PublicKey,
    d: Num,
    phi: Num,
}

impl PrivateKey {
    /// From the PKCS#1 components. The primes are checked to multiply to
    /// n, and e*d to be 1 modulo phi(n), so a damaged key file is
    /// refused here instead of producing wrong signatures.
    pub fn new(n: &[u8], e: &[u8], d: &[u8], p: &[u8], q: &[u8]) -> Option<PrivateKey> {
        let public = PublicKey::new(n, e)?;
        let limbs = public.n.len();
        let p = from_be(p, limbs)?;
        let q = from_be(q, limbs)?;
        if mul_full(&p, &q)[..limbs] != public.n[..]
            || mul_full(&p, &q)[limbs..].iter().any(|&w| w != 0)
        {
            return None;
        }
        let one = {
            let mut o = vec![0u64; limbs];
            o[0] = 1;
            o
        };
        let phi_full = mul_full(&sub(&p, &one), &sub(&q, &one));
        let phi: Num = phi_full[..limbs].to_vec();
        let d = from_be(d, limbs)?;
        if !lt(&d, &public.n) {
            return None;
        }
        // e * d must be 1 modulo p-1 and modulo q-1. That holds whether d
        // was computed modulo phi(n) or modulo lcm(p-1, q-1), as OpenSSL
        // does.
        let ed = mul_full(&public.e, &d);
        let mut ed_wide = ed.clone();
        ed_wide.resize(2 * limbs, 0);
        for f in [sub(&p, &one), sub(&q, &one)] {
            if rem(&ed_wide, &f) != one {
                return None;
            }
        }
        Some(PrivateKey { public, d, phi })
    }

    pub fn public(&self) -> &PublicKey {
        &self.public
    }

    /// `m^d mod n` with blinding: the input is multiplied by `r^e` for a
    /// fresh random `r` before exponentiation and the result by `r^-1`
    /// after, so the exponentiation never sees a value the caller chose.
    /// `r^-1` is `r^(phi - 1)`, computed with the same constant time
    /// exponentiation.
    fn private_op(&self, em: &[u8]) -> std::io::Result<Vec<u8>> {
        let n = &self.public.n;
        let md = Modulus::new(n.clone());
        let m = from_be(em, n.len()).expect("encoding fits");
        let r = loop {
            let mut b = Secret::zeroed(self.public.bytes);
            super::rand::fill(b.expose_mut())?;
            let r = from_be(b.expose(), n.len()).unwrap();
            if lt(&r, n) && bits(&r) > 64 {
                break r;
            }
        };
        let blinded = md.out_of_mont(&md.mul(
            &md.to_mont(&m),
            &md.to_mont(&md.pow_public(&r, &self.public.e)),
        ));
        let s_blind = md.pow_secret(&blinded, &self.d);
        let mut phi_1 = self.phi.clone();
        phi_1[0] -= 1;
        let r_inv = md.pow_secret(&r, &phi_1);
        let s = md.out_of_mont(&md.mul(&md.to_mont(&s_blind), &md.to_mont(&r_inv)));
        Ok(to_be(&s, self.public.bytes))
    }

    /// RSASSA-PSS with a random salt of the hash's length, as TLS 1.3
    /// requires (RFC 8446 4.2.3).
    pub fn sign_pss(&self, hash: HashAlg, msg: &[u8]) -> std::io::Result<Vec<u8>> {
        let mut salt = vec![0u8; hash.output_len()];
        super::rand::fill(&mut salt)?;
        let em_bits = self.public.bits() - 1;
        let em = pss_encode(hash, &hash.digest(msg), em_bits, &salt);
        let sig = self.private_op(&em)?;
        self.check(self.public.verify_pss(hash, msg, &sig, salt.len()))?;
        Ok(sig)
    }

    /// RSASSA-PKCS1-v1_5, for TLS 1.2 and certificates.
    pub fn sign_pkcs1(&self, hash: HashAlg, msg: &[u8]) -> std::io::Result<Vec<u8>> {
        let em = pkcs1_encode(hash, msg, self.public.bytes).expect("modulus large enough");
        let sig = self.private_op(&em)?;
        self.check(self.public.verify_pkcs1(hash, msg, &sig))?;
        Ok(sig)
    }

    /// A signature that does not verify means a fault in the computation;
    /// such a value can leak the key and is never handed out.
    fn check(&self, ok: bool) -> std::io::Result<()> {
        if ok {
            Ok(())
        } else {
            Err(std::io::Error::other("RSA signature failed its own check"))
        }
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) {
        ct::wipe_u64(&mut self.d);
        ct::wipe_u64(&mut self.phi);
    }
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "rsa::PrivateKey({} bits)", self.public.bits())
    }
}

/// The full product of two numbers of the same width.
fn mul_full(a: &Num, b: &Num) -> Num {
    let n = a.len();
    let mut out = vec![0u64; 2 * n];
    for i in 0..n {
        let mut c = 0u128;
        for j in 0..n {
            let t = out[i + j] as u128 + a[i] as u128 * b[j] as u128 + c;
            out[i + j] = t as u64;
            c = t >> 64;
        }
        out[i + n] = c as u64;
    }
    out
}

fn sub(a: &Num, b: &Num) -> Num {
    let mut out = vec![0u64; a.len()];
    let mut borrow = 0u64;
    for i in 0..a.len() {
        let (x, b1) = a[i].overflowing_sub(b[i]);
        let (x, b2) = x.overflowing_sub(borrow);
        out[i] = x;
        borrow = (b1 | b2) as u64;
    }
    out
}

/// `a mod m` by shift and subtract, for the one-time key check; not
/// constant time, and only run on the key while loading it.
fn rem(a: &Num, m: &Num) -> Num {
    let n = m.len();
    let mut r = vec![0u64; n + 1];
    for i in (0..64 * a.len()).rev() {
        let mut carry = (a[i / 64] >> (i % 64)) & 1;
        for limb in r.iter_mut() {
            let next = *limb >> 63;
            *limb = (*limb << 1) | carry;
            carry = next;
        }
        let mut mm = m.clone();
        mm.push(0);
        if !lt(&r, &mm) {
            r = sub(&r, &mm);
        }
    }
    r.truncate(n);
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_exponentiation_matches_a_slow_reference() {
        // m = a 2048-bit odd number made of a pattern; compare both
        // exponentiations with each other on a public exponent.
        let mut nb = vec![0xc3u8; 256];
        nb[0] = 0xd1;
        nb[255] |= 1;
        let n = from_be(&nb, 32).unwrap();
        let md = Modulus::new(n.clone());
        let a = from_be(&[7u8; 200], 32).unwrap();
        let mut e = vec![0u64; 32];
        e[0] = 65537;
        assert_eq!(md.pow_public(&a, &e), md.pow_secret(&a, &e));
        e[0] = 1;
        assert_eq!(md.pow_public(&a, &e), a);
    }
}
