//! Arithmetic modulo p = 2^255 - 19, shared by X25519 and Ed25519.
//!
//! Five limbs of 51 bits in `u64`, products in `u128`. Every operation
//! carries back to limbs of at most 52 bits, which keeps the products of
//! two inputs and their nineteenfold multiples far below 2^128 without any
//! branch on the values. Only `to_bytes` reduces fully.

use super::ct;

const MASK: u64 = (1 << 51) - 1;

#[derive(Clone, Copy, Default)]
pub(crate) struct Fe(pub(crate) [u64; 5]);

impl Fe {
    pub(crate) const ZERO: Fe = Fe([0; 5]);
    pub(crate) const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    /// Ignores the top bit, as RFC 7748 and RFC 8032 both require.
    pub(crate) fn from_bytes(b: &[u8; 32]) -> Fe {
        let w = |i: usize| u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
        Fe([
            w(0) & MASK,
            (w(6) >> 3) & MASK,
            (w(12) >> 6) & MASK,
            (w(19) >> 1) & MASK,
            (w(24) >> 12) & MASK,
        ])
    }

    fn carry(mut self) -> Fe {
        let l = &mut self.0;
        let mut c;
        c = l[0] >> 51;
        l[0] &= MASK;
        l[1] += c;
        c = l[1] >> 51;
        l[1] &= MASK;
        l[2] += c;
        c = l[2] >> 51;
        l[2] &= MASK;
        l[3] += c;
        c = l[3] >> 51;
        l[3] &= MASK;
        l[4] += c;
        c = l[4] >> 51;
        l[4] &= MASK;
        l[0] += c * 19;
        self
    }

    /// The unique representative in `[0, p)`.
    pub(crate) fn to_bytes(self) -> [u8; 32] {
        let mut l = self.carry().carry().0;
        // q is 1 exactly when the value is at least p.
        let mut q = (l[0] + 19) >> 51;
        q = (l[1] + q) >> 51;
        q = (l[2] + q) >> 51;
        q = (l[3] + q) >> 51;
        q = (l[4] + q) >> 51;
        l[0] += 19 * q;
        for i in 0..4 {
            l[i + 1] += l[i] >> 51;
            l[i] &= MASK;
        }
        l[4] &= MASK;
        let mut out = [0u8; 32];
        let v = [
            l[0] | (l[1] << 51),
            (l[1] >> 13) | (l[2] << 38),
            (l[2] >> 26) | (l[3] << 25),
            (l[3] >> 39) | (l[4] << 12),
        ];
        for (o, w) in out.as_chunks_mut::<8>().0.iter_mut().zip(v) {
            *o = w.to_le_bytes();
        }
        out
    }

    pub(crate) fn add(&self, b: &Fe) -> Fe {
        Fe(core::array::from_fn(|i| self.0[i] + b.0[i])).carry()
    }

    /// Adds 4p first so that no limb goes negative for inputs of up to 53
    /// bits per limb.
    pub(crate) fn sub(&self, b: &Fe) -> Fe {
        const FOUR_P: [u64; 5] = [
            0x1f_ffff_ffff_ffb4,
            0x1f_ffff_ffff_fffc,
            0x1f_ffff_ffff_fffc,
            0x1f_ffff_ffff_fffc,
            0x1f_ffff_ffff_fffc,
        ];
        Fe(core::array::from_fn(|i| self.0[i] + FOUR_P[i] - b.0[i])).carry()
    }

    pub(crate) fn mul(&self, b: &Fe) -> Fe {
        let a = self.0.map(|x| x as u128);
        let b = b.0.map(|x| x as u128);
        let b19: [u128; 5] = core::array::from_fn(|i| b[i] * 19);
        let r = [
            a[0] * b[0] + a[1] * b19[4] + a[2] * b19[3] + a[3] * b19[2] + a[4] * b19[1],
            a[0] * b[1] + a[1] * b[0] + a[2] * b19[4] + a[3] * b19[3] + a[4] * b19[2],
            a[0] * b[2] + a[1] * b[1] + a[2] * b[0] + a[3] * b19[4] + a[4] * b19[3],
            a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0] + a[4] * b19[4],
            a[0] * b[4] + a[1] * b[3] + a[2] * b[2] + a[3] * b[1] + a[4] * b[0],
        ];
        Fe::reduce_wide(r)
    }

    pub(crate) fn square(&self) -> Fe {
        self.mul(self)
    }

    pub(crate) fn mul_small(&self, k: u32) -> Fe {
        let r: [u128; 5] = core::array::from_fn(|i| self.0[i] as u128 * k as u128);
        Fe::reduce_wide(r)
    }

    fn reduce_wide(mut r: [u128; 5]) -> Fe {
        let m = MASK as u128;
        for i in 0..4 {
            r[i + 1] += r[i] >> 51;
            r[i] &= m;
        }
        let c = r[4] >> 51;
        r[4] &= m;
        r[0] += c * 19;
        let c = r[0] >> 51;
        r[0] &= m;
        r[1] += c;
        Fe(r.map(|x| x as u64))
    }

    /// `self^(2^k)`.
    pub(crate) fn pow2k(&self, k: u32) -> Fe {
        let mut x = *self;
        for _ in 0..k {
            x = x.square();
        }
        x
    }

    /// `self^(2^250 - 1)` and `self^11`. Ed25519's square root exponent
    /// (p - 5) / 8 shares this prefix.
    fn pow_2_250_minus_1(&self) -> (Fe, Fe) {
        let z2 = self.square();
        let z9 = z2.pow2k(2).mul(self);
        let z11 = z9.mul(&z2);
        let z_5_0 = z11.square().mul(&z9);
        let z_10_0 = z_5_0.pow2k(5).mul(&z_5_0);
        let z_20_0 = z_10_0.pow2k(10).mul(&z_10_0);
        let z_40_0 = z_20_0.pow2k(20).mul(&z_20_0);
        let z_50_0 = z_40_0.pow2k(10).mul(&z_10_0);
        let z_100_0 = z_50_0.pow2k(50).mul(&z_50_0);
        let z_200_0 = z_100_0.pow2k(100).mul(&z_100_0);
        let z_250_0 = z_200_0.pow2k(50).mul(&z_50_0);
        (z_250_0, z11)
    }

    /// `self^(p - 2)`, which is the inverse for nonzero values and zero for
    /// zero, with a fixed sequence of operations.
    pub(crate) fn invert(&self) -> Fe {
        let (z_250_0, z11) = self.pow_2_250_minus_1();
        z_250_0.pow2k(5).mul(&z11)
    }

    /// Swaps `a` and `b` if `swap` is 1, without a branch.
    pub(crate) fn cswap(a: &mut Fe, b: &mut Fe, swap: u64) {
        let mask = 0u64.wrapping_sub(std::hint::black_box(swap));
        for i in 0..5 {
            let t = mask & (a.0[i] ^ b.0[i]);
            a.0[i] ^= t;
            b.0[i] ^= t;
        }
    }

    pub(crate) fn wipe(&mut self) {
        ct::wipe_u64(&mut self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_at_and_above_p_reduce() {
        let mut p = [0xffu8; 32];
        p[0] = 0xed;
        p[31] = 0x7f;
        assert_eq!(Fe::from_bytes(&p).to_bytes(), [0; 32]);
        let mut p1 = p;
        p1[0] = 0xee;
        assert_eq!(Fe::from_bytes(&p1).to_bytes(), Fe::ONE.to_bytes());
        // 2^255 - 1 is p + 18.
        let mut top = [0xffu8; 32];
        top[31] = 0x7f;
        let mut want = [0u8; 32];
        want[0] = 18;
        assert_eq!(Fe::from_bytes(&top).to_bytes(), want);
    }

    #[test]
    fn inverse() {
        let mut b = [0u8; 32];
        for (i, x) in b.iter_mut().enumerate() {
            *x = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
        b[31] &= 0x7f;
        let x = Fe::from_bytes(&b);
        assert_eq!(x.mul(&x.invert()).to_bytes(), Fe::ONE.to_bytes());
        assert_eq!(Fe::ZERO.invert().to_bytes(), [0; 32]);
    }
}
