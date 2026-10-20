//! Constant time helpers and wiping of secrets.
//!
//! Rust promises nothing about timing. `black_box` keeps the optimizer
//! from seeing that a mask is really a boolean and turning the arithmetic
//! back into a branch, which it otherwise does at `-O`. Whether it worked
//! is checked by the timing test, not by reading this file.

use std::hint::black_box;

/// `0xff` if `a == b`, else `0`.
#[inline]
pub fn eq_mask_u8(a: u8, b: u8) -> u8 {
    let x = black_box(a ^ b) as u32;
    (x.wrapping_sub(1) >> 8) as u8
}

/// All ones if `a == b`, else zero.
#[inline]
pub fn eq_mask_u32(a: u32, b: u32) -> u32 {
    let x = black_box(a ^ b) as u64;
    (x.wrapping_sub(1) >> 32) as u32
}

/// All ones if `a < b`, else zero.
#[inline]
pub fn lt_mask_u32(a: u32, b: u32) -> u32 {
    let d = black_box((a as u64).wrapping_sub(b as u64));
    (d >> 32) as u32
}

/// Equality of two slices in time that depends only on their lengths.
/// The lengths themselves are treated as public.
pub fn eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b) {
        acc |= x ^ y;
    }
    black_box(acc) == 0
}

/// `dst = if mask { src } else { dst }`, for a mask of all ones or zero.
pub fn select_into(mask: u8, dst: &mut [u8], src: &[u8]) {
    assert_eq!(dst.len(), src.len());
    let mask = black_box(mask);
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= mask & (*d ^ *s);
    }
}

/// Overwrites a secret with zeros.
///
/// Without `unsafe` there is no volatile write, so the zeroing is passed
/// through `black_box`, which makes the stores observable to the
/// optimizer and keeps them from being removed as dead. Copies the
/// compiler made on its own, in registers or on the stack, are out of
/// reach either way.
pub fn wipe(buf: &mut [u8]) {
    buf.fill(0);
    black_box(buf);
}

pub fn wipe_u32(buf: &mut [u32]) {
    buf.fill(0);
    black_box(buf);
}

pub fn wipe_u64(buf: &mut [u64]) {
    buf.fill(0);
    black_box(buf);
}

/// Bytes that are wiped on drop and never printed.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct Secret(Vec<u8>);

impl Secret {
    pub fn new(bytes: Vec<u8>) -> Secret {
        Secret(bytes)
    }
    pub fn zeroed(len: usize) -> Secret {
        Secret(vec![0; len])
    }
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
    pub fn expose_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<&[u8]> for Secret {
    fn from(b: &[u8]) -> Secret {
        Secret(b.to_vec())
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Secret({} bytes)", self.0.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_at_the_edges() {
        for (a, b) in [
            (0u32, 0u32),
            (0, 1),
            (1, 0),
            (u32::MAX, u32::MAX),
            (0, u32::MAX),
        ] {
            assert_eq!(eq_mask_u32(a, b), if a == b { !0 } else { 0 });
            assert_eq!(lt_mask_u32(a, b), if a < b { !0 } else { 0 });
        }
        for a in 0..=255u8 {
            assert_eq!(eq_mask_u8(a, 0x80), if a == 0x80 { 0xff } else { 0 });
        }
    }

    #[test]
    fn eq_sees_every_bit_position() {
        let a = [0x5au8; 33];
        for i in 0..a.len() * 8 {
            let mut b = a;
            b[i / 8] ^= 1 << (i % 8);
            assert!(!eq(&a, &b));
        }
        assert!(eq(&a, &a));
        assert!(!eq(&a, &a[..32]));
    }

    #[test]
    fn secret_does_not_print_its_bytes() {
        let s = Secret::new(vec![0x41; 4]);
        assert_eq!(format!("{s:?}"), "Secret(4 bytes)");
    }
}
