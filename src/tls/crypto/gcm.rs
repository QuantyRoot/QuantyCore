//! AES-GCM (NIST SP 800-38D) with 96-bit nonces.
//!
//! GHASH multiplies in GF(2^128). A table of multiples of H would be
//! indexed by secret data, so the carryless products are computed with
//! integer multiplications on operands that have three zero bits between
//! every data bit (the method of BearSSL's `ghash_ctmul64`): the carries of
//! the integer product land in the gaps and are masked away. The low half
//! of a 64x64 product comes out directly; the high half is the low half of
//! the product of the bit reversed operands.

use super::aead::{Aead, AeadError, NONCE_LEN, TAG_LEN};
use super::aes::Aes;
use super::ct;

/// The low 64 bits of the carryless product.
fn bmul64(x: u64, y: u64) -> u64 {
    const M0: u64 = 0x1111_1111_1111_1111;
    const M1: u64 = M0 << 1;
    const M2: u64 = M0 << 2;
    const M3: u64 = M0 << 3;
    let (x0, x1, x2, x3) = (x & M0, x & M1, x & M2, x & M3);
    let (y0, y1, y2, y3) = (y & M0, y & M1, y & M2, y & M3);
    let m = |a: u64, b: u64| a.wrapping_mul(b);
    let z0 = m(x0, y0) ^ m(x1, y3) ^ m(x2, y2) ^ m(x3, y1);
    let z1 = m(x0, y1) ^ m(x1, y0) ^ m(x2, y3) ^ m(x3, y2);
    let z2 = m(x0, y2) ^ m(x1, y1) ^ m(x2, y0) ^ m(x3, y3);
    let z3 = m(x0, y3) ^ m(x1, y2) ^ m(x2, y1) ^ m(x3, y0);
    (z0 & M0) | (z1 & M1) | (z2 & M2) | (z3 & M3)
}

#[derive(Clone)]
struct Ghash {
    h: [u64; 2],
    y: [u64; 2],
}

impl Ghash {
    fn new(h: &[u8; 16]) -> Ghash {
        Ghash {
            h: [
                u64::from_be_bytes(h[8..].try_into().unwrap()),
                u64::from_be_bytes(h[..8].try_into().unwrap()),
            ],
            y: [0, 0],
        }
    }

    /// `y = (y ^ block) * H`, GCM's bit order: the first bit of the block
    /// is the coefficient of x^0, so values are reflected, which is why the
    /// product is shifted left by one and reduced from the low end.
    fn block(&mut self, block: &[u8]) {
        let y0 = self.y[0] ^ u64::from_be_bytes(block[8..16].try_into().unwrap());
        let y1 = self.y[1] ^ u64::from_be_bytes(block[..8].try_into().unwrap());
        let [h0, h1] = self.h;
        let (h0r, h1r) = (h0.reverse_bits(), h1.reverse_bits());
        let (y0r, y1r) = (y0.reverse_bits(), y1.reverse_bits());
        let (h2, h2r, y2, y2r) = (h0 ^ h1, h0r ^ h1r, y0 ^ y1, y0r ^ y1r);

        let z0 = bmul64(y0, h0);
        let z1 = bmul64(y1, h1);
        let mut z2 = bmul64(y2, h2);
        let mut z0h = bmul64(y0r, h0r);
        let mut z1h = bmul64(y1r, h1r);
        let mut z2h = bmul64(y2r, h2r);
        z2 ^= z0 ^ z1;
        z2h ^= z0h ^ z1h;
        z0h = z0h.reverse_bits() >> 1;
        z1h = z1h.reverse_bits() >> 1;
        z2h = z2h.reverse_bits() >> 1;

        let mut v0 = z0;
        let mut v1 = z0h ^ z2;
        let mut v2 = z1 ^ z2h;
        let mut v3 = z1h;

        v3 = (v3 << 1) | (v2 >> 63);
        v2 = (v2 << 1) | (v1 >> 63);
        v1 = (v1 << 1) | (v0 >> 63);
        v0 <<= 1;

        v2 ^= v0 ^ (v0 >> 1) ^ (v0 >> 2) ^ (v0 >> 7);
        v1 ^= (v0 << 63) ^ (v0 << 62) ^ (v0 << 57);
        v3 ^= v1 ^ (v1 >> 1) ^ (v1 >> 2) ^ (v1 >> 7);
        v2 ^= (v1 << 63) ^ (v1 << 62) ^ (v1 << 57);

        self.y = [v2, v3];
    }

    /// Absorbs `data` zero padded to a multiple of 16 bytes.
    fn update_padded(&mut self, data: &[u8]) {
        let (chunks, rest) = data.as_chunks::<16>();
        for c in chunks {
            self.block(c);
        }
        if !rest.is_empty() {
            let mut b = [0u8; 16];
            b[..rest.len()].copy_from_slice(rest);
            self.block(&b);
        }
    }

    fn finish(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[..8].copy_from_slice(&self.y[1].to_be_bytes());
        out[8..].copy_from_slice(&self.y[0].to_be_bytes());
        out
    }
}

impl Drop for Ghash {
    fn drop(&mut self) {
        ct::wipe_u64(&mut self.h);
        ct::wipe_u64(&mut self.y);
    }
}

#[derive(Clone)]
pub struct AesGcm {
    aes: Aes,
    h: [u8; 16],
}

impl AesGcm {
    /// Xors the keystream for counter blocks 2, 3, ... (block 1 is used
    /// for the tag) into `data`, four blocks per AES call.
    fn ctr(&self, nonce: &[u8; NONCE_LEN], data: &mut [u8]) {
        assert!(
            data.len() as u64 <= ((1u64 << 32) - 2) * 16,
            "GCM message longer than 2^32 - 2 blocks"
        );
        let mut ks = [0u8; 64];
        for (i, chunk) in data.chunks_mut(64).enumerate() {
            for lane in 0..4 {
                let ctr = (2 + 4 * i + lane) as u32;
                ks[16 * lane..16 * lane + 12].copy_from_slice(nonce);
                ks[16 * lane + 12..16 * lane + 16].copy_from_slice(&ctr.to_be_bytes());
            }
            self.aes.encrypt4(&mut ks);
            for (d, k) in chunk.iter_mut().zip(ks.iter()) {
                *d ^= k;
            }
        }
        ct::wipe(&mut ks);
    }

    fn tag(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
        let mut g = Ghash::new(&self.h);
        g.update_padded(aad);
        g.update_padded(ciphertext);
        let mut lens = [0u8; 16];
        lens[..8].copy_from_slice(&(aad.len() as u64 * 8).to_be_bytes());
        lens[8..].copy_from_slice(&(ciphertext.len() as u64 * 8).to_be_bytes());
        g.block(&lens);
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(nonce);
        j0[15] = 1;
        self.aes.encrypt_block(&mut j0);
        let s = g.finish();
        core::array::from_fn(|i| s[i] ^ j0[i])
    }
}

impl Aead for AesGcm {
    /// 16 for AES-128-GCM; `new` also takes 32 for AES-256-GCM.
    const KEY_LEN: usize = 16;

    fn new(key: &[u8]) -> Self {
        let aes = Aes::new(key);
        let mut h = [0u8; 16];
        aes.encrypt_block(&mut h);
        AesGcm { aes, h }
    }

    fn seal(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], buf: &mut Vec<u8>) {
        self.ctr(nonce, buf);
        let tag = self.tag(nonce, aad, buf);
        buf.extend_from_slice(&tag);
    }

    fn open(
        &self,
        nonce: &[u8; NONCE_LEN],
        aad: &[u8],
        buf: &mut Vec<u8>,
    ) -> Result<(), AeadError> {
        let Some(body) = buf.len().checked_sub(TAG_LEN) else {
            return Err(AeadError);
        };
        let want = self.tag(nonce, aad, &buf[..body]);
        if !ct::eq(&want, &buf[body..]) {
            return Err(AeadError);
        }
        buf.truncate(body);
        self.ctr(nonce, buf);
        Ok(())
    }
}

impl Drop for AesGcm {
    fn drop(&mut self) {
        ct::wipe(&mut self.h);
    }
}

impl std::fmt::Debug for AesGcm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AesGcm({:?})", self.aes)
    }
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

    // Test cases 4 (AES-128) and 16 (AES-256) of McGrew and Viega, "The
    // Galois/Counter Mode of Operation", which NIST's GCM specification
    // reproduces: partial last block and AAD that is not block aligned.
    #[test]
    fn gcm_spec_cases_4_and_16() {
        let plain = hex(
            "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72
             1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        );
        let aad = hex("feedfacedeadbeeffeedfacedeadbeefabaddad2");
        let nonce: [u8; 12] = hex("cafebabefacedbaddecaf888").try_into().unwrap();
        for (key, ct_hex, tag) in [
            (
                "feffe9928665731c6d6a8f9467308308",
                "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e
                 21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
                "5bc94fbc3221a5db94fae95ae7121a47",
            ),
            (
                "feffe9928665731c6d6a8f9467308308feffe9928665731c6d6a8f9467308308",
                "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa
                 8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
                "76fc6ece0f4e1768cddf8853bb2d551b",
            ),
        ] {
            let gcm = AesGcm::new(&hex(key));
            let mut buf = plain.clone();
            gcm.seal(&nonce, &aad, &mut buf);
            let mut want = hex(ct_hex);
            want.extend(hex(tag));
            assert_eq!(buf, want, "key {key}");
            gcm.open(&nonce, &aad, &mut buf).unwrap();
            assert_eq!(buf, plain);
        }
    }

    #[test]
    fn open_rejects_and_leaves_no_plaintext() {
        let gcm = AesGcm::new(&[3; 16]);
        let nonce = [9; 12];
        let mut buf = vec![0x42; 100];
        gcm.seal(&nonce, b"aad", &mut buf);
        let sealed = buf.clone();
        let last = buf.len() - 1;
        buf[last] ^= 0x80;
        assert_eq!(gcm.open(&nonce, b"aad", &mut buf), Err(AeadError));
        buf[last] ^= 0x80;
        assert_eq!(buf, sealed);
        assert!(gcm.open(&nonce, b"aae", &mut buf).is_err());
    }
}
