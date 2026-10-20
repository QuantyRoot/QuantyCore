//! ChaCha20, Poly1305 and their AEAD composition (RFC 8439).
//!
//! Both are additions, rotations and xors on words, with no secret
//! dependent branch or index. Poly1305 uses 26-bit limbs so that every
//! product fits in a `u64` without carries in between, and its final
//! reduction selects with masks instead of comparing.

use super::aead::{Aead, AeadError, NONCE_LEN, TAG_LEN};
use super::ct;

fn quarter(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

fn le32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// One 64-byte keystream block.
fn chacha20_block(key: &[u32; 8], counter: u32, nonce: &[u32; 3], out: &mut [u8; 64]) {
    let mut input = [0u32; 16];
    input[..4].copy_from_slice(&[0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);
    input[4..12].copy_from_slice(key);
    input[12] = counter;
    input[13..].copy_from_slice(nonce);
    let mut s = input;
    for _ in 0..10 {
        quarter(&mut s, 0, 4, 8, 12);
        quarter(&mut s, 1, 5, 9, 13);
        quarter(&mut s, 2, 6, 10, 14);
        quarter(&mut s, 3, 7, 11, 15);
        quarter(&mut s, 0, 5, 10, 15);
        quarter(&mut s, 1, 6, 11, 12);
        quarter(&mut s, 2, 7, 8, 13);
        quarter(&mut s, 3, 4, 9, 14);
    }
    for (i, o) in out.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        o.copy_from_slice(&s[i].wrapping_add(input[i]).to_le_bytes());
    }
    ct::wipe_u32(&mut s);
    ct::wipe_u32(&mut input);
}

#[derive(Clone)]
pub struct ChaCha20 {
    key: [u32; 8],
    nonce: [u32; 3],
}

impl ChaCha20 {
    pub fn new(key: &[u8; 32], nonce: &[u8; 12]) -> ChaCha20 {
        let mut k = [0u32; 8];
        for (w, b) in k.iter_mut().zip(key.as_chunks::<4>().0) {
            *w = le32(b);
        }
        let mut n = [0u32; 3];
        for (w, b) in n.iter_mut().zip(nonce.as_chunks::<4>().0) {
            *w = le32(b);
        }
        ChaCha20 { key: k, nonce: n }
    }

    /// Xors the keystream starting at block `counter` into `data`.
    ///
    /// Panics if the 32-bit block counter would wrap, which RFC 8439 leaves
    /// undefined and which would reuse keystream. That is 256 GiB under one
    /// nonce, far beyond the 2^14 byte records TLS encrypts.
    pub fn apply(&self, counter: u32, data: &mut [u8]) {
        let blocks = data.len().div_ceil(64) as u64;
        assert!(
            counter as u64 + blocks <= 1 << 32,
            "ChaCha20 block counter would wrap"
        );
        let mut ks = [0u8; 64];
        for (i, chunk) in data.chunks_mut(64).enumerate() {
            chacha20_block(&self.key, counter + i as u32, &self.nonce, &mut ks);
            for (d, k) in chunk.iter_mut().zip(ks.iter()) {
                *d ^= k;
            }
        }
        ct::wipe(&mut ks);
    }
}

impl Drop for ChaCha20 {
    fn drop(&mut self) {
        ct::wipe_u32(&mut self.key);
    }
}

const M26: u32 = 0x3ff_ffff;

pub struct Poly1305 {
    r: [u32; 5],
    h: [u32; 5],
    pad: [u32; 4],
    buf: [u8; 16],
    used: usize,
}

impl Poly1305 {
    pub fn new(key: &[u8; 32]) -> Poly1305 {
        // Clamping per RFC 8439 2.5, folded into the limb split.
        let r = [
            le32(&key[0..]) & 0x3ff_ffff,
            (le32(&key[3..]) >> 2) & 0x3ff_ff03,
            (le32(&key[6..]) >> 4) & 0x3ff_c0ff,
            (le32(&key[9..]) >> 6) & 0x3f0_3fff,
            (le32(&key[12..]) >> 8) & 0x00f_ffff,
        ];
        let pad = [
            le32(&key[16..]),
            le32(&key[20..]),
            le32(&key[24..]),
            le32(&key[28..]),
        ];
        Poly1305 {
            r,
            h: [0; 5],
            pad,
            buf: [0; 16],
            used: 0,
        }
    }

    /// `hibit` is 2^128 for a full block and 0 for the padded last block,
    /// where the 1 byte is appended explicitly instead.
    fn block(&mut self, m: &[u8; 16], hibit: u32) {
        let [r0, r1, r2, r3, r4] = self.r.map(|x| x as u64);
        let (s1, s2, s3, s4) = (r1 * 5, r2 * 5, r3 * 5, r4 * 5);
        let h = &mut self.h;
        h[0] += le32(&m[0..]) & M26;
        h[1] += (le32(&m[3..]) >> 2) & M26;
        h[2] += (le32(&m[6..]) >> 4) & M26;
        h[3] += (le32(&m[9..]) >> 6) & M26;
        h[4] += (le32(&m[12..]) >> 8) | hibit;
        let [h0, h1, h2, h3, h4] = h.map(|x| x as u64);
        let d0 = h0 * r0 + h1 * s4 + h2 * s3 + h3 * s2 + h4 * s1;
        let mut d1 = h0 * r1 + h1 * r0 + h2 * s4 + h3 * s3 + h4 * s2;
        let mut d2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s4 + h4 * s3;
        let mut d3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s4;
        let mut d4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;
        d1 += d0 >> 26;
        h[0] = d0 as u32 & M26;
        d2 += d1 >> 26;
        h[1] = d1 as u32 & M26;
        d3 += d2 >> 26;
        h[2] = d2 as u32 & M26;
        d4 += d3 >> 26;
        h[3] = d3 as u32 & M26;
        h[4] = d4 as u32 & M26;
        h[0] += (d4 >> 26) as u32 * 5;
        h[1] += h[0] >> 26;
        h[0] &= M26;
    }

    pub fn update(&mut self, mut data: &[u8]) {
        if self.used > 0 {
            let take = (16 - self.used).min(data.len());
            self.buf[self.used..self.used + take].copy_from_slice(&data[..take]);
            self.used += take;
            data = &data[take..];
            if self.used < 16 {
                return;
            }
            let b = self.buf;
            self.block(&b, 1 << 24);
            self.used = 0;
        }
        let (blocks, rest) = data.as_chunks::<16>();
        for b in blocks {
            self.block(b, 1 << 24);
        }
        self.buf[..rest.len()].copy_from_slice(rest);
        self.used = rest.len();
    }

    pub fn finish(mut self) -> [u8; 16] {
        if self.used > 0 {
            let mut b = [0u8; 16];
            b[..self.used].copy_from_slice(&self.buf[..self.used]);
            b[self.used] = 1;
            self.block(&b, 0);
        }
        let h = &mut self.h;
        let mut c;
        c = h[1] >> 26;
        h[1] &= M26;
        h[2] += c;
        c = h[2] >> 26;
        h[2] &= M26;
        h[3] += c;
        c = h[3] >> 26;
        h[3] &= M26;
        h[4] += c;
        c = h[4] >> 26;
        h[4] &= M26;
        h[0] += c * 5;
        c = h[0] >> 26;
        h[0] &= M26;
        h[1] += c;

        // g = h - p, kept only if it did not go negative.
        let mut g = [0u32; 5];
        g[0] = h[0] + 5;
        c = g[0] >> 26;
        g[0] &= M26;
        for i in 1..4 {
            g[i] = h[i] + c;
            c = g[i] >> 26;
            g[i] &= M26;
        }
        g[4] = (h[4] + c).wrapping_sub(1 << 26);
        let keep_g = (g[4] >> 31).wrapping_sub(1);
        for i in 0..5 {
            h[i] = (h[i] & !keep_g) | (g[i] & keep_g);
        }

        let w = [
            h[0] | (h[1] << 26),
            (h[1] >> 6) | (h[2] << 20),
            (h[2] >> 12) | (h[3] << 14),
            (h[3] >> 18) | (h[4] << 8),
        ];
        let mut out = [0u8; 16];
        let mut f = 0u64;
        for i in 0..4 {
            f = w[i] as u64 + self.pad[i] as u64 + (f >> 32);
            out[4 * i..4 * i + 4].copy_from_slice(&(f as u32).to_le_bytes());
        }
        out
    }
}

impl Drop for Poly1305 {
    fn drop(&mut self) {
        ct::wipe_u32(&mut self.r);
        ct::wipe_u32(&mut self.h);
        ct::wipe_u32(&mut self.pad);
        ct::wipe(&mut self.buf);
    }
}

#[derive(Clone)]
pub struct ChaCha20Poly1305 {
    key: [u8; 32],
}

impl ChaCha20Poly1305 {
    fn tag(&self, cipher: &ChaCha20, aad: &[u8], ct_bytes: &[u8]) -> [u8; 16] {
        let mut otk = [0u8; 32];
        cipher.apply(0, &mut otk);
        let mut p = Poly1305::new(&otk);
        ct::wipe(&mut otk);
        let zeros = [0u8; 16];
        p.update(aad);
        p.update(&zeros[..(16 - aad.len() % 16) % 16]);
        p.update(ct_bytes);
        p.update(&zeros[..(16 - ct_bytes.len() % 16) % 16]);
        p.update(&(aad.len() as u64).to_le_bytes());
        p.update(&(ct_bytes.len() as u64).to_le_bytes());
        p.finish()
    }
}

impl Aead for ChaCha20Poly1305 {
    const KEY_LEN: usize = 32;

    fn new(key: &[u8]) -> Self {
        ChaCha20Poly1305 {
            key: key.try_into().expect("ChaCha20-Poly1305 key is 32 bytes"),
        }
    }

    fn seal(&self, nonce: &[u8; NONCE_LEN], aad: &[u8], buf: &mut Vec<u8>) {
        let cipher = ChaCha20::new(&self.key, nonce);
        cipher.apply(1, buf);
        let tag = self.tag(&cipher, aad, buf);
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
        let cipher = ChaCha20::new(&self.key, nonce);
        let want = self.tag(&cipher, aad, &buf[..body]);
        if !ct::eq(&want, &buf[body..]) {
            return Err(AeadError);
        }
        buf.truncate(body);
        cipher.apply(1, buf);
        Ok(())
    }
}

impl Drop for ChaCha20Poly1305 {
    fn drop(&mut self) {
        ct::wipe(&mut self.key);
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

    fn seq_key() -> [u8; 32] {
        core::array::from_fn(|i| i as u8)
    }

    // RFC 8439 2.4.2: the "sunscreen" text, which spans a partial block.
    #[test]
    fn rfc_8439_chacha20() {
        let nonce: [u8; 12] = hex("000000000000004a00000000").try_into().unwrap();
        let mut data = b"Ladies and Gentlemen of the class of '99: If I could offer you only \
one tip for the future, sunscreen would be it."
            .to_vec();
        ChaCha20::new(&seq_key(), &nonce).apply(1, &mut data);
        assert_eq!(
            data,
            hex(
                "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0b
                 f91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d8
                 07ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab7793736
                 5af90bbf74a35be6b40b8eedf2785e42874d"
            )
        );
    }

    // RFC 8439 2.5.2.
    #[test]
    fn rfc_8439_poly1305() {
        let key: [u8; 32] = hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
            .try_into()
            .unwrap();
        let mut p = Poly1305::new(&key);
        p.update(b"Cryptographic Forum Research Group");
        assert_eq!(p.finish().to_vec(), hex("a8061dc1305136c6c22b8baf0c0127a9"));
    }

    // RFC 8439 A.3 vectors 6 and 5: the accumulator ends at or just above
    // 2^130 - 5, so only the final conditional subtraction of p gives the
    // right tag, and the addition of s must carry across all four words.
    #[test]
    fn poly1305_reduces_values_just_above_p() {
        let mut key = [0u8; 32];
        key[0] = 2;
        key[16] = 0xff;
        key[17..32].fill(0xff);
        let mut p = Poly1305::new(&key);
        p.update(&hex("02000000000000000000000000000000"));
        assert_eq!(p.finish().to_vec(), hex("03000000000000000000000000000000"));

        let mut key = [0u8; 32];
        key[0] = 2;
        let mut p = Poly1305::new(&key);
        p.update(&[0xff; 16]);
        assert_eq!(p.finish().to_vec(), hex("03000000000000000000000000000000"));
    }

    // RFC 8439 2.8.2.
    #[test]
    fn rfc_8439_aead() {
        let key = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
        let nonce: [u8; 12] = hex("070000004041424344454647").try_into().unwrap();
        let aad = hex("50515253c0c1c2c3c4c5c6c7");
        let plain = b"Ladies and Gentlemen of the class of '99: If I could offer you only \
one tip for the future, sunscreen would be it.";
        let aead = ChaCha20Poly1305::new(&key);
        let mut buf = plain.to_vec();
        aead.seal(&nonce, &aad, &mut buf);
        assert_eq!(
            buf,
            hex(
                "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6
                 3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36
                 92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc
                 3ff4def08e4b7a9de576d26586cec64b6116
                 1ae10b594f09e26a7e902ecbd0600691"
            )
        );
        aead.open(&nonce, &aad, &mut buf).unwrap();
        assert_eq!(buf, plain);
    }

    #[test]
    fn open_rejects_and_leaves_no_plaintext() {
        let aead = ChaCha20Poly1305::new(&[7; 32]);
        let nonce = [1; 12];
        let mut buf = b"secret".to_vec();
        aead.seal(&nonce, b"", &mut buf);
        let sealed = buf.clone();
        buf[0] ^= 1;
        assert_eq!(aead.open(&nonce, b"", &mut buf), Err(AeadError));
        buf[0] ^= 1;
        assert_eq!(buf, sealed);
        assert!(aead.open(&nonce, b"x", &mut buf).is_err());
        let mut short = vec![0; 15];
        assert!(aead.open(&nonce, b"", &mut short).is_err());
    }
}
