//! SHA-256, SHA-384 and SHA-512 (FIPS 180-4).
//!
//! The input to a hash is often secret (keys inside HMAC, the premaster
//! secret), but SHA-2 is only additions, rotations and boolean operations
//! on words, with no data dependent branch or index, so it is constant
//! time as written. Only the message length decides the number of blocks,
//! and lengths are public in every use here.

use super::ct;

/// A hash function with a fixed output.
pub trait Hash: Clone + Default {
    const OUTPUT_LEN: usize;
    const BLOCK_LEN: usize;

    fn update(&mut self, data: &[u8]);

    /// Writes the digest to `out`, which must be `OUTPUT_LEN` long.
    fn finish_into(self, out: &mut [u8]);

    fn finish(self) -> Vec<u8> {
        let mut out = vec![0; Self::OUTPUT_LEN];
        self.finish_into(&mut out);
        out
    }

    fn digest(data: &[u8]) -> Vec<u8> {
        let mut h = Self::default();
        h.update(data);
        h.finish()
    }
}

const K256: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const K512: [u64; 80] = [
    0x428a2f98d728ae22,
    0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f,
    0xe9b5dba58189dbbc,
    0x3956c25bf348b538,
    0x59f111f1b605d019,
    0x923f82a4af194f9b,
    0xab1c5ed5da6d8118,
    0xd807aa98a3030242,
    0x12835b0145706fbe,
    0x243185be4ee4b28c,
    0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f,
    0x80deb1fe3b1696b1,
    0x9bdc06a725c71235,
    0xc19bf174cf692694,
    0xe49b69c19ef14ad2,
    0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5,
    0x240ca1cc77ac9c65,
    0x2de92c6f592b0275,
    0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4,
    0x76f988da831153b5,
    0x983e5152ee66dfab,
    0xa831c66d2db43210,
    0xb00327c898fb213f,
    0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2,
    0xd5a79147930aa725,
    0x06ca6351e003826f,
    0x142929670a0e6e70,
    0x27b70a8546d22ffc,
    0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed,
    0x53380d139d95b3df,
    0x650a73548baf63de,
    0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6,
    0x92722c851482353b,
    0xa2bfe8a14cf10364,
    0xa81a664bbc423001,
    0xc24b8b70d0f89791,
    0xc76c51a30654be30,
    0xd192e819d6ef5218,
    0xd69906245565a910,
    0xf40e35855771202a,
    0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8,
    0x1e376c085141ab53,
    0x2748774cdf8eeb99,
    0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63,
    0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373,
    0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc,
    0x78a5636f43172f60,
    0x84c87814a1f0ab72,
    0x8cc702081a6439ec,
    0x90befffa23631e28,
    0xa4506cebde82bde9,
    0xbef9a3f7b2c67915,
    0xc67178f2e372532b,
    0xca273eceea26619c,
    0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e,
    0xf57d4f7fee6ed178,
    0x06f067aa72176fba,
    0x0a637dc5a2c898a6,
    0x113f9804bef90dae,
    0x1b710b35131c471b,
    0x28db77f523047d84,
    0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc,
    0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6,
    0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec,
    0x6c44198c4a475817,
];

fn compress256(state: &mut [u32; 8], block: &[u8]) {
    let mut w = [0u32; 64];
    for (i, c) in block.as_chunks::<4>().0.iter().enumerate() {
        w[i] = u32::from_be_bytes(*c);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K256[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *s = s.wrapping_add(v);
    }
    ct::wipe_u32(&mut w);
}

fn compress512(state: &mut [u64; 8], block: &[u8]) {
    let mut w = [0u64; 80];
    for (i, c) in block.as_chunks::<8>().0.iter().enumerate() {
        w[i] = u64::from_be_bytes(*c);
    }
    for i in 16..80 {
        let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
        let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for i in 0..80 {
        let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K512[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *s = s.wrapping_add(v);
    }
    ct::wipe_u64(&mut w);
}

/// Shared block buffering. `B` is the block length in bytes.
#[derive(Clone)]
struct Buffer<const B: usize> {
    block: [u8; B],
    used: usize,
    /// Bytes absorbed so far. SHA-512 allows up to 2^128 bits; a `u128`
    /// byte count covers every message that fits in memory either way.
    total: u128,
}

impl<const B: usize> Default for Buffer<B> {
    fn default() -> Self {
        Buffer {
            block: [0; B],
            used: 0,
            total: 0,
        }
    }
}

impl<const B: usize> Buffer<B> {
    fn absorb(&mut self, mut data: &[u8], mut compress: impl FnMut(&[u8])) {
        self.total += data.len() as u128;
        if self.used > 0 {
            let take = (B - self.used).min(data.len());
            self.block[self.used..self.used + take].copy_from_slice(&data[..take]);
            self.used += take;
            data = &data[take..];
            if self.used < B {
                return;
            }
            compress(&self.block);
            self.used = 0;
        }
        let (blocks, rest) = data.as_chunks::<B>();
        for b in blocks {
            compress(b);
        }
        self.block[..rest.len()].copy_from_slice(rest);
        self.used = rest.len();
    }

    /// Appends the padding of FIPS 180-4 section 5.1, with a length field
    /// of `len_bytes` bytes.
    fn pad(&mut self, len_bytes: usize, mut compress: impl FnMut(&[u8])) {
        let bits = self.total.wrapping_mul(8);
        self.block[self.used] = 0x80;
        self.used += 1;
        if self.used > B - len_bytes {
            self.block[self.used..].fill(0);
            compress(&self.block);
            self.used = 0;
        }
        self.block[self.used..B - len_bytes].fill(0);
        let be = bits.to_be_bytes();
        self.block[B - len_bytes..].copy_from_slice(&be[16 - len_bytes..]);
        compress(&self.block);
        ct::wipe(&mut self.block);
    }
}

impl<const B: usize> Drop for Buffer<B> {
    fn drop(&mut self) {
        ct::wipe(&mut self.block);
    }
}

#[derive(Clone)]
pub struct Sha256 {
    state: [u32; 8],
    buf: Buffer<64>,
}

impl Default for Sha256 {
    fn default() -> Self {
        Sha256 {
            state: [
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
                0x5be0cd19,
            ],
            buf: Buffer::default(),
        }
    }
}

impl Drop for Sha256 {
    fn drop(&mut self) {
        ct::wipe_u32(&mut self.state);
    }
}

impl Hash for Sha256 {
    const OUTPUT_LEN: usize = 32;
    const BLOCK_LEN: usize = 64;

    fn update(&mut self, data: &[u8]) {
        let state = &mut self.state;
        self.buf.absorb(data, |b| compress256(state, b));
    }

    fn finish_into(mut self, out: &mut [u8]) {
        let state = &mut self.state;
        self.buf.pad(8, |b| compress256(state, b));
        for (o, w) in out.as_chunks_mut::<4>().0.iter_mut().zip(self.state) {
            o.copy_from_slice(&w.to_be_bytes());
        }
    }
}

#[derive(Clone)]
struct Sha512Core {
    state: [u64; 8],
    buf: Buffer<128>,
}

impl Sha512Core {
    fn new(iv: [u64; 8]) -> Self {
        Sha512Core {
            state: iv,
            buf: Buffer::default(),
        }
    }
    fn update(&mut self, data: &[u8]) {
        let state = &mut self.state;
        self.buf.absorb(data, |b| compress512(state, b));
    }
    fn finish_into(&mut self, out: &mut [u8]) {
        let state = &mut self.state;
        self.buf.pad(16, |b| compress512(state, b));
        let mut full = [0u8; 64];
        for (o, w) in full.as_chunks_mut::<8>().0.iter_mut().zip(self.state) {
            o.copy_from_slice(&w.to_be_bytes());
        }
        out.copy_from_slice(&full[..out.len()]);
        ct::wipe(&mut full);
    }
}

impl Drop for Sha512Core {
    fn drop(&mut self) {
        ct::wipe_u64(&mut self.state);
    }
}

#[derive(Clone)]
pub struct Sha512(Sha512Core);

impl Default for Sha512 {
    fn default() -> Self {
        Sha512(Sha512Core::new([
            0x6a09e667f3bcc908,
            0xbb67ae8584caa73b,
            0x3c6ef372fe94f82b,
            0xa54ff53a5f1d36f1,
            0x510e527fade682d1,
            0x9b05688c2b3e6c1f,
            0x1f83d9abfb41bd6b,
            0x5be0cd19137e2179,
        ]))
    }
}

impl Hash for Sha512 {
    const OUTPUT_LEN: usize = 64;
    const BLOCK_LEN: usize = 128;
    fn update(&mut self, data: &[u8]) {
        self.0.update(data)
    }
    fn finish_into(mut self, out: &mut [u8]) {
        self.0.finish_into(&mut out[..64])
    }
}

#[derive(Clone)]
pub struct Sha384(Sha512Core);

impl Default for Sha384 {
    fn default() -> Self {
        Sha384(Sha512Core::new([
            0xcbbb9d5dc1059ed8,
            0x629a292a367cd507,
            0x9159015a3070dd17,
            0x152fecd8f70e5939,
            0x67332667ffc00b31,
            0x8eb44a8768581511,
            0xdb0c2e0d64f98fa7,
            0x47b5481dbefa4fa4,
        ]))
    }
}

impl Hash for Sha384 {
    const OUTPUT_LEN: usize = 48;
    const BLOCK_LEN: usize = 128;
    fn update(&mut self, data: &[u8]) {
        self.0.update(data)
    }
    fn finish_into(mut self, out: &mut [u8]) {
        self.0.finish_into(&mut out[..48])
    }
}

/// A hash chosen at run time, as TLS chooses it per cipher suite.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HashAlg {
    Sha256,
    Sha384,
    Sha512,
}

impl HashAlg {
    pub fn output_len(self) -> usize {
        match self {
            HashAlg::Sha256 => Sha256::OUTPUT_LEN,
            HashAlg::Sha384 => Sha384::OUTPUT_LEN,
            HashAlg::Sha512 => Sha512::OUTPUT_LEN,
        }
    }
    pub fn block_len(self) -> usize {
        match self {
            HashAlg::Sha256 => Sha256::BLOCK_LEN,
            HashAlg::Sha384 | HashAlg::Sha512 => Sha512::BLOCK_LEN,
        }
    }
    pub fn new_hasher(self) -> AnyHash {
        match self {
            HashAlg::Sha256 => AnyHash::Sha256(Sha256::default()),
            HashAlg::Sha384 => AnyHash::Sha384(Sha384::default()),
            HashAlg::Sha512 => AnyHash::Sha512(Sha512::default()),
        }
    }
    pub fn digest(self, data: &[u8]) -> Vec<u8> {
        let mut h = self.new_hasher();
        h.update(data);
        h.finish()
    }
}

#[derive(Clone)]
pub enum AnyHash {
    Sha256(Sha256),
    Sha384(Sha384),
    Sha512(Sha512),
}

impl AnyHash {
    pub fn alg(&self) -> HashAlg {
        match self {
            AnyHash::Sha256(_) => HashAlg::Sha256,
            AnyHash::Sha384(_) => HashAlg::Sha384,
            AnyHash::Sha512(_) => HashAlg::Sha512,
        }
    }
    pub fn update(&mut self, data: &[u8]) {
        match self {
            AnyHash::Sha256(h) => h.update(data),
            AnyHash::Sha384(h) => h.update(data),
            AnyHash::Sha512(h) => h.update(data),
        }
    }
    pub fn finish(self) -> Vec<u8> {
        match self {
            AnyHash::Sha256(h) => h.finish(),
            AnyHash::Sha384(h) => h.finish(),
            AnyHash::Sha512(h) => h.finish(),
        }
    }
    /// The digest of everything so far, without ending the hash. TLS needs
    /// this for the transcript hash at several points of one handshake.
    pub fn peek(&self) -> Vec<u8> {
        self.clone().finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // FIPS 180-4 examples (csrc.nist.gov, "Examples with Intermediate
    // Values"): one block, two blocks, and the million `a`.
    const ABC: &[u8] = b"abc";
    const TWO_256: &[u8] = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    const TWO_512: &[u8] = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn\
hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";

    #[test]
    fn fips_180_4_examples() {
        let cases: [(HashAlg, &[u8], &str); 6] = [
            (
                HashAlg::Sha256,
                ABC,
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                HashAlg::Sha256,
                TWO_256,
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
            (
                HashAlg::Sha384,
                ABC,
                "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed\
8086072ba1e7cc2358baeca134c825a7",
            ),
            (
                HashAlg::Sha384,
                TWO_512,
                "09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa08086e3b0f712\
fcc7c71a557e2db966c3e9fa91746039",
            ),
            (
                HashAlg::Sha512,
                ABC,
                "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
            ),
            (
                HashAlg::Sha512,
                TWO_512,
                "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018\
501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
            ),
        ];
        for (alg, msg, want) in cases {
            assert_eq!(alg.digest(msg), hex(want), "{alg:?} {msg:?}");
        }
    }

    #[test]
    fn million_a_fed_in_odd_pieces() {
        let want = [
            (
                HashAlg::Sha256,
                "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
            ),
            (
                HashAlg::Sha512,
                "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb\
de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b",
            ),
        ];
        let chunk = [b'a'; 997];
        for (alg, want) in want {
            let mut h = alg.new_hasher();
            let mut left = 1_000_000;
            while left > 0 {
                let n = left.min(chunk.len());
                h.update(&chunk[..n]);
                left -= n;
            }
            assert_eq!(h.finish(), hex(want), "{alg:?}");
        }
    }
}
