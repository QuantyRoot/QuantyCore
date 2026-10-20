//! SHA3-256, SHA3-512, SHAKE128 and SHAKE256 (FIPS 202), the hashes and
//! extendable output functions under ML-KEM. Keccak has no table
//! lookups and no data dependent branches, so it is constant time as
//! written.

const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

/// The rotation of lane x + 5y in the rho step.
const ROT: [u32; 25] = [
    0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14,
];

fn keccak_f(a: &mut [u64; 25]) {
    for rc in RC {
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                a[x + 5 * y] ^= d;
            }
        }
        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                b[y + 5 * ((2 * x + 3 * y) % 5)] = a[x + 5 * y].rotate_left(ROT[x + 5 * y]);
            }
        }
        for y in 0..5 {
            for x in 0..5 {
                a[x + 5 * y] = b[x + 5 * y] ^ (!b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
            }
        }
        a[0] ^= rc;
    }
}

/// The sponge. Absorbs with `update`, then squeezes with `squeeze`, as
/// often as wanted.
#[derive(Clone)]
pub struct Keccak {
    a: [u64; 25],
    rate: usize,
    pos: usize,
    suffix: u8,
    squeezing: bool,
}

impl Keccak {
    fn new(rate: usize, suffix: u8) -> Keccak {
        Keccak {
            a: [0; 25],
            rate,
            pos: 0,
            suffix,
            squeezing: false,
        }
    }

    pub fn shake128() -> Keccak {
        Keccak::new(168, 0x1f)
    }

    pub fn shake256() -> Keccak {
        Keccak::new(136, 0x1f)
    }

    fn xor_byte(&mut self, i: usize, b: u8) {
        self.a[i / 8] ^= (b as u64) << (8 * (i % 8));
    }

    pub fn update(&mut self, data: &[u8]) {
        assert!(!self.squeezing, "absorb after squeeze");
        for &b in data {
            self.xor_byte(self.pos, b);
            self.pos += 1;
            if self.pos == self.rate {
                keccak_f(&mut self.a);
                self.pos = 0;
            }
        }
    }

    pub fn squeeze(&mut self, out: &mut [u8]) {
        if !self.squeezing {
            self.xor_byte(self.pos, self.suffix);
            self.xor_byte(self.rate - 1, 0x80);
            keccak_f(&mut self.a);
            self.pos = 0;
            self.squeezing = true;
        }
        for o in out {
            if self.pos == self.rate {
                keccak_f(&mut self.a);
                self.pos = 0;
            }
            *o = (self.a[self.pos / 8] >> (8 * (self.pos % 8))) as u8;
            self.pos += 1;
        }
    }
}

impl Drop for Keccak {
    fn drop(&mut self) {
        for w in self.a.iter_mut() {
            *w = 0;
        }
        std::hint::black_box(&mut self.a);
    }
}

pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut k = Keccak::new(136, 0x06);
    k.update(data);
    let mut out = [0; 32];
    k.squeeze(&mut out);
    out
}

pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    let mut k = Keccak::new(72, 0x06);
    k.update(data);
    let mut out = [0; 64];
    k.squeeze(&mut out);
    out
}

pub fn shake128(data: &[u8], out: &mut [u8]) {
    let mut k = Keccak::shake128();
    k.update(data);
    k.squeeze(out);
}

pub fn shake256(data: &[u8], out: &mut [u8]) {
    let mut k = Keccak::shake256();
    k.update(data);
    k.squeeze(out);
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

    // FIPS 202 examples from NIST's example values page: the empty
    // message and "abc".
    #[test]
    fn known_answers() {
        assert_eq!(
            sha3_256(b"").to_vec(),
            hex("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
        );
        assert_eq!(
            sha3_256(b"abc").to_vec(),
            hex("3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532")
        );
        assert_eq!(
            sha3_512(b"abc").to_vec(),
            hex(
                "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e\
                 10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0"
            )
        );
        let mut out = [0u8; 32];
        shake128(b"", &mut out);
        assert_eq!(
            out.to_vec(),
            hex("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26")
        );
        shake256(b"", &mut out);
        assert_eq!(
            out.to_vec(),
            hex("46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f")
        );
    }

    #[test]
    fn squeezing_in_pieces_is_squeezing_at_once() {
        let mut whole = [0u8; 500];
        shake128(b"pieces", &mut whole);
        let mut k = Keccak::shake128();
        k.update(b"pie");
        k.update(b"ces");
        let mut parts = [0u8; 500];
        let (a, rest) = parts.split_at_mut(167);
        let (b, c) = rest.split_at_mut(2);
        k.squeeze(a);
        k.squeeze(b);
        k.squeeze(c);
        assert_eq!(whole, parts);
    }
}
