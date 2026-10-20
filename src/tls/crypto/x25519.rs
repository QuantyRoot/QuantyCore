//! X25519 (RFC 7748).

use super::ct::{self, Secret};
use super::field25519::Fe;
use super::rand;

/// The scalar multiplication of RFC 7748 section 5: clamping, then a
/// Montgomery ladder over all 255 bits with conditional swaps, the same
/// work for every scalar.
pub fn x25519(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let mut k = *scalar;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;

    let x1 = Fe::from_bytes(u);
    let mut x2 = Fe::ONE;
    let mut z2 = Fe::ZERO;
    let mut x3 = x1;
    let mut z3 = Fe::ONE;
    let mut swap = 0u64;
    for t in (0..255).rev() {
        let bit = ((k[t / 8] >> (t % 8)) & 1) as u64;
        swap ^= bit;
        Fe::cswap(&mut x2, &mut x3, swap);
        Fe::cswap(&mut z2, &mut z3, swap);
        swap = bit;

        let a = x2.add(&z2);
        let aa = a.square();
        let b = x2.sub(&z2);
        let bb = b.square();
        let e = aa.sub(&bb);
        let c = x3.add(&z3);
        let d = x3.sub(&z3);
        let da = d.mul(&a);
        let cb = c.mul(&b);
        x3 = da.add(&cb).square();
        z3 = x1.mul(&da.sub(&cb).square());
        x2 = aa.mul(&bb);
        z2 = e.mul(&aa.add(&e.mul_small(121665)));
    }
    Fe::cswap(&mut x2, &mut x3, swap);
    Fe::cswap(&mut z2, &mut z3, swap);
    let out = x2.mul(&z2.invert()).to_bytes();
    ct::wipe(&mut k);
    for f in [&mut x2, &mut z2, &mut x3, &mut z3] {
        f.wipe();
    }
    out
}

pub const BASE_POINT: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
};

/// An X25519 private key.
pub struct PrivateKey(Secret);

impl PrivateKey {
    pub fn generate() -> std::io::Result<PrivateKey> {
        let mut k = Secret::zeroed(32);
        rand::fill(k.expose_mut())?;
        Ok(PrivateKey(k))
    }

    pub fn from_bytes(b: &[u8; 32]) -> PrivateKey {
        PrivateKey(Secret::from(&b[..]))
    }

    fn scalar(&self) -> &[u8; 32] {
        self.0.expose().try_into().unwrap()
    }

    pub fn public_key(&self) -> [u8; 32] {
        x25519(self.scalar(), &BASE_POINT)
    }

    /// `None` when the result is all zeros, which happens exactly when the
    /// peer sent a point of small order. RFC 8446 section 7.4.2 requires
    /// the handshake to abort then, because the "shared" secret would be
    /// known to anyone.
    pub fn diffie_hellman(&self, peer: &[u8; 32]) -> Option<Secret> {
        let s = Secret::new(x25519(self.scalar(), peer).to_vec());
        if ct::eq(s.expose(), &[0; 32]) {
            None
        } else {
            Some(s)
        }
    }
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("x25519::PrivateKey")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(s: &str) -> [u8; 32] {
        core::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
    }

    // RFC 7748 5.2, both vectors; the second has the top bit of u set,
    // which must be ignored.
    #[test]
    fn rfc_7748_vectors() {
        let cases = [
            (
                "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
                "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
                "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
            ),
            (
                "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
                "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
                "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
            ),
        ];
        for (k, u, out) in cases {
            assert_eq!(x25519(&hex32(k), &hex32(u)), hex32(out));
        }
    }

    // RFC 7748 5.2, the iterated vector after 1 and 1000 rounds. The
    // million rounds take minutes and add nothing the thousand do not.
    #[test]
    fn rfc_7748_iterated() {
        let mut k = BASE_POINT;
        let mut u = BASE_POINT;
        for i in 1..=1000 {
            let r = x25519(&k, &u);
            u = k;
            k = r;
            if i == 1 {
                assert_eq!(
                    k,
                    hex32("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079")
                );
            }
        }
        assert_eq!(
            k,
            hex32("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51")
        );
    }

    // RFC 7748 6.1: both sides arrive at the same secret.
    #[test]
    fn rfc_7748_key_agreement() {
        let a = PrivateKey::from_bytes(&hex32(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        ));
        let b = PrivateKey::from_bytes(&hex32(
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
        ));
        assert_eq!(
            a.public_key(),
            hex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
        let shared = hex32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
        assert_eq!(a.diffie_hellman(&b.public_key()).unwrap().expose(), shared);
        assert_eq!(b.diffie_hellman(&a.public_key()).unwrap().expose(), shared);
    }

    #[test]
    fn small_order_point_is_refused() {
        let a = PrivateKey::from_bytes(&[0x42; 32]);
        assert!(a.diffie_hellman(&[0; 32]).is_none());
        let mut one = [0u8; 32];
        one[0] = 1;
        assert!(a.diffie_hellman(&one).is_none());
    }
}
