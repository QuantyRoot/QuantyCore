//! HMAC (RFC 2104, FIPS 198-1) over any of the SHA-2 hashes.

use super::ct;
use super::sha2::{AnyHash, HashAlg};

#[derive(Clone)]
pub struct Hmac {
    inner: AnyHash,
    outer: AnyHash,
}

impl Hmac {
    pub fn new(alg: HashAlg, key: &[u8]) -> Hmac {
        let block = alg.block_len();
        let mut k = vec![0u8; block];
        if key.len() > block {
            let d = alg.digest(key);
            k[..d.len()].copy_from_slice(&d);
        } else {
            k[..key.len()].copy_from_slice(key);
        }
        let mut inner = alg.new_hasher();
        let mut outer = alg.new_hasher();
        for b in k.iter_mut() {
            *b ^= 0x36;
        }
        inner.update(&k);
        for b in k.iter_mut() {
            *b ^= 0x36 ^ 0x5c;
        }
        outer.update(&k);
        ct::wipe(&mut k);
        Hmac { inner, outer }
    }

    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    pub fn finish(self) -> Vec<u8> {
        let mut inner = self.inner.finish();
        let mut outer = self.outer;
        outer.update(&inner);
        ct::wipe(&mut inner);
        outer.finish()
    }

    /// Compares in constant time against an expected tag of the full
    /// output length.
    pub fn verify(self, tag: &[u8]) -> bool {
        let mut got = self.finish();
        let ok = ct::eq(&got, tag);
        ct::wipe(&mut got);
        ok
    }
}

impl std::fmt::Debug for Hmac {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Hmac({:?})", self.inner.alg())
    }
}

pub fn hmac(alg: HashAlg, key: &[u8], msg: &[u8]) -> Vec<u8> {
    let mut h = Hmac::new(alg, key);
    h.update(msg);
    h.finish()
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

    // RFC 4231 test cases 1, 6 and 7. Case 6 and 7 have keys longer than
    // the SHA-256 block, which must be hashed first; case 7's key is
    // shorter than the SHA-512 block, so the two hashes take different
    // branches on the same key.
    #[test]
    fn rfc_4231() {
        let key6 = [0xaa; 131];
        let cases: [(&[u8], &[u8], [&str; 3]); 3] = [
            (
                &[0x0b; 20],
                b"Hi There",
                [
                    "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
                    "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59c\
faea9ea9076ede7f4af152e8b2fa9cb6",
                    "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde\
daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854",
                ],
            ),
            (
                &key6,
                b"Test Using Larger Than Block-Size Key - Hash Key First",
                [
                    "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
                    "4ece084485813e9088d2c63a041bc5b44f9ef1012a2b588f3cd11f05033ac4c6\
0c2ef6ab4030fe8296248df163f44952",
                    "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352\
6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598",
                ],
            ),
            (
                &key6,
                b"This is a test using a larger than block-size key and a larger \
than block-size data. The key needs to be hashed before being used by the \
HMAC algorithm.",
                [
                    "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
                    "6617178e941f020d351e2f254e8fd32c602420feb0b8fb9adccebb82461e99c5\
a678cc31e799176d3860e6110c46523e",
                    "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944\
b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58",
                ],
            ),
        ];
        for (key, msg, want) in cases {
            for (alg, w) in [HashAlg::Sha256, HashAlg::Sha384, HashAlg::Sha512]
                .into_iter()
                .zip(want)
            {
                assert_eq!(hmac(alg, key, msg), hex(w), "{alg:?}");
                let mut h = Hmac::new(alg, key);
                h.update(msg);
                assert!(h.verify(&hex(w)));
            }
        }
    }

    #[test]
    fn verify_rejects_a_flipped_last_bit() {
        let mut tag = hmac(HashAlg::Sha256, b"k", b"m");
        *tag.last_mut().unwrap() ^= 1;
        let mut h = Hmac::new(HashAlg::Sha256, b"k");
        h.update(b"m");
        assert!(!h.verify(&tag));
    }
}
