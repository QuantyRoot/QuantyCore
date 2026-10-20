//! HKDF (RFC 5869).

use super::ct::Secret;
use super::hmac::Hmac;
use super::sha2::HashAlg;

/// HKDF-Extract. An empty salt means a string of `HashLen` zeros, which
/// HMAC produces by itself because the key is zero padded to a block.
pub fn extract(alg: HashAlg, salt: &[u8], ikm: &[u8]) -> Secret {
    let mut h = Hmac::new(alg, salt);
    h.update(ikm);
    Secret::new(h.finish())
}

/// HKDF-Expand. `None` if more than 255 blocks are asked for, which RFC
/// 5869 forbids because the block counter is one byte.
pub fn expand(alg: HashAlg, prk: &[u8], info: &[u8], len: usize) -> Option<Secret> {
    let hash_len = alg.output_len();
    if len > 255 * hash_len {
        return None;
    }
    let mut out = Secret::zeroed(len);
    let base = Hmac::new(alg, prk);
    let mut prev: Option<Secret> = None;
    for (i, chunk) in out.expose_mut().chunks_mut(hash_len).enumerate() {
        let mut h = base.clone();
        if let Some(p) = &prev {
            h.update(p.expose());
        }
        h.update(info);
        h.update(&[i as u8 + 1]);
        let t = Secret::new(h.finish());
        chunk.copy_from_slice(&t.expose()[..chunk.len()]);
        prev = Some(t);
    }
    Some(out)
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

    // RFC 5869 A.1 (short inputs) and A.3 (empty salt and info).
    #[test]
    fn rfc_5869() {
        let ikm = [0x0b; 22];
        let prk = extract(HashAlg::Sha256, &hex("000102030405060708090a0b0c"), &ikm);
        assert_eq!(
            prk.expose(),
            hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        );
        let okm = expand(
            HashAlg::Sha256,
            prk.expose(),
            &hex("f0f1f2f3f4f5f6f7f8f9"),
            42,
        )
        .unwrap();
        assert_eq!(
            okm.expose(),
            hex(
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
34007208d5b887185865"
            )
        );

        let prk = extract(HashAlg::Sha256, b"", &ikm);
        assert_eq!(
            prk.expose(),
            hex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04")
        );
        let okm = expand(HashAlg::Sha256, prk.expose(), b"", 42).unwrap();
        assert_eq!(
            okm.expose(),
            hex(
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
9d201395faa4b61a96c8"
            )
        );
    }

    #[test]
    fn length_limit_is_255_blocks() {
        assert!(expand(HashAlg::Sha256, &[0; 32], b"", 255 * 32).is_some());
        assert!(expand(HashAlg::Sha256, &[0; 32], b"", 255 * 32 + 1).is_none());
    }
}
