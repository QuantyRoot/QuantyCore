//! PEM (RFC 7468): base64 between BEGIN and END lines.

/// Every block in `text` with the given label, decoded. Blocks with other
/// labels are skipped; a block whose base64 is broken is an error rather
/// than silently dropped, so a damaged trust store is noticed.
pub fn decode_all(text: &str, label: &str) -> Result<Vec<Vec<u8>>, &'static str> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(i) = rest.find(&begin) {
        let body_start = i + begin.len();
        let j = rest[body_start..]
            .find(&end)
            .ok_or("PEM block without END")?;
        let body = &rest[body_start..body_start + j];
        out.push(base64(body)?);
        rest = &rest[body_start + j + end.len()..];
    }
    Ok(out)
}

/// The first block with any of `labels`, with its label.
pub fn decode_first<'l>(
    text: &str,
    labels: &[&'l str],
) -> Result<Option<(&'l str, Vec<u8>)>, &'static str> {
    let mut best: Option<(usize, &'l str)> = None;
    for l in labels {
        if let Some(i) = text.find(&format!("-----BEGIN {l}-----")) {
            if best.is_none_or(|(b, _)| i < b) {
                best = Some((i, l));
            }
        }
    }
    let Some((i, label)) = best else {
        return Ok(None);
    };
    let blocks = decode_all(&text[i..], label)?;
    Ok(blocks.into_iter().next().map(|b| (label, b)))
}

pub fn encode(label: &str, der: &[u8]) -> String {
    let mut s = format!("-----BEGIN {label}-----\n");
    let b64 = to_base64(der);
    for line in b64.as_bytes().chunks(64) {
        s.push_str(std::str::from_utf8(line).unwrap());
        s.push('\n');
    }
    s.push_str(&format!("-----END {label}-----\n"));
    s
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn base64(s: &str) -> Result<Vec<u8>, &'static str> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let (mut acc, mut bits, mut pad) = (0u32, 0, 0);
    for c in s.bytes() {
        if c.is_ascii_whitespace() {
            continue;
        }
        if c == b'=' {
            pad += 1;
            continue;
        }
        if pad > 0 {
            return Err("base64 data after padding");
        }
        let v = ALPHABET.iter().position(|&a| a == c).ok_or("not base64")? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    if pad > 2 || bits >= 6 || acc & ((1 << bits) - 1) != 0 {
        return Err("base64 padding");
    }
    Ok(out)
}

fn to_base64(data: &[u8]) -> String {
    let mut s = String::with_capacity(data.len().div_ceil(3) * 4);
    for c in data.chunks(3) {
        let n = (c[0] as u32) << 16
            | (*c.get(1).unwrap_or(&0) as u32) << 8
            | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                s.push(ALPHABET[(n >> (18 - 6 * i)) as usize & 63] as char);
            } else {
                s.push('=');
            }
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_rfc_4648_vectors() {
        for (plain, enc) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(to_base64(plain.as_bytes()), enc);
            assert_eq!(base64(enc).unwrap(), plain.as_bytes());
        }
        assert!(base64("Zm9=v").is_err());
        assert!(base64("Zh==").is_err());
        let pem = encode("CERTIFICATE", &[1, 2, 3, 250]);
        let both = format!("junk\n{pem}{}", encode("OTHER", &[9]));
        assert_eq!(
            decode_all(&both, "CERTIFICATE").unwrap(),
            vec![vec![1, 2, 3, 250]]
        );
    }
}
