//! HPACK, the header compression of HTTP/2 (RFC 7541).
//!
//! The encoder never inserts into the dynamic table. That is valid HPACK,
//! keeps the encoder stateless, and costs a few bytes on repeated headers.
//!
//! The Huffman code of Appendix B is canonical: sorting symbols by code
//! length, then by value, and counting upward reproduces the published
//! codes. So only the 257 lengths are stored and the codes are derived.

use std::collections::VecDeque;

/// Every one of these is a COMPRESSION_ERROR in HTTP/2 and ends the
/// connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HpackError {
    Truncated,
    IntegerOverflow,
    BadIndex(usize),
    HuffmanEos,
    HuffmanPadding,
    TableSizeTooLarge(usize),
    LateTableSizeUpdate,
    HeaderListTooLarge,
}

impl std::fmt::Display for HpackError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HpackError::Truncated => f.write_str("header block truncated"),
            HpackError::IntegerOverflow => f.write_str("integer too large"),
            HpackError::BadIndex(i) => write!(f, "no table entry {i}"),
            HpackError::HuffmanEos => f.write_str("EOS inside a Huffman string"),
            HpackError::HuffmanPadding => f.write_str("invalid Huffman padding"),
            HpackError::TableSizeTooLarge(n) => write!(f, "table size update to {n}"),
            HpackError::LateTableSizeUpdate => f.write_str("table size update after a field"),
            HpackError::HeaderListTooLarge => f.write_str("header list too large"),
        }
    }
}

impl std::error::Error for HpackError {}

/// Every legitimate length, index and table size fits far below this, and
/// capping here keeps all later arithmetic free of overflow.
pub const MAX_INTEGER: u64 = u32::MAX as u64;

/// `flags` holds the bits above the `n` bit prefix in the first byte.
pub fn encode_integer(value: u64, n: u8, flags: u8, out: &mut Vec<u8>) {
    debug_assert!((1..=8).contains(&n));
    let max = (1u64 << n) - 1;
    debug_assert!(u64::from(flags) & max == 0, "flags overlap the prefix");
    if value < max {
        out.push(flags | value as u8);
        return;
    }
    out.push(flags | max as u8);
    let mut rest = value - max;
    while rest >= 128 {
        out.push((rest % 128) as u8 | 0x80);
        rest /= 128;
    }
    out.push(rest as u8);
}

pub fn decode_integer(input: &[u8], n: u8) -> Result<(u64, usize), HpackError> {
    debug_assert!((1..=8).contains(&n));
    let max = (1u64 << n) - 1;
    let first = *input.first().ok_or(HpackError::Truncated)?;
    let mut value = u64::from(first) & max;
    if value < max {
        return Ok((value, 1));
    }
    let mut shift = 0u32;
    for (i, &byte) in input[1..].iter().enumerate() {
        // a sixth continuation byte is either overflow or endless padding
        if shift > 28 {
            return Err(HpackError::IntegerOverflow);
        }
        value += u64::from(byte & 0x7f) << shift;
        if value > MAX_INTEGER {
            return Err(HpackError::IntegerOverflow);
        }
        if byte & 0x80 == 0 {
            return Ok((value, i + 2));
        }
        shift += 7;
    }
    Err(HpackError::Truncated)
}

/// RFC 7541 Appendix B, symbols 0 to 255 and EOS.
#[rustfmt::skip]
const HUFFMAN_LENGTHS: [u8; 257] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
    28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6,
    5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10,
    13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6,
    15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6, 6, 5,
    6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28,
    20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
    24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
    22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
    21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
    26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
    19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
    20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
    26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
    30,
];

const EOS: u16 = 256;
const MAX_CODE_LEN: usize = 30;

struct Canonical {
    codes: [u32; 257],
    count: [u32; MAX_CODE_LEN + 1],
    first: [u32; MAX_CODE_LEN + 1],
    offset: [usize; MAX_CODE_LEN + 1],
    /// ordered by length, then by value
    symbols: [u16; 257],
}

const HUFFMAN: Canonical = build_canonical();

const fn build_canonical() -> Canonical {
    let mut count = [0u32; MAX_CODE_LEN + 1];
    let mut s = 0;
    while s < 257 {
        count[HUFFMAN_LENGTHS[s] as usize] += 1;
        s += 1;
    }
    let mut first = [0u32; MAX_CODE_LEN + 1];
    let mut offset = [0usize; MAX_CODE_LEN + 1];
    let mut code = 0u32;
    let mut len = 1;
    while len <= MAX_CODE_LEN {
        code = (code + count[len - 1]) << 1;
        first[len] = code;
        offset[len] = offset[len - 1] + count[len - 1] as usize;
        len += 1;
    }
    let mut symbols = [0u16; 257];
    let mut codes = [0u32; 257];
    let mut next = offset;
    let mut len = 1;
    while len <= MAX_CODE_LEN {
        let mut s = 0;
        while s < 257 {
            if HUFFMAN_LENGTHS[s] as usize == len {
                let k = next[len];
                symbols[k] = s as u16;
                codes[s] = first[len] + (k - offset[len]) as u32;
                next[len] += 1;
            }
            s += 1;
        }
        len += 1;
    }
    Canonical {
        codes,
        count,
        first,
        offset,
        symbols,
    }
}

pub fn huffman_encoded_len(input: &[u8]) -> usize {
    let bits: usize = input
        .iter()
        .map(|&b| HUFFMAN_LENGTHS[b as usize] as usize)
        .sum();
    bits.div_ceil(8)
}

pub fn huffman_encode(input: &[u8], out: &mut Vec<u8>) {
    let mut acc: u64 = 0;
    let mut bits: u32 = 0;
    for &b in input {
        let len = u32::from(HUFFMAN_LENGTHS[b as usize]);
        acc = (acc << len) | u64::from(HUFFMAN.codes[b as usize]);
        bits += len;
        while bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
        acc &= (1 << bits) - 1;
    }
    if bits > 0 {
        let pad = 8 - bits;
        out.push(((acc << pad) | ((1 << pad) - 1)) as u8);
    }
}

pub fn huffman_decode(input: &[u8]) -> Result<Vec<u8>, HpackError> {
    let mut out = Vec::with_capacity(input.len() * 8 / 5);
    let mut code: u32 = 0;
    let mut len: usize = 0;
    for &byte in input {
        for bit in (0..8).rev() {
            code = (code << 1) | u32::from((byte >> bit) & 1);
            len += 1;
            let first = HUFFMAN.first[len];
            if code >= first && code - first < HUFFMAN.count[len] {
                let sym = HUFFMAN.symbols[HUFFMAN.offset[len] + (code - first) as usize];
                if sym == EOS {
                    return Err(HpackError::HuffmanEos);
                }
                out.push(sym as u8);
                code = 0;
                len = 0;
            } else if len == MAX_CODE_LEN {
                // unreachable with a complete code; a broken table should
                // fail here rather than index out of bounds
                return Err(HpackError::HuffmanEos);
            }
        }
    }
    // the rest must be a prefix of EOS: at most seven bits, all ones
    if len > 7 || code != (1 << len) - 1 {
        return Err(HpackError::HuffmanPadding);
    }
    Ok(out)
}

/// RFC 7541 Appendix A. Index 1 is the first entry.
#[rustfmt::skip]
const STATIC_TABLE: [(&[u8], &[u8]); 61] = [
    (b":authority", b""),
    (b":method", b"GET"),
    (b":method", b"POST"),
    (b":path", b"/"),
    (b":path", b"/index.html"),
    (b":scheme", b"http"),
    (b":scheme", b"https"),
    (b":status", b"200"),
    (b":status", b"204"),
    (b":status", b"206"),
    (b":status", b"304"),
    (b":status", b"400"),
    (b":status", b"404"),
    (b":status", b"500"),
    (b"accept-charset", b""),
    (b"accept-encoding", b"gzip, deflate"),
    (b"accept-language", b""),
    (b"accept-ranges", b""),
    (b"accept", b""),
    (b"access-control-allow-origin", b""),
    (b"age", b""),
    (b"allow", b""),
    (b"authorization", b""),
    (b"cache-control", b""),
    (b"content-disposition", b""),
    (b"content-encoding", b""),
    (b"content-language", b""),
    (b"content-length", b""),
    (b"content-location", b""),
    (b"content-range", b""),
    (b"content-type", b""),
    (b"cookie", b""),
    (b"date", b""),
    (b"etag", b""),
    (b"expect", b""),
    (b"expires", b""),
    (b"from", b""),
    (b"host", b""),
    (b"if-match", b""),
    (b"if-modified-since", b""),
    (b"if-none-match", b""),
    (b"if-range", b""),
    (b"if-unmodified-since", b""),
    (b"last-modified", b""),
    (b"link", b""),
    (b"location", b""),
    (b"max-forwards", b""),
    (b"proxy-authenticate", b""),
    (b"proxy-authorization", b""),
    (b"range", b""),
    (b"referer", b""),
    (b"refresh", b""),
    (b"retry-after", b""),
    (b"server", b""),
    (b"set-cookie", b""),
    (b"strict-transport-security", b""),
    (b"transfer-encoding", b""),
    (b"user-agent", b""),
    (b"vary", b""),
    (b"via", b""),
    (b"www-authenticate", b""),
];

/// RFC 7541 section 4.1.
const ENTRY_OVERHEAD: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
    /// "Never indexed": intermediaries must not compress it either.
    pub sensitive: bool,
}

/// One per connection and direction.
pub struct Decoder {
    table: VecDeque<(Vec<u8>, Vec<u8>)>,
    size: usize,
    /// set by the peer's size updates
    max_size: usize,
    /// what this side advertised in SETTINGS_HEADER_TABLE_SIZE
    limit: usize,
    /// counted the way RFC 7540 counts SETTINGS_MAX_HEADER_LIST_SIZE
    max_list_size: usize,
}

impl Decoder {
    pub fn new(table_size: usize, max_list_size: usize) -> Self {
        Decoder {
            table: VecDeque::new(),
            size: 0,
            max_size: table_size,
            limit: table_size,
            max_list_size,
        }
    }

    pub fn table_size(&self) -> usize {
        self.size
    }

    pub fn table_len(&self) -> usize {
        self.table.len()
    }

    fn entry(&self, index: usize) -> Result<(&[u8], &[u8]), HpackError> {
        match index {
            0 => Err(HpackError::BadIndex(0)),
            1..=61 => Ok(STATIC_TABLE[index - 1]),
            _ => self
                .table
                .get(index - 62)
                .map(|(n, v)| (n.as_slice(), v.as_slice()))
                .ok_or(HpackError::BadIndex(index)),
        }
    }

    fn evict_to(&mut self, max: usize) {
        while self.size > max {
            let (n, v) = self.table.pop_back().expect("size > 0 implies an entry");
            self.size -= n.len() + v.len() + ENTRY_OVERHEAD;
        }
    }

    fn insert(&mut self, name: Vec<u8>, value: Vec<u8>) {
        let cost = name.len() + value.len() + ENTRY_OVERHEAD;
        if cost > self.max_size {
            // section 4.4: not an error, the table just ends up empty
            self.table.clear();
            self.size = 0;
            return;
        }
        self.evict_to(self.max_size - cost);
        self.size += cost;
        self.table.push_front((name, value));
    }

    /// `block` is a HEADERS frame's fragment joined with its CONTINUATION
    /// frames.
    pub fn decode(&mut self, block: &[u8]) -> Result<Vec<Header>, HpackError> {
        let mut out = Vec::new();
        let mut list_size = 0usize;
        let mut pos = 0;
        while pos < block.len() {
            let b = block[pos];
            let rest = &block[pos..];
            if b & 0x80 != 0 {
                let (index, used) = decode_integer(rest, 7)?;
                pos += used;
                let (n, v) = self.entry(index as usize)?;
                out.push(Header {
                    name: n.to_vec(),
                    value: v.to_vec(),
                    sensitive: false,
                });
            } else if b & 0x20 != 0 && b & 0x40 == 0 {
                if !out.is_empty() {
                    return Err(HpackError::LateTableSizeUpdate);
                }
                let (size, used) = decode_integer(rest, 5)?;
                pos += used;
                let size = size as usize;
                if size > self.limit {
                    return Err(HpackError::TableSizeTooLarge(size));
                }
                self.max_size = size;
                self.evict_to(size);
                continue;
            } else {
                // literal: 01 adds to the table, 0000 does not, 0001 is
                // never indexed
                let indexing = b & 0x40 != 0;
                let prefix = if indexing { 6 } else { 4 };
                let (index, used) = decode_integer(rest, prefix)?;
                pos += used;
                let name = if index == 0 {
                    let (s, used) = decode_string(&block[pos..])?;
                    pos += used;
                    s
                } else {
                    self.entry(index as usize)?.0.to_vec()
                };
                let (value, used) = decode_string(&block[pos..])?;
                pos += used;
                if indexing {
                    self.insert(name.clone(), value.clone());
                }
                out.push(Header {
                    name,
                    value,
                    sensitive: !indexing && b & 0x10 != 0,
                });
            }
            let last = out.last().expect("a field was just pushed");
            list_size += last.name.len() + last.value.len() + ENTRY_OVERHEAD;
            if list_size > self.max_list_size {
                return Err(HpackError::HeaderListTooLarge);
            }
        }
        Ok(out)
    }
}

fn decode_string(input: &[u8]) -> Result<(Vec<u8>, usize), HpackError> {
    let first = *input.first().ok_or(HpackError::Truncated)?;
    let (len, used) = decode_integer(input, 7)?;
    let len = len as usize;
    let data = input.get(used..used + len).ok_or(HpackError::Truncated)?;
    let s = if first & 0x80 != 0 {
        huffman_decode(data)?
    } else {
        data.to_vec()
    };
    Ok((s, used + len))
}

fn encode_string(s: &[u8], out: &mut Vec<u8>) {
    let huff = huffman_encoded_len(s);
    if huff < s.len() {
        encode_integer(huff as u64, 7, 0x80, out);
        huffman_encode(s, out);
    } else {
        encode_integer(s.len() as u64, 7, 0, out);
        out.extend_from_slice(s);
    }
}

/// Names must already be lowercase, as HTTP/2 requires.
pub fn encode(headers: &[(&[u8], &[u8], bool)], out: &mut Vec<u8>) {
    for &(name, value, sensitive) in headers {
        debug_assert!(
            !name.iter().any(u8::is_ascii_uppercase),
            "HTTP/2 header names are lowercase"
        );
        if !sensitive {
            if let Some(i) = STATIC_TABLE
                .iter()
                .position(|&(n, v)| n == name && v == value)
            {
                encode_integer(i as u64 + 1, 7, 0x80, out);
                continue;
            }
        }
        let flags = if sensitive { 0x10 } else { 0x00 };
        match STATIC_TABLE.iter().position(|&(n, _)| n == name) {
            Some(i) => encode_integer(i as u64 + 1, 4, flags, out),
            None => {
                out.push(flags);
                encode_string(name, out);
            }
        }
        encode_string(value, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    fn pairs(h: &[Header]) -> Vec<(String, String)> {
        h.iter()
            .map(|h| {
                (
                    String::from_utf8(h.name.clone()).unwrap(),
                    String::from_utf8(h.value.clone()).unwrap(),
                )
            })
            .collect()
    }

    fn owned(list: &[(&str, &str)]) -> Vec<(String, String)> {
        list.iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect()
    }

    // RFC 7541 C.1.
    #[test]
    fn integer_examples_from_the_rfc() {
        let mut out = Vec::new();
        encode_integer(10, 5, 0, &mut out);
        assert_eq!(out, [0x0a]);
        out.clear();
        encode_integer(1337, 5, 0, &mut out);
        assert_eq!(out, [0x1f, 0x9a, 0x0a]);
        out.clear();
        encode_integer(42, 8, 0, &mut out);
        assert_eq!(out, [0x2a]);
        assert_eq!(decode_integer(&[0xea], 5), Ok((10, 1)));
        assert_eq!(decode_integer(&[0x1f, 0x9a, 0x0a], 5), Ok((1337, 3)));
    }

    #[test]
    fn integers_round_trip_for_every_prefix() {
        for n in 1..=8u8 {
            let max = (1u64 << n) - 1;
            for v in [
                0,
                1,
                max - 1,
                max,
                max + 1,
                max + 127,
                max + 128,
                1 << 20,
                MAX_INTEGER,
            ] {
                let mut out = Vec::new();
                encode_integer(v, n, 0, &mut out);
                assert_eq!(decode_integer(&out, n), Ok((v, out.len())), "v={v} n={n}");
            }
        }
    }

    #[test]
    fn oversized_and_truncated_integers_are_rejected() {
        let mut out = Vec::new();
        encode_integer(MAX_INTEGER + 1, 5, 0, &mut out);
        assert_eq!(decode_integer(&out, 5), Err(HpackError::IntegerOverflow));
        assert_eq!(
            decode_integer(&[0x1f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00], 5),
            Err(HpackError::IntegerOverflow)
        );
        assert_eq!(decode_integer(&[0x1f, 0x80], 5), Err(HpackError::Truncated));
        assert_eq!(decode_integer(&[], 5), Err(HpackError::Truncated));
    }

    #[test]
    fn the_lengths_form_a_complete_canonical_code() {
        // Kraft equality: complete, no overlap
        let total: u64 = HUFFMAN_LENGTHS
            .iter()
            .map(|&l| 1u64 << (MAX_CODE_LEN - l as usize))
            .sum();
        assert_eq!(total, 1 << MAX_CODE_LEN);
        let code = |s: usize| (HUFFMAN.codes[s], HUFFMAN_LENGTHS[s]);
        assert_eq!(code(b'0' as usize), (0x0, 5));
        assert_eq!(code(b'a' as usize), (0x3, 5));
        assert_eq!(code(b' ' as usize), (0x14, 6));
        assert_eq!(code(b'A' as usize), (0x21, 6));
        assert_eq!(code(0), (0x1ff8, 13));
        assert_eq!(code(255), (0x3ffffee, 26));
        assert_eq!(code(256), (0x3fffffff, 30));
    }

    #[test]
    fn every_byte_round_trips_through_huffman() {
        let all: Vec<u8> = (0..=255).collect();
        let mut out = Vec::new();
        huffman_encode(&all, &mut out);
        assert_eq!(out.len(), huffman_encoded_len(&all));
        assert_eq!(huffman_decode(&out), Ok(all));
        for b in 0..=255u8 {
            let mut out = Vec::new();
            huffman_encode(&[b], &mut out);
            assert_eq!(huffman_decode(&out), Ok(vec![b]));
        }
    }

    // RFC 7541 C.4.1: "www.example.com".
    #[test]
    fn huffman_example_from_the_rfc() {
        let mut out = Vec::new();
        huffman_encode(b"www.example.com", &mut out);
        assert_eq!(out, hex("f1e3 c2e5 f23a 6ba0 ab90 f4ff"));
    }

    #[test]
    fn bad_huffman_input_is_rejected() {
        assert_eq!(
            huffman_decode(&[0xff, 0xff, 0xff, 0xff]),
            Err(HpackError::HuffmanEos)
        );
        let mut out = Vec::new();
        huffman_encode(b"a", &mut out);
        out.push(0xff);
        assert_eq!(huffman_decode(&out), Err(HpackError::HuffmanPadding));
        assert_eq!(
            huffman_decode(&[0b0001_1000]),
            Err(HpackError::HuffmanPadding)
        );
    }

    // RFC 7541 C.2.1: literal with indexing.
    #[test]
    fn literal_with_indexing_from_the_rfc() {
        let mut d = Decoder::new(4096, 1 << 16);
        let h = d
            .decode(&hex(
                "400a 6375 7374 6f6d 2d6b 6579 0d63 7573 746f 6d2d 6865 6164 6572",
            ))
            .unwrap();
        assert_eq!(pairs(&h), owned(&[("custom-key", "custom-header")]));
        assert_eq!(d.table_size(), 55);
    }

    fn run_requests(blocks: [&str; 3]) {
        let mut d = Decoder::new(4096, 1 << 16);
        let h = d.decode(&hex(blocks[0])).unwrap();
        assert_eq!(
            pairs(&h),
            owned(&[
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com")
            ])
        );
        assert_eq!(d.table_size(), 57);
        let h = d.decode(&hex(blocks[1])).unwrap();
        assert_eq!(
            pairs(&h),
            owned(&[
                (":method", "GET"),
                (":scheme", "http"),
                (":path", "/"),
                (":authority", "www.example.com"),
                ("cache-control", "no-cache")
            ])
        );
        assert_eq!(d.table_size(), 110);
        let h = d.decode(&hex(blocks[2])).unwrap();
        assert_eq!(
            pairs(&h),
            owned(&[
                (":method", "GET"),
                (":scheme", "https"),
                (":path", "/index.html"),
                (":authority", "www.example.com"),
                ("custom-key", "custom-value")
            ])
        );
        assert_eq!(d.table_size(), 164);
        assert_eq!(d.table_len(), 3);
    }

    // RFC 7541 C.3: three requests, plain literals.
    #[test]
    fn requests_without_huffman_from_the_rfc() {
        run_requests([
            "8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d",
            "8286 84be 5808 6e6f 2d63 6163 6865",
            "8287 85bf 400a 6375 7374 6f6d 2d6b 6579 0c63 7573 746f 6d2d 7661 6c75 65",
        ]);
    }

    // RFC 7541 C.4: the same requests, Huffman coded.
    #[test]
    fn requests_with_huffman_from_the_rfc() {
        run_requests([
            "8286 8441 8cf1 e3c2 e5f2 3a6b a0ab 90f4 ff",
            "8286 84be 5886 a8eb 1064 9cbf",
            "8287 85bf 4088 25a8 49e9 5ba9 7d7f 8925 a849 e95b b8e8 b4bf",
        ]);
    }

    #[test]
    fn eviction_keeps_the_table_within_its_size() {
        // Room for exactly two 50 byte entries (9 + 9 + 32 each).
        let mut d = Decoder::new(100, 1 << 16);
        let mut block = Vec::new();
        for i in 0..3u8 {
            block.push(0x40);
            encode_string(
                &[b'n', b'a', b'm', b'e', b'-', b'0' + i, b'x', b'x', b'x'],
                &mut block,
            );
            encode_string(b"value-xxx", &mut block);
        }
        d.decode(&block).unwrap();
        assert_eq!(d.table_len(), 2);
        assert_eq!(d.table_size(), 100);
        let h = d.decode(&[0x80 | 62, 0x80 | 63]).unwrap();
        assert_eq!(h[0].name, b"name-2xxx");
        assert_eq!(h[1].name, b"name-1xxx");
        assert_eq!(d.decode(&[0x80 | 64]), Err(HpackError::BadIndex(64)));
    }

    #[test]
    fn an_entry_larger_than_the_table_empties_it() {
        let mut d = Decoder::new(60, 1 << 16);
        d.decode(&hex(
            "400a 6375 7374 6f6d 2d6b 6579 0d63 7573 746f 6d2d 6865 6164 6572",
        ))
        .unwrap();
        assert_eq!(d.table_len(), 1);
        let mut block = vec![0x40];
        encode_string(b"a-much-longer-header-name", &mut block);
        encode_string(b"and-its-long-value", &mut block);
        d.decode(&block).unwrap();
        assert_eq!((d.table_len(), d.table_size()), (0, 0));
    }

    #[test]
    fn table_size_updates_are_checked() {
        let mut d = Decoder::new(4096, 1 << 16);
        d.decode(&hex(
            "400a 6375 7374 6f6d 2d6b 6579 0d63 7573 746f 6d2d 6865 6164 6572",
        ))
        .unwrap();
        d.decode(&[0x20]).unwrap();
        assert_eq!(d.table_len(), 0);
        let mut big = Vec::new();
        encode_integer(4097, 5, 0x20, &mut big);
        assert_eq!(d.decode(&big), Err(HpackError::TableSizeTooLarge(4097)));
        assert_eq!(
            d.decode(&[0x82, 0x20]),
            Err(HpackError::LateTableSizeUpdate)
        );
    }

    #[test]
    fn bad_blocks_are_rejected() {
        let mut d = Decoder::new(4096, 1 << 16);
        assert_eq!(d.decode(&[0x80]), Err(HpackError::BadIndex(0)));
        assert_eq!(d.decode(&[0x80 | 62]), Err(HpackError::BadIndex(62)));
        assert_eq!(d.decode(&[0x04, 0x05, b'a']), Err(HpackError::Truncated));
        assert_eq!(d.decode(&[0x40]), Err(HpackError::Truncated));
    }

    #[test]
    fn the_header_list_size_is_enforced() {
        let mut d = Decoder::new(4096, 100);
        // ":method: GET" costs 7 + 3 + 32 = 42; three of them exceed 100.
        assert!(d.decode(&[0x82, 0x82]).is_ok());
        assert_eq!(
            d.decode(&[0x82, 0x82, 0x82]),
            Err(HpackError::HeaderListTooLarge)
        );
    }

    #[test]
    fn the_encoder_round_trips_through_the_decoder() {
        let input: [(&[u8], &[u8], bool); 6] = [
            (b":status", b"200", false),
            (b"content-type", b"application/grpc", false),
            (b"grpc-status", b"0", false),
            (b"authorization", b"Bearer secret", true),
            (b":method", b"GET", true),
            (b"x-empty", b"", false),
        ];
        let mut block = Vec::new();
        encode(&input, &mut block);
        assert_eq!(block[0], 0x88);
        let mut d = Decoder::new(4096, 1 << 16);
        let out = d.decode(&block).unwrap();
        assert_eq!(out.len(), input.len());
        for (h, &(n, v, s)) in out.iter().zip(input.iter()) {
            assert_eq!(
                (h.name.as_slice(), h.value.as_slice(), h.sensitive),
                (n, v, s)
            );
        }
        assert_eq!(d.table_len(), 0);
    }

    #[test]
    fn random_strings_round_trip() {
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        for _ in 0..2000 {
            let len = (next() % 64) as usize;
            let s: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            let mut out = Vec::new();
            huffman_encode(&s, &mut out);
            assert_eq!(huffman_decode(&out), Ok(s.clone()));
            let mut out = Vec::new();
            encode_string(&s, &mut out);
            assert_eq!(decode_string(&out), Ok((s, out.len())));
        }
    }
}
