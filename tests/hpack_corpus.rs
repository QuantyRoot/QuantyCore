//! The hpack-test-case corpus (github.com/http2jp/hpack-test-case, MIT):
//! the same recorded headers as encoded by nghttp2, Go, Python, Node,
//! Swift and Haskell implementations, with and without Huffman and the
//! dynamic table. Too large to vendor at 66 MB, so it runs when
//! QUANTY_HPACK_CASES points at a checkout; CI pins a commit.
//!
//! It does not catch a 31 byte entry overhead instead of 32, because the
//! recorded encoders rarely fill the table to an eviction boundary. The
//! unit tests pin that number.

use quantycore::hpack::{encode, Decoder};
use std::path::Path;

#[test]
fn every_story_in_the_corpus_decodes() {
    let Ok(root) = std::env::var("QUANTY_HPACK_CASES") else {
        eprintln!("QUANTY_HPACK_CASES not set, corpus not run");
        return;
    };
    let mut implementations = 0;
    let mut cases = 0;
    let mut entries: Vec<_> = std::fs::read_dir(&root)
        .expect("QUANTY_HPACK_CASES must be a directory")
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_dir() && p.join("story_00.json").exists())
        .collect();
    entries.sort();
    for dir in entries {
        // raw-data has the headers but no encoding of them
        let encoded = dir.file_name().unwrap() != "raw-data";
        if encoded {
            implementations += 1;
        }
        let mut stories: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().is_some_and(|x| x == "json"))
            .collect();
        stories.sort();
        for story in stories {
            cases += run_story(&story, encoded);
        }
    }
    eprintln!("{implementations} encoders, {cases} header blocks");
    assert!(implementations >= 10, "corpus looks incomplete");
    assert!(cases > 10_000, "corpus looks incomplete");
}

fn run_story(path: &Path, encoded: bool) -> usize {
    let text = std::fs::read_to_string(path).unwrap();
    let doc = Json::parse(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let list = doc.get("cases").and_then(Json::as_array).expect("cases");
    let limit = list
        .iter()
        .filter_map(|c| c.get("header_table_size").and_then(Json::as_u64))
        .max()
        .unwrap_or(4096)
        .max(4096) as usize;
    let mut decoder = Decoder::new(limit, usize::MAX);
    for case in list {
        let expected: Vec<(Vec<u8>, Vec<u8>)> = case
            .get("headers")
            .and_then(Json::as_array)
            .expect("headers")
            .iter()
            .map(|h| match h {
                Json::Object(fields) => {
                    let (n, v) = &fields[0];
                    (n.clone(), v.as_bytes().expect("string value").to_vec())
                }
                _ => panic!("header is not an object"),
            })
            .collect();
        let seq = case.get("seqno").and_then(Json::as_u64).unwrap_or(0);
        let at = || format!("{} seqno {seq}", path.display());
        if encoded {
            let wire = hex(case.get("wire").and_then(Json::as_bytes).expect("wire"));
            let got = decoder
                .decode(&wire)
                .unwrap_or_else(|e| panic!("{}: {e}", at()));
            let got: Vec<_> = got.into_iter().map(|h| (h.name, h.value)).collect();
            assert_eq!(got, expected, "{}", at());
        }
        let input: Vec<(&[u8], &[u8], bool)> = expected
            .iter()
            .map(|(n, v)| (n.as_slice(), v.as_slice(), false))
            .collect();
        let mut block = Vec::new();
        encode(&input, &mut block);
        let back = Decoder::new(4096, usize::MAX)
            .decode(&block)
            .unwrap_or_else(|e| panic!("own encoding, {}: {e}", at()));
        let back: Vec<_> = back.into_iter().map(|h| (h.name, h.value)).collect();
        assert_eq!(back, expected, "own encoding, {}", at());
    }
    list.len()
}

fn hex(s: &[u8]) -> Vec<u8> {
    let digit = |c: u8| match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => panic!("not hex: {c}"),
    };
    s.chunks(2)
        .map(|p| digit(p[0]) << 4 | digit(p[1]))
        .collect()
}

/// Just enough JSON for the corpus files.
enum Json {
    Null,
    Bool,
    Number(f64),
    String(Vec<u8>),
    Array(Vec<Json>),
    Object(Vec<(Vec<u8>, Json)>),
}

impl Json {
    fn parse(text: &str) -> Result<Json, String> {
        let mut p = Parser {
            s: text.as_bytes(),
            i: 0,
        };
        let v = p.value()?;
        p.ws();
        if p.i != p.s.len() {
            return Err(format!("trailing data at {}", p.i));
        }
        Ok(v)
    }
    fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(f) => f.iter().find(|(k, _)| k == key.as_bytes()).map(|(_, v)| v),
            _ => None,
        }
    }
    fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Array(a) => Some(a),
            _ => None,
        }
    }
    fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Json::String(s) => Some(s),
            _ => None,
        }
    }
    fn as_u64(&self) -> Option<u64> {
        match self {
            Json::Number(n) => Some(*n as u64),
            _ => None,
        }
    }
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self.i < self.s.len() && self.s[self.i].is_ascii_whitespace() {
            self.i += 1;
        }
    }
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }
    fn expect(&mut self, c: u8) -> Result<(), String> {
        self.ws();
        if self.peek() == Some(c) {
            self.i += 1;
            Ok(())
        } else {
            Err(format!("expected {} at {}", c as char, self.i))
        }
    }
    fn literal(&mut self, word: &[u8], v: Json) -> Result<Json, String> {
        if self.s[self.i..].starts_with(word) {
            self.i += word.len();
            Ok(v)
        } else {
            Err(format!("bad literal at {}", self.i))
        }
    }
    fn value(&mut self) -> Result<Json, String> {
        self.ws();
        match self.peek().ok_or("unexpected end")? {
            b'{' => {
                self.i += 1;
                let mut fields = Vec::new();
                self.ws();
                if self.peek() == Some(b'}') {
                    self.i += 1;
                    return Ok(Json::Object(fields));
                }
                loop {
                    self.ws();
                    let k = self.string()?;
                    self.expect(b':')?;
                    fields.push((k, self.value()?));
                    self.ws();
                    match self.peek() {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            return Ok(Json::Object(fields));
                        }
                        _ => return Err(format!("bad object at {}", self.i)),
                    }
                }
            }
            b'[' => {
                self.i += 1;
                let mut items = Vec::new();
                self.ws();
                if self.peek() == Some(b']') {
                    self.i += 1;
                    return Ok(Json::Array(items));
                }
                loop {
                    items.push(self.value()?);
                    self.ws();
                    match self.peek() {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            return Ok(Json::Array(items));
                        }
                        _ => return Err(format!("bad array at {}", self.i)),
                    }
                }
            }
            b'"' => Ok(Json::String(self.string()?)),
            b't' => self.literal(b"true", Json::Bool),
            b'f' => self.literal(b"false", Json::Bool),
            b'n' => self.literal(b"null", Json::Null),
            _ => {
                let start = self.i;
                while self.i < self.s.len() && b"+-.0123456789eE".contains(&self.s[self.i]) {
                    self.i += 1;
                }
                std::str::from_utf8(&self.s[start..self.i])
                    .unwrap()
                    .parse()
                    .map(Json::Number)
                    .map_err(|_| format!("bad number at {start}"))
            }
        }
    }
    fn hex4(&mut self) -> Result<u32, String> {
        let h = self.s.get(self.i..self.i + 4).ok_or("short escape")?;
        self.i += 4;
        u32::from_str_radix(std::str::from_utf8(h).unwrap(), 16).map_err(|e| e.to_string())
    }
    fn string(&mut self) -> Result<Vec<u8>, String> {
        if self.peek() != Some(b'"') {
            return Err(format!("expected string at {}", self.i));
        }
        self.i += 1;
        let mut out = Vec::new();
        loop {
            let c = self.peek().ok_or("unterminated string")?;
            self.i += 1;
            match c {
                b'"' => return Ok(out),
                b'\\' => {
                    let e = self.peek().ok_or("bad escape")?;
                    self.i += 1;
                    match e {
                        b'"' | b'\\' | b'/' => out.push(e),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let mut cp = self.hex4()?;
                            if (0xd800..0xdc00).contains(&cp)
                                && self.s[self.i..].starts_with(b"\\u")
                            {
                                self.i += 2;
                                let lo = self.hex4()?;
                                cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
                            }
                            let ch = char::from_u32(cp).ok_or("bad code point")?;
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        _ => return Err(format!("bad escape at {}", self.i)),
                    }
                }
                _ => out.push(c),
            }
        }
    }
}
