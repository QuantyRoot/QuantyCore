//! Shared by the TLS test files: a small JSON reader for the published
//! vector suites, hex, and where to find the suites.

#![allow(dead_code)]

use std::path::PathBuf;

/// The directory a vector suite was checked out to, from the environment.
/// When `QUANTY_VECTORS_REQUIRED` is set, as it is in CI, a missing suite
/// fails the test instead of skipping it, so an unset variable cannot turn
/// the job green.
pub fn suite(var: &str) -> Option<PathBuf> {
    match std::env::var(var) {
        Ok(p) => Some(PathBuf::from(p)),
        Err(_) if std::env::var_os("QUANTY_VECTORS_REQUIRED").is_some() => {
            panic!("{var} not set but QUANTY_VECTORS_REQUIRED is")
        }
        Err(_) => {
            eprintln!("{var} not set, suite not run");
            None
        }
    }
}

pub fn load(path: &std::path::Path) -> Json {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    Json::parse(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

pub fn hex(s: &[u8]) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
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

/// Just enough JSON for the vector files.
pub enum Json {
    Null,
    Bool(bool),
    Number(f64),
    String(Vec<u8>),
    Array(Vec<Json>),
    Object(Vec<(Vec<u8>, Json)>),
}

impl Json {
    pub fn parse(text: &str) -> Result<Json, String> {
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
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(f) => f.iter().find(|(k, _)| k == key.as_bytes()).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Array(a) => Some(a),
            _ => None,
        }
    }
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Json::String(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Json::Number(n) => Some(*n as u64),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }
    pub fn str(&self, key: &str) -> &str {
        let v = self.get(key).and_then(Json::as_bytes);
        std::str::from_utf8(v.unwrap_or_else(|| panic!("no string {key}"))).unwrap()
    }
    pub fn hex(&self, key: &str) -> Vec<u8> {
        hex(self.str(key).as_bytes())
    }
    pub fn num(&self, key: &str) -> u64 {
        self.get(key)
            .and_then(Json::as_u64)
            .unwrap_or_else(|| panic!("no number {key}"))
    }
    pub fn list(&self, key: &str) -> &[Json] {
        self.get(key)
            .and_then(Json::as_array)
            .unwrap_or_else(|| panic!("no array {key}"))
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
            b't' => self.literal(b"true", Json::Bool(true)),
            b'f' => self.literal(b"false", Json::Bool(false)),
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

/// One section of a CAVP `.rsp` file: the bracketed parameters above it
/// and its records, each a list of `name = value` pairs plus bare flags
/// such as `FAIL`.
pub struct RspRecord {
    pub params: Vec<(String, String)>,
    pub fields: Vec<(String, String)>,
}

impl RspRecord {
    pub fn param(&self, k: &str) -> &str {
        self.params
            .iter()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.as_str())
            .unwrap_or_else(|| panic!("no parameter {k}"))
    }
    pub fn get(&self, k: &str) -> Option<&str> {
        self.fields
            .iter()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.as_str())
    }
    pub fn hex(&self, k: &str) -> Vec<u8> {
        hex(self
            .get(k)
            .unwrap_or_else(|| panic!("no field {k}"))
            .as_bytes())
    }
    pub fn has_flag(&self, k: &str) -> bool {
        self.fields.iter().any(|(n, v)| n == k && v.is_empty())
    }
}

pub fn rsp(path: &std::path::Path) -> Vec<RspRecord> {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut params: Vec<(String, String)> = Vec::new();
    let mut params_open = false;
    let mut out = Vec::new();
    let mut cur: Option<RspRecord> = None;
    for line in text.lines().map(str::trim) {
        if line.starts_with('#') {
            continue;
        }
        if line.is_empty() {
            out.extend(cur.take());
            continue;
        }
        if let Some(p) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            out.extend(cur.take());
            if !params_open {
                params.clear();
                params_open = true;
            }
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            params.push((k.trim().into(), v.trim().into()));
            continue;
        }
        params_open = false;
        let rec = cur.get_or_insert_with(|| RspRecord {
            params: params.clone(),
            fields: Vec::new(),
        });
        let (k, v) = line.split_once('=').unwrap_or((line, ""));
        rec.fields.push((k.trim().into(), v.trim().into()));
    }
    out.extend(cur);
    out
}
