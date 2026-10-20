//! JSON (RFC 8259) for OCI manifests and indexes, image configs, registry
//! token responses and CNI configuration, all of which can arrive from a
//! peer nobody here controls.
//!
//! The parser is strict: anything RFC 8259 does not allow is an error, and
//! so are duplicate object keys, which the RFC only discourages. A digest
//! check or a security decision must never depend on which of two values
//! for the same key a reader happened to keep, and readers disagree on that.
//!
//! Containers nest at most [`MAX_DEPTH`] deep, so a hostile document cannot
//! exhaust the stack. Size limits are the caller's: the parser costs time
//! and memory in proportion to its input and nothing more.
//!
//! Numbers keep their source text, so a document that is parsed and
//! written again keeps every digit, whatever its magnitude.

use std::collections::HashSet;
use std::fmt::{self, Write};

pub const MAX_DEPTH: usize = 128;

/// Objects up to this many keys check for duplicates by scanning; larger
/// ones switch to a hash set so a huge object stays linear.
const LINEAR_KEYS: usize = 16;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(Number),
    String(String),
    Array(Vec<Value>),
    Object(Object),
}

/// A number as written in the source. Two numbers are equal when their
/// text is, so `1.0` and `1` differ, as they do to a digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Number {
    text: String,
}

/// Keys in the order they appeared, which is the order they are written
/// back in.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Object {
    entries: Vec<(String, Value)>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorKind {
    UnexpectedEnd,
    UnexpectedByte(u8),
    TrailingData,
    InvalidUtf8,
    ByteOrderMark,
    /// U+0000 to U+001F must be escaped inside a string.
    ControlCharacter,
    InvalidEscape,
    /// A \u escape of a UTF-16 surrogate that is not half of a pair.
    LoneSurrogate,
    InvalidNumber,
    DuplicateKey,
    TooDeep,
}

/// `line` and `column` count from 1, the column in bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    pub kind: ErrorKind,
    pub offset: usize,
    pub line: usize,
    pub column: usize,
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ErrorKind::UnexpectedEnd => f.write_str("unexpected end of input"),
            ErrorKind::UnexpectedByte(b) if b.is_ascii_graphic() => {
                write!(f, "unexpected '{}'", *b as char)
            }
            ErrorKind::UnexpectedByte(b) => write!(f, "unexpected byte {b:#04x}"),
            ErrorKind::TrailingData => f.write_str("data after the value"),
            ErrorKind::InvalidUtf8 => f.write_str("invalid UTF-8"),
            ErrorKind::ByteOrderMark => f.write_str("byte order mark"),
            ErrorKind::ControlCharacter => f.write_str("unescaped control character in string"),
            ErrorKind::InvalidEscape => f.write_str("invalid escape"),
            ErrorKind::LoneSurrogate => f.write_str("unpaired UTF-16 surrogate"),
            ErrorKind::InvalidNumber => f.write_str("invalid number"),
            ErrorKind::DuplicateKey => f.write_str("duplicate object key"),
            ErrorKind::TooDeep => write!(f, "nested deeper than {MAX_DEPTH}"),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} at line {} column {} (byte {})",
            self.kind, self.line, self.column, self.offset
        )
    }
}

impl std::error::Error for Error {}

impl Error {
    fn at(kind: ErrorKind, offset: usize, input: &[u8]) -> Error {
        let before = &input[..offset.min(input.len())];
        let line = 1 + before.iter().filter(|&&b| b == b'\n').count();
        let line_start = before
            .iter()
            .rposition(|&b| b == b'\n')
            .map_or(0, |i| i + 1);
        Error {
            kind,
            offset,
            line,
            column: offset - line_start + 1,
        }
    }
}

/// A UTF-8 byte order mark is an error, as it is for Go's encoding/json:
/// RFC 8259 forbids sending one, and accepting it would give one value
/// two encodings with different digests.
pub fn parse(input: &str) -> Result<Value, Error> {
    let mut p = Parser {
        src: input,
        bytes: input.as_bytes(),
        pos: 0,
    };
    p.document()
        .map_err(|(kind, offset)| Error::at(kind, offset, input.as_bytes()))
}

pub fn parse_bytes(input: &[u8]) -> Result<Value, Error> {
    match std::str::from_utf8(input) {
        Ok(s) => parse(s),
        Err(e) => Err(Error::at(ErrorKind::InvalidUtf8, e.valid_up_to(), input)),
    }
}

impl Number {
    pub fn as_str(&self) -> &str {
        &self.text
    }

    fn is_integer(&self) -> bool {
        !self.text.contains(['.', 'e', 'E'])
    }

    /// None for a number written with a fraction or an exponent, even
    /// `1.0` or `1e2`, and for one outside the range of i64.
    pub fn as_i64(&self) -> Option<i64> {
        if !self.is_integer() {
            return None;
        }
        self.text.parse().ok()
    }

    pub fn as_u64(&self) -> Option<u64> {
        if !self.is_integer() {
            return None;
        }
        if self.text == "-0" {
            return Some(0);
        }
        self.text.parse().ok()
    }

    /// The nearest f64, or None when that is infinite, as for `1e400`.
    pub fn as_f64(&self) -> Option<f64> {
        self.text.parse::<f64>().ok().filter(|f| f.is_finite())
    }

    /// None for NaN and the infinities, which JSON cannot represent.
    pub fn from_f64(f: f64) -> Option<Number> {
        // Debug, not Display: Display writes 1e300 as 301 digits.
        f.is_finite().then(|| Number {
            text: format!("{f:?}"),
        })
    }
}

impl From<i64> for Number {
    fn from(v: i64) -> Number {
        Number {
            text: v.to_string(),
        }
    }
}

impl From<u64> for Number {
    fn from(v: u64) -> Number {
        Number {
            text: v.to_string(),
        }
    }
}

impl Object {
    pub fn new() -> Object {
        Object::default()
    }

    pub fn get(&self, key: &str) -> Option<&Value> {
        self.entries.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }

    /// Replaces the value of an existing key in place, or appends.
    /// Linear in the number of keys.
    pub fn insert(&mut self, key: impl Into<String>, value: Value) -> Option<Value> {
        let key = key.into();
        match self.entries.iter_mut().find(|(k, _)| *k == key) {
            Some((_, v)) => Some(std::mem::replace(v, value)),
            None => {
                self.entries.push((key, value));
                None
            }
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &Value)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.as_object()?.get(key)
    }

    pub fn index(&self, i: usize) -> Option<&Value> {
        self.as_array()?.get(i)
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_number(&self) -> Option<&Number> {
        match self {
            Value::Number(n) => Some(n),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        self.as_number()?.as_i64()
    }

    pub fn as_u64(&self) -> Option<u64> {
        self.as_number()?.as_u64()
    }

    pub fn as_f64(&self) -> Option<f64> {
        self.as_number()?.as_f64()
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&Object> {
        match self {
            Value::Object(o) => Some(o),
            _ => None,
        }
    }

    /// A JSON Pointer (RFC 6901), such as `/config/digest`. The empty
    /// pointer is the whole document. In a token, `~1` stands for `/` and
    /// `~0` for `~`; any other `~` makes the pointer invalid.
    pub fn pointer(&self, pointer: &str) -> Option<&Value> {
        if pointer.is_empty() {
            return Some(self);
        }
        let mut at = self;
        for token in pointer.strip_prefix('/')?.split('/') {
            let key = unescape_token(token)?;
            at = match at {
                Value::Object(o) => o.get(&key)?,
                Value::Array(a) => a.get(array_index(&key)?)?,
                _ => return None,
            };
        }
        Some(at)
    }

    /// Two spaces per level, `": "` after keys, empty containers as `[]`
    /// and `{}`: the same bytes as Python's `json.dumps(v, indent=2,
    /// ensure_ascii=False)`.
    pub fn to_string_pretty(&self) -> String {
        let mut out = String::new();
        // Writing to a String cannot fail.
        let _ = write_value(&mut out, self, Some(0));
        out
    }
}

fn unescape_token(token: &str) -> Option<String> {
    let mut out = String::with_capacity(token.len());
    let mut chars = token.chars();
    while let Some(c) = chars.next() {
        if c == '~' {
            match chars.next() {
                Some('0') => out.push('~'),
                Some('1') => out.push('/'),
                _ => return None,
            }
        } else {
            out.push(c);
        }
    }
    Some(out)
}

/// RFC 6901 allows no leading zeros and no sign; `-` names the element
/// after the last, which never exists for a lookup.
fn array_index(token: &str) -> Option<usize> {
    let digits = token.bytes().all(|b| b.is_ascii_digit());
    if token.is_empty() || !digits || (token.len() > 1 && token.starts_with('0')) {
        return None;
    }
    token.parse().ok()
}

impl From<bool> for Value {
    fn from(v: bool) -> Value {
        Value::Bool(v)
    }
}

impl From<&str> for Value {
    fn from(v: &str) -> Value {
        Value::String(v.to_string())
    }
}

impl From<String> for Value {
    fn from(v: String) -> Value {
        Value::String(v)
    }
}

impl From<i64> for Value {
    fn from(v: i64) -> Value {
        Value::Number(v.into())
    }
}

impl From<u64> for Value {
    fn from(v: u64) -> Value {
        Value::Number(v.into())
    }
}

impl From<Vec<Value>> for Value {
    fn from(v: Vec<Value>) -> Value {
        Value::Array(v)
    }
}

impl From<Object> for Value {
    fn from(v: Object) -> Value {
        Value::Object(v)
    }
}

/// Compact, with no whitespace at all.
impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_value(f, self, None)
    }
}

// Recursive: values from the parser are at most MAX_DEPTH deep, values a
// caller builds are as deep as the caller made them.
fn write_value<W: Write>(out: &mut W, v: &Value, indent: Option<usize>) -> fmt::Result {
    match v {
        Value::Null => out.write_str("null"),
        Value::Bool(b) => out.write_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.write_str(&n.text),
        Value::String(s) => write_string(out, s),
        Value::Array(a) => {
            if a.is_empty() {
                return out.write_str("[]");
            }
            out.write_char('[')?;
            for (i, item) in a.iter().enumerate() {
                if i > 0 {
                    out.write_char(',')?;
                }
                newline(out, indent.map(|d| d + 1))?;
                write_value(out, item, indent.map(|d| d + 1))?;
            }
            newline(out, indent)?;
            out.write_char(']')
        }
        Value::Object(o) => {
            if o.is_empty() {
                return out.write_str("{}");
            }
            out.write_char('{')?;
            for (i, (k, item)) in o.entries.iter().enumerate() {
                if i > 0 {
                    out.write_char(',')?;
                }
                newline(out, indent.map(|d| d + 1))?;
                write_string(out, k)?;
                out.write_str(if indent.is_some() { ": " } else { ":" })?;
                write_value(out, item, indent.map(|d| d + 1))?;
            }
            newline(out, indent)?;
            out.write_char('}')
        }
    }
}

fn newline<W: Write>(out: &mut W, indent: Option<usize>) -> fmt::Result {
    if let Some(depth) = indent {
        out.write_char('\n')?;
        for _ in 0..depth {
            out.write_str("  ")?;
        }
    }
    Ok(())
}

/// Escapes only what RFC 8259 requires: the quote, the backslash and the
/// control characters, using the short forms where they exist and
/// lowercase `\u00xx` otherwise, as Python does. Everything else is
/// written as UTF-8.
fn write_string<W: Write>(out: &mut W, s: &str) -> fmt::Result {
    out.write_char('"')?;
    let bytes = s.as_bytes();
    let mut start = 0;
    for (i, &b) in bytes.iter().enumerate() {
        let short = match b {
            b'"' => "\\\"",
            b'\\' => "\\\\",
            b'\n' => "\\n",
            b'\r' => "\\r",
            b'\t' => "\\t",
            0x08 => "\\b",
            0x0c => "\\f",
            0x00..=0x1f => "",
            _ => continue,
        };
        // i is at an ASCII byte, so both slices end on a char boundary.
        out.write_str(&s[start..i])?;
        if short.is_empty() {
            write!(out, "\\u{b:04x}")?;
        } else {
            out.write_str(short)?;
        }
        start = i + 1;
    }
    out.write_str(&s[start..])?;
    out.write_char('"')
}

type Parsed<T> = Result<T, (ErrorKind, usize)>;

struct Parser<'a> {
    src: &'a str,
    bytes: &'a [u8],
    pos: usize,
}

impl Parser<'_> {
    fn document(&mut self) -> Parsed<Value> {
        if self.src.starts_with('\u{feff}') {
            return Err((ErrorKind::ByteOrderMark, 0));
        }
        let v = self.value(0)?;
        self.skip_whitespace();
        if self.pos < self.bytes.len() {
            return Err((ErrorKind::TrailingData, self.pos));
        }
        Ok(v)
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.pos).copied()
    }

    // RFC 8259 whitespace is these four and nothing else: no form feed,
    // no vertical tab, no Unicode spaces.
    fn skip_whitespace(&mut self) {
        while let Some(b' ' | b'\t' | b'\n' | b'\r') = self.peek() {
            self.pos += 1;
        }
    }

    fn unexpected(&self) -> (ErrorKind, usize) {
        match self.peek() {
            Some(b) => (ErrorKind::UnexpectedByte(b), self.pos),
            None => (ErrorKind::UnexpectedEnd, self.pos),
        }
    }

    fn expect(&mut self, b: u8) -> Parsed<()> {
        if self.peek() != Some(b) {
            return Err(self.unexpected());
        }
        self.pos += 1;
        Ok(())
    }

    fn literal(&mut self, word: &str, v: Value) -> Parsed<Value> {
        for &b in word.as_bytes() {
            self.expect(b)?;
        }
        Ok(v)
    }

    /// `depth` counts the containers around this value.
    fn value(&mut self, depth: usize) -> Parsed<Value> {
        self.skip_whitespace();
        match self.peek() {
            Some(b'{') => self.object(depth + 1),
            Some(b'[') => self.array(depth + 1),
            Some(b'"') => self.string().map(Value::String),
            Some(b'-' | b'0'..=b'9') => self.number().map(Value::Number),
            Some(b't') => self.literal("true", Value::Bool(true)),
            Some(b'f') => self.literal("false", Value::Bool(false)),
            Some(b'n') => self.literal("null", Value::Null),
            _ => Err(self.unexpected()),
        }
    }

    fn array(&mut self, depth: usize) -> Parsed<Value> {
        if depth > MAX_DEPTH {
            return Err((ErrorKind::TooDeep, self.pos));
        }
        self.pos += 1;
        let mut items = Vec::new();
        self.skip_whitespace();
        if self.peek() == Some(b']') {
            self.pos += 1;
            return Ok(Value::Array(items));
        }
        loop {
            items.push(self.value(depth)?);
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b']') => {
                    self.pos += 1;
                    return Ok(Value::Array(items));
                }
                _ => return Err(self.unexpected()),
            }
        }
    }

    fn object(&mut self, depth: usize) -> Parsed<Value> {
        if depth > MAX_DEPTH {
            return Err((ErrorKind::TooDeep, self.pos));
        }
        self.pos += 1;
        let mut entries: Vec<(String, Value)> = Vec::new();
        let mut seen: Option<HashSet<String>> = None;
        self.skip_whitespace();
        if self.peek() == Some(b'}') {
            self.pos += 1;
            return Ok(Value::Object(Object { entries }));
        }
        loop {
            self.skip_whitespace();
            if self.peek() != Some(b'"') {
                return Err(self.unexpected());
            }
            let key_at = self.pos;
            // Compared after unescaping: "a" and "\u0061" are the same key.
            let key = self.string()?;
            let duplicate = match &mut seen {
                Some(set) => !set.insert(key.clone()),
                None => entries.iter().any(|(k, _)| *k == key),
            };
            if duplicate {
                return Err((ErrorKind::DuplicateKey, key_at));
            }
            self.skip_whitespace();
            self.expect(b':')?;
            let v = self.value(depth)?;
            entries.push((key, v));
            if seen.is_none() && entries.len() == LINEAR_KEYS {
                seen = Some(entries.iter().map(|(k, _)| k.clone()).collect());
            }
            self.skip_whitespace();
            match self.peek() {
                Some(b',') => self.pos += 1,
                Some(b'}') => {
                    self.pos += 1;
                    return Ok(Value::Object(Object { entries }));
                }
                _ => return Err(self.unexpected()),
            }
        }
    }

    fn string(&mut self) -> Parsed<String> {
        self.pos += 1;
        let mut out = String::new();
        loop {
            let start = self.pos;
            while let Some(b) = self.peek() {
                if b == b'"' || b == b'\\' || b < 0x20 {
                    break;
                }
                self.pos += 1;
            }
            // The run stops at an ASCII byte or the end, a char boundary.
            out.push_str(&self.src[start..self.pos]);
            match self.peek() {
                None => return Err((ErrorKind::UnexpectedEnd, self.pos)),
                Some(b'"') => {
                    self.pos += 1;
                    return Ok(out);
                }
                Some(b'\\') => out.push(self.escape()?),
                Some(_) => return Err((ErrorKind::ControlCharacter, self.pos)),
            }
        }
    }

    fn escape(&mut self) -> Parsed<char> {
        let at = self.pos;
        self.pos += 1;
        let c = match self.peek() {
            None => return Err((ErrorKind::UnexpectedEnd, self.pos)),
            Some(b'"') => '"',
            Some(b'\\') => '\\',
            Some(b'/') => '/',
            Some(b'b') => '\u{8}',
            Some(b'f') => '\u{c}',
            Some(b'n') => '\n',
            Some(b'r') => '\r',
            Some(b't') => '\t',
            Some(b'u') => {
                self.pos += 1;
                let unit = self.hex4()?;
                return match unit {
                    0xd800..=0xdbff => {
                        // A high surrogate counts only when the very next
                        // thing is a \u escape of a low one.
                        if !self.bytes[self.pos..].starts_with(b"\\u") {
                            return Err((ErrorKind::LoneSurrogate, at));
                        }
                        self.pos += 2;
                        let low = self.hex4()?;
                        if !(0xdc00..=0xdfff).contains(&low) {
                            return Err((ErrorKind::LoneSurrogate, at));
                        }
                        let c = 0x10000 + ((unit - 0xd800) << 10) + (low - 0xdc00);
                        char::from_u32(c).ok_or((ErrorKind::LoneSurrogate, at))
                    }
                    0xdc00..=0xdfff => Err((ErrorKind::LoneSurrogate, at)),
                    _ => char::from_u32(unit).ok_or((ErrorKind::InvalidEscape, at)),
                };
            }
            Some(_) => return Err((ErrorKind::InvalidEscape, at)),
        };
        self.pos += 1;
        Ok(c)
    }

    fn hex4(&mut self) -> Parsed<u32> {
        let mut unit = 0;
        for _ in 0..4 {
            let digit = match self.peek() {
                None => return Err((ErrorKind::UnexpectedEnd, self.pos)),
                Some(b) => (b as char)
                    .to_digit(16)
                    .ok_or((ErrorKind::InvalidEscape, self.pos))?,
            };
            unit = (unit << 4) | digit;
            self.pos += 1;
        }
        Ok(unit)
    }

    fn digits(&mut self) -> usize {
        let start = self.pos;
        while let Some(b'0'..=b'9') = self.peek() {
            self.pos += 1;
        }
        self.pos - start
    }

    // -?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?  A leading zero ends
    // the integer part, so "01" fails afterwards as data after a value.
    fn number(&mut self) -> Parsed<Number> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.pos += 1;
        }
        match self.peek() {
            Some(b'0') => self.pos += 1,
            Some(b'1'..=b'9') => {
                self.digits();
            }
            _ => return Err((ErrorKind::InvalidNumber, start)),
        }
        if self.peek() == Some(b'.') {
            self.pos += 1;
            if self.digits() == 0 {
                return Err((ErrorKind::InvalidNumber, start));
            }
        }
        if let Some(b'e' | b'E') = self.peek() {
            self.pos += 1;
            if let Some(b'+' | b'-') = self.peek() {
                self.pos += 1;
            }
            if self.digits() == 0 {
                return Err((ErrorKind::InvalidNumber, start));
            }
        }
        Ok(Number {
            text: self.src[start..self.pos].to_string(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;
    use std::process::{Command, Stdio};

    fn kind(input: &str) -> ErrorKind {
        parse(input).expect_err(input).kind
    }

    // The example from the OCI image specification, image-manifest.md.
    const MANIFEST: &str = r#"{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "digest": "sha256:b5b2b2c507a0944348e0303114d8d93aaaa081732b86451d9bce1f432a537bc7",
    "size": 7023
  },
  "layers": [
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "sha256:9834876dcfb05cb167a5c24953eba58c4ac89b1adf57f28f2f9d09af107ee8f0",
      "size": 32654
    },
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "sha256:3c3a4604a545cdc127456d94e421cd355bca5b528f4a9c1905b15da2eb4a4c6b",
      "size": 16724
    },
    {
      "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
      "digest": "sha256:ec4b8955958665577945c89419d1af06b5f7636b4ac3da7f12184802ad867736",
      "size": 73109
    }
  ],
  "subject": {
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "digest": "sha256:5b0bcabd1ed22e9fb1310cf6c2dec7cdef19f0ad69efa1f392e94a4333501270",
    "size": 7682
  },
  "annotations": {
    "com.example.key1": "value1",
    "com.example.key2": "value2"
  }
}"#;

    // The example from the OCI image specification, image-index.md.
    const INDEX: &str = r#"{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "manifests": [
    {
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "size": 7143,
      "digest": "sha256:e692418e4cbaf90ca69d05a66403747baa33ee08806650b51fab815ad7fc331f",
      "platform": {
        "architecture": "ppc64le",
        "os": "linux"
      }
    },
    {
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "size": 7682,
      "digest": "sha256:5b0bcabd1ed22e9fb1310cf6c2dec7cdef19f0ad69efa1f392e94a4333501270",
      "platform": {
        "architecture": "amd64",
        "os": "linux"
      }
    }
  ],
  "annotations": {
    "com.example.key1": "value1",
    "com.example.key2": "value2"
  }
}"#;

    #[test]
    fn oci_manifest_and_index_round_trip_byte_for_byte() {
        for doc in [MANIFEST, INDEX] {
            let v = parse(doc).unwrap();
            assert_eq!(v.to_string_pretty(), doc);
            let compact = v.to_string();
            assert!(!compact.contains([' ', '\n']));
            assert_eq!(parse(&compact).unwrap(), v);
        }
        let m = parse(MANIFEST).unwrap();
        assert_eq!(m.get("schemaVersion").and_then(Value::as_u64), Some(2));
        assert_eq!(
            m.pointer("/config/digest").and_then(Value::as_str),
            Some("sha256:b5b2b2c507a0944348e0303114d8d93aaaa081732b86451d9bce1f432a537bc7")
        );
        let layers = m.get("layers").and_then(Value::as_array).unwrap();
        let sizes: Vec<_> = layers
            .iter()
            .filter_map(|l| l.get("size")?.as_u64())
            .collect();
        assert_eq!(sizes, [32654, 16724, 73109]);
        let keys: Vec<_> = m.as_object().unwrap().iter().map(|(k, _)| k).collect();
        assert_eq!(
            keys,
            [
                "schemaVersion",
                "mediaType",
                "config",
                "layers",
                "subject",
                "annotations"
            ]
        );
        let i = parse(INDEX).unwrap();
        assert_eq!(
            i.pointer("/manifests/1/platform/architecture")
                .and_then(Value::as_str),
            Some("amd64")
        );
        assert_eq!(
            i.pointer("/annotations/com.example.key2"),
            Some(&Value::from("value2"))
        );
    }

    // The example document and table of RFC 6901, section 5.
    #[test]
    fn pointers_follow_rfc_6901() {
        let doc = parse(
            r#"{"foo": ["bar", "baz"], "": 0, "a/b": 1, "c%d": 2, "e^f": 3,
                "g|h": 4, "i\\j": 5, "k\"l": 6, " ": 7, "m~n": 8, "~1": 9}"#,
        )
        .unwrap();
        assert_eq!(doc.pointer(""), Some(&doc));
        assert_eq!(
            doc.pointer("/foo").and_then(|v| v.index(1)),
            doc.pointer("/foo/1")
        );
        let expect = [
            ("/foo/0", "bar"),
            ("/", "0"),
            ("/a~1b", "1"),
            ("/c%d", "2"),
            ("/e^f", "3"),
            ("/g|h", "4"),
            ("/i\\j", "5"),
            ("/k\"l", "6"),
            ("/ ", "7"),
            ("/m~0n", "8"),
            // ~1 is decoded before ~0 would be, so ~01 is "~1", not "/".
            ("/~01", "9"),
        ];
        for (p, want) in expect {
            let got = doc.pointer(p).unwrap_or_else(|| panic!("{p}"));
            let got = got.as_str().map_or_else(|| got.to_string(), str::to_string);
            assert_eq!(got, want, "{p}");
        }
        for p in [
            "foo", "/foo/01", "/foo/-", "/foo/2", "/foo/+1", "/m~2n", "/m~", "/x", "/a/b",
        ] {
            assert_eq!(doc.pointer(p), None, "{p}");
        }
    }

    #[test]
    fn numbers_keep_their_text_and_never_truncate() {
        let doc = "[-0,0,1e400,-1e400,1E+2,1.0,9223372036854775807,-9223372036854775808,\
                   9223372036854775808,18446744073709551615,18446744073709551616,\
                   -9223372036854775809,1e-400,123456789012345678901234567890]";
        let v = parse(doc).unwrap();
        assert_eq!(v.to_string(), doc);
        let n = |i: usize| v.index(i).and_then(Value::as_number).unwrap();
        assert_eq!((n(0).as_i64(), n(0).as_u64()), (Some(0), Some(0)));
        assert!(n(0).as_f64().unwrap().is_sign_negative());
        assert_ne!(n(0), n(1));
        assert_eq!(n(2).as_str(), "1e400");
        assert_eq!((n(2).as_f64(), n(3).as_f64()), (None, None));
        assert_eq!((n(4).as_f64(), n(4).as_i64()), (Some(100.0), None));
        assert_eq!((n(5).as_f64(), n(5).as_i64()), (Some(1.0), None));
        assert_eq!(n(6).as_i64(), Some(i64::MAX));
        assert_eq!((n(7).as_i64(), n(7).as_u64()), (Some(i64::MIN), None));
        assert_eq!((n(8).as_i64(), n(8).as_u64()), (None, Some(1 << 63)));
        assert_eq!(n(9).as_u64(), Some(u64::MAX));
        assert_eq!((n(10).as_i64(), n(10).as_u64()), (None, None));
        assert_eq!(n(11).as_i64(), None);
        assert_eq!(n(12).as_f64(), Some(0.0));
        assert_eq!(n(13).as_f64(), Some(1.2345678901234568e29));

        assert_eq!(Number::from_f64(1e300).unwrap().as_str(), "1e300");
        assert_eq!(Number::from_f64(-0.5).unwrap().as_str(), "-0.5");
        assert_eq!(Number::from_f64(f64::NAN), None);
        assert_eq!(Number::from_f64(f64::INFINITY), None);
        for f in [0.1, 1e-7, 5e-324, f64::MAX, -2.0] {
            let text = Value::Number(Number::from_f64(f).unwrap()).to_string();
            assert_eq!(parse(&text).unwrap().as_f64(), Some(f), "{text}");
        }
    }

    #[test]
    fn rejects_what_rfc_8259_forbids_and_says_where() {
        use ErrorKind::*;
        let cases: &[(&str, ErrorKind, usize)] = &[
            ("", UnexpectedEnd, 0),
            ("[1,]", UnexpectedByte(b']'), 3),
            ("{\"a\":1,}", UnexpectedByte(b'}'), 7),
            ("[1 2]", UnexpectedByte(b'2'), 3),
            ("{'a':1}", UnexpectedByte(b'\''), 1),
            ("[1]/**/", TrailingData, 3),
            ("01", TrailingData, 1),
            ("-", InvalidNumber, 0),
            ("[1.]", InvalidNumber, 1),
            ("[.5]", UnexpectedByte(b'.'), 1),
            ("1e+", InvalidNumber, 0),
            ("+1", UnexpectedByte(b'+'), 0),
            ("NaN", UnexpectedByte(b'N'), 0),
            ("-Infinity", InvalidNumber, 0),
            ("[\u{c}]", UnexpectedByte(0x0c), 1),
            ("\u{a0}1", UnexpectedByte(0xc2), 0),
            ("\"a\tb\"", ControlCharacter, 2),
            ("\"\\x\"", InvalidEscape, 1),
            ("\"\\u12g4\"", InvalidEscape, 5),
            ("\"\\u12", UnexpectedEnd, 5),
            ("\"abc", UnexpectedEnd, 4),
            ("tru", UnexpectedEnd, 3),
            ("nul1", UnexpectedByte(b'1'), 3),
            ("\u{feff}{}", ByteOrderMark, 0),
        ];
        for &(input, want, at) in cases {
            let e = parse(input).expect_err(input);
            assert_eq!((e.kind, e.offset), (want, at), "{input:?}");
        }
        let e = parse("{\n  \"a\": [1,\n    2,,\n]}").unwrap_err();
        assert_eq!((e.line, e.column, e.offset), (3, 7, 19));
        assert_eq!(e.to_string(), "unexpected ',' at line 3 column 7 (byte 19)");
        let e = parse_bytes(b"[\"ok\", \"\xff\"]").unwrap_err();
        assert_eq!((e.kind, e.offset), (InvalidUtf8, 8));
        assert_eq!(
            parse_bytes(b"\xef\xbb\xbf[]").unwrap_err().kind,
            ByteOrderMark
        );
        assert_eq!(
            parse_bytes(b" [true , null]\r\n").unwrap().to_string(),
            "[true,null]"
        );
    }

    #[test]
    fn surrogate_pairs_join_and_lone_halves_are_refused() {
        let v = parse(r#"["\ud83d\ude00", "\uD834\uDD1E", "\u00e9\u20ac", "\uffff"]"#).unwrap();
        let strings: Vec<_> = v
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap())
            .collect();
        assert_eq!(
            strings,
            ["\u{1f600}", "\u{1d11e}", "\u{e9}\u{20ac}", "\u{ffff}"]
        );
        for bad in [
            r#""\ud83d""#,
            r#""\ud83dx""#,
            r#""\ud83d\n""#,
            r#""\ud83d\u0041""#,
            r#""\ud83d\ud83d""#,
            r#""\ude00""#,
            r#""\ude00\ud83d""#,
        ] {
            let e = parse(bad).expect_err(bad);
            assert_eq!((e.kind, e.offset), (ErrorKind::LoneSurrogate, 1), "{bad}");
        }
        assert_eq!(kind("\"\\ud83d\\u"), ErrorKind::UnexpectedEnd);
    }

    #[test]
    fn duplicate_keys_are_refused_at_every_size() {
        assert_eq!(kind(r#"{"a": 1, "a": 1}"#), ErrorKind::DuplicateKey);
        assert_eq!(kind(r#"{"a": 1, "\u0061": 2}"#), ErrorKind::DuplicateKey);
        assert_eq!(
            kind(r#"{"x": {"a": 1, "b": 2, "a": 3}}"#),
            ErrorKind::DuplicateKey
        );
        assert!(parse(r#"{"a": {"a": 1}, "b": [{"a": 2}, {"a": 3}]}"#).is_ok());

        // Large enough to use the hash set, with the duplicate on either
        // side of the switch.
        let keys: Vec<String> = (0..50_000).map(|i| format!("\"k{i}\":{i}")).collect();
        let doc = format!("{{{}}}", keys.join(","));
        assert_eq!(parse(&doc).unwrap().as_object().unwrap().len(), 50_000);
        for dup in [3, LINEAR_KEYS - 1, LINEAR_KEYS, 49_999] {
            let doc = format!("{{{},\"k{dup}\":0}}", keys.join(","));
            let e = parse(&doc).unwrap_err();
            let at = doc.rfind(&format!("\"k{dup}\"")).unwrap();
            assert_eq!((e.kind, e.offset), (ErrorKind::DuplicateKey, at));
        }
        let mut small = keys[..LINEAR_KEYS - 1].join(",");
        small.push_str(",\"k0\":0");
        assert_eq!(kind(&format!("{{{small}}}")), ErrorKind::DuplicateKey);
    }

    #[test]
    fn depth_is_limited_without_using_the_stack() {
        let nest = |n: usize| format!("{}{}", "[".repeat(n), "]".repeat(n));
        assert!(parse(&nest(MAX_DEPTH)).is_ok());
        let e = parse(&nest(MAX_DEPTH + 1)).unwrap_err();
        assert_eq!((e.kind, e.offset), (ErrorKind::TooDeep, MAX_DEPTH));
        let objects = "{\"a\":".repeat(MAX_DEPTH) + "1" + &"}".repeat(MAX_DEPTH);
        assert!(parse(&objects).is_ok());
        assert_eq!(kind(&format!("[{objects}]")), ErrorKind::TooDeep);
        assert_eq!(kind(&"[".repeat(1_000_000)), ErrorKind::TooDeep);
        assert_eq!(kind(&"{\"\":".repeat(1_000_000)), ErrorKind::TooDeep);
    }

    // Python's json module is the reference reader: what it makes of our
    // output must be what we wrote, and what it writes we must read.
    #[test]
    fn escaping_matches_python() {
        let mut tricky: String = (0u8..0x20).map(char::from).collect();
        tricky.push_str("\"\\/\u{7f}\u{e9}\u{2028}\u{fffe}\u{1f600}<>&'");
        let mut inner = Object::new();
        inner.insert("", Value::Array(vec![]));
        inner.insert("e", Value::Object(Object::new()));
        inner.insert("n", Value::Number(Number::from_f64(-1.5).unwrap()));
        let mut obj = Object::new();
        obj.insert(tricky.clone(), Value::from(tricky.as_str()));
        obj.insert(
            "list",
            Value::from(vec![Value::Null, true.into(), 7i64.into()]),
        );
        obj.insert("nested", inner.into());
        assert_eq!(
            obj.insert("list", Value::from(u64::MAX))
                .map(|v| v.to_string()),
            Some("[null,true,7]".into())
        );
        let v = Value::Object(obj);

        let script = "import json,sys\n\
                      v = json.loads(sys.stdin.buffer.read())\n\
                      out = [json.dumps(v, ensure_ascii=False, separators=(',', ':')),\n\
                             json.dumps(v, ensure_ascii=False, indent=2), json.dumps(v)]\n\
                      sys.stdout.buffer.write('\\n'.join(out).encode())\n";
        let child = Command::new("python3")
            .args(["-I", "-c", script])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn();
        let Ok(mut child) = child else {
            eprintln!("python3 not found, comparison not run");
            return;
        };
        child
            .stdin
            .take()
            .unwrap()
            .write_all(v.to_string().as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success());
        let out = String::from_utf8(out.stdout).unwrap();
        let mut parts = out.splitn(2, '\n');
        assert_eq!(parts.next().unwrap(), v.to_string());
        let rest = parts.next().unwrap();
        let pretty = v.to_string_pretty();
        assert_eq!(&rest[..pretty.len()], pretty);
        // ensure_ascii=True writes the emoji as a surrogate pair escape.
        let ascii = &rest[pretty.len() + 1..];
        assert!(ascii.contains("\\ud83d\\ude00"));
        assert_eq!(parse(ascii).unwrap(), v);
    }

    #[test]
    fn mutated_documents_never_panic() {
        let seeds = [
            MANIFEST,
            INDEX,
            r#"{"a":[1,-2.5e-3,"\u00e9\ud83d\ude00\n",true,false,null,{}],"b":{"c":[[]]}}"#,
        ];
        let alphabet = b"{}[]\":,\\u0123456789eE+-.tfnrl \t\n\xc3\xa9\xed\xa0\x80\xef\xbb\xbf";
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut rand = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let (mut accepted, mut rejected) = (0, 0);
        for i in 0..5000 {
            let mut doc = seeds[i % seeds.len()].as_bytes().to_vec();
            for _ in 0..1 + rand() % 4 {
                let at = (rand() as usize) % (doc.len() + 1);
                let b = alphabet[(rand() as usize) % alphabet.len()];
                match rand() % 5 {
                    0 if at < doc.len() => doc[at] = b,
                    1 => doc.insert(at, b),
                    2 if at < doc.len() => {
                        doc.remove(at);
                    }
                    3 => doc.truncate(at),
                    _ => {
                        let end = (at + (rand() as usize) % 40).min(doc.len());
                        let copy = doc[at..end].to_vec();
                        doc.splice(at..at, copy);
                    }
                }
            }
            match parse_bytes(&doc) {
                Ok(v) => {
                    accepted += 1;
                    assert_eq!(parse(&v.to_string()).as_ref(), Ok(&v));
                    assert_eq!(parse(&v.to_string_pretty()).as_ref(), Ok(&v));
                }
                Err(e) => {
                    rejected += 1;
                    assert!(e.offset <= doc.len());
                }
            }
        }
        assert!(accepted > 100 && rejected > 1000, "{accepted} {rejected}");
    }
}
