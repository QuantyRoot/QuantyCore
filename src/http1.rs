//! A blocking HTTP/1.1 client (RFC 9112) for talking to OCI registries:
//! GET and HEAD requests without a body, over any `Read + Write` stream.
//!
//! The response head is read whole, within [`MAX_HEAD`] bytes and
//! [`MAX_HEADERS`] fields; the body is streamed through a fixed 16 KiB
//! buffer, so a response of any size costs the same memory. Framing that
//! two parsers could read two ways is refused rather than guessed at.
//!
//! Redirects are never followed here. The caller decides, with
//! [`resolve`], where a `Location` points and whether credentials go
//! along.

use std::fmt;
use std::io::{self, Read, Write};

/// The status line and header fields together, including any 1xx interim
/// responses before the final one. Trailers get a budget of their own.
pub const MAX_HEAD: usize = 64 * 1024;
pub const MAX_HEADERS: usize = 100;
/// A chunk-size line with its extensions.
pub const MAX_CHUNK_LINE: usize = 4096;

const BUF: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A method, target, host or header the caller passed would not make
    /// a single well-formed request.
    InvalidRequest,
    HeadTooLarge,
    TooManyHeaders,
    BadStatusLine,
    /// 101: nothing here asks to switch protocols.
    UnexpectedUpgrade,
    /// A line ending in LF without CR, or a CR elsewhere.
    BadLineEnding,
    BadHeader,
    /// A field line starting with whitespace (RFC 9112 section 5.2).
    ObsFold,
    BadContentLength,
    /// Anything but a single `chunked`, or any in an HTTP/1.0 response.
    BadTransferEncoding,
    /// Both framings at once, the response smuggling ambiguity of RFC 9112
    /// section 6.1.
    LengthAndChunked,
    BadChunk,
    ChunkLineTooLong,
    Truncated,
    /// The body returned an error before and its state is not trusted.
    EarlierFailure,
    BadUrl,
    UnsupportedScheme,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::InvalidRequest => "request would not be well-formed",
            Error::HeadTooLarge => "response head too large",
            Error::TooManyHeaders => "too many header fields",
            Error::BadStatusLine => "malformed status line",
            Error::UnexpectedUpgrade => "unrequested protocol switch",
            Error::BadLineEnding => "line not ended by CRLF",
            Error::BadHeader => "malformed header field",
            Error::ObsFold => "obsolete line folding",
            Error::BadContentLength => "invalid or conflicting Content-Length",
            Error::BadTransferEncoding => "unsupported Transfer-Encoding",
            Error::LengthAndChunked => "both Content-Length and Transfer-Encoding",
            Error::BadChunk => "malformed chunk",
            Error::ChunkLineTooLong => "chunk-size line too long",
            Error::Truncated => "connection closed inside the response",
            Error::EarlierFailure => "response body failed earlier",
            Error::BadUrl => "malformed URL",
            Error::UnsupportedScheme => "URL scheme is not http or https",
        })
    }
}

impl std::error::Error for Error {}

impl From<Error> for io::Error {
    fn from(e: Error) -> io::Error {
        let kind = match e {
            Error::InvalidRequest => io::ErrorKind::InvalidInput,
            Error::Truncated => io::ErrorKind::UnexpectedEof,
            _ => io::ErrorKind::InvalidData,
        };
        io::Error::new(kind, e)
    }
}

pub struct Request<'a> {
    /// Any token; no request body is ever sent.
    pub method: &'a str,
    /// Origin form: path and query, starting with `/`.
    pub target: &'a str,
    /// The Host field value, with the port when it is not the default.
    pub host: &'a str,
    /// Host, Content-Length and Transfer-Encoding are written by
    /// [`send`] or not at all, and are refused here.
    pub headers: &'a [(&'a str, &'a str)],
}

fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

fn is_token(s: &[u8]) -> bool {
    !s.is_empty() && s.iter().all(|&b| is_tchar(b))
}

fn is_visible(b: u8) -> bool {
    (0x21..=0x7e).contains(&b)
}

/// field-vchar, SP and HTAB (RFC 9110 section 5.5): everything but the
/// controls, so no CR, LF or NUL.
fn is_field_byte(b: u8) -> bool {
    b == b'\t' || b == b' ' || is_visible(b) || b >= 0x80
}

fn trim_ows(mut s: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = s {
        s = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = s {
        s = rest;
    }
    s
}

fn encode_request(req: &Request) -> Result<Vec<u8>, Error> {
    let target = req.target.as_bytes();
    let host = req.host.as_bytes();
    let ok = is_token(req.method.as_bytes())
        && target.first() == Some(&b'/')
        && target.iter().all(|&b| is_visible(b) && b != b'#')
        && !host.is_empty()
        && host
            .iter()
            .all(|&b| is_visible(b) && !b"/?#@\\".contains(&b));
    if !ok {
        return Err(Error::InvalidRequest);
    }
    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(req.method.as_bytes());
    out.push(b' ');
    out.extend_from_slice(target);
    out.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    out.extend_from_slice(host);
    out.extend_from_slice(b"\r\n");
    for (name, value) in req.headers {
        let reserved = ["host", "content-length", "transfer-encoding"]
            .iter()
            .any(|r| name.eq_ignore_ascii_case(r));
        let value_ok = value
            .bytes()
            .all(|b| b == b'\t' || b == b' ' || is_visible(b));
        if reserved || !is_token(name.as_bytes()) || !value_ok {
            return Err(Error::InvalidRequest);
        }
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    Ok(out)
}

/// Writes the request and reads the response head. 1xx interim responses
/// are skipped. The body is read from the returned [`Response`].
pub fn send<S: Read + Write>(mut stream: S, req: &Request) -> io::Result<Response<S>> {
    let bytes = encode_request(req)?;
    stream.write_all(&bytes)?;
    stream.flush()?;
    let mut conn = Conn {
        stream,
        buf: vec![0; BUF].into_boxed_slice(),
        pos: 0,
        end: 0,
    };
    let mut line = Vec::new();
    let mut budget = MAX_HEAD;
    let (minor, status, reason, headers) = loop {
        conn.read_line(&mut line, &mut budget, Error::HeadTooLarge)?;
        let (minor, status, reason) = parse_status_line(&line)?;
        let headers = read_fields(&mut conn, &mut line, &mut budget)?;
        match status {
            101 => return Err(Error::UnexpectedUpgrade.into()),
            100..=199 => continue,
            _ => break (minor, status, reason, headers),
        }
    };

    let mut length: Option<u64> = None;
    let mut chunked = false;
    let mut keep_alive = minor == 1;
    for (name, value) in &headers {
        match name.as_str() {
            "content-length" => {
                // A list of equal values is allowed (RFC 9110 section 8.6).
                for part in value.split(',') {
                    let part = part.trim_matches([' ', '\t']);
                    if part.is_empty() || !part.bytes().all(|b| b.is_ascii_digit()) {
                        return Err(Error::BadContentLength.into());
                    }
                    let n: u64 = part.parse().map_err(|_| Error::BadContentLength)?;
                    if length.is_some_and(|l| l != n) {
                        return Err(Error::BadContentLength.into());
                    }
                    length = Some(n);
                }
            }
            "transfer-encoding" => {
                for part in value.split(',') {
                    let part = part.trim_matches([' ', '\t']);
                    if chunked || !part.eq_ignore_ascii_case("chunked") {
                        return Err(Error::BadTransferEncoding.into());
                    }
                    chunked = true;
                }
            }
            "connection" => {
                keep_alive &= !value
                    .split(',')
                    .any(|t| t.trim_matches([' ', '\t']).eq_ignore_ascii_case("close"));
            }
            _ => {}
        }
    }
    if chunked && minor == 0 {
        return Err(Error::BadTransferEncoding.into());
    }
    if chunked && length.is_some() {
        return Err(Error::LengthAndChunked.into());
    }
    let body = if req.method == "HEAD" || status == 204 || status == 304 {
        Body::Done
    } else if chunked {
        Body::Chunked(Chunk::Size)
    } else {
        match length {
            Some(0) => Body::Done,
            Some(n) => Body::Length(n),
            None => {
                keep_alive = false;
                Body::Close
            }
        }
    };
    Ok(Response {
        status,
        reason,
        headers,
        conn,
        line,
        body,
        keep_alive,
    })
}

fn parse_status_line(line: &[u8]) -> Result<(u8, u16, String), Error> {
    let rest = line.strip_prefix(b"HTTP/1.").ok_or(Error::BadStatusLine)?;
    let (minor, code, reason) = match rest {
        [m @ (b'0' | b'1'), b' ', a, b, c, tail @ ..] => {
            let reason = match tail {
                [] => &[][..],
                [b' ', r @ ..] => r,
                _ => return Err(Error::BadStatusLine),
            };
            (m - b'0', [*a, *b, *c], reason)
        }
        _ => return Err(Error::BadStatusLine),
    };
    if !code.iter().all(u8::is_ascii_digit) || code[0] == b'0' {
        return Err(Error::BadStatusLine);
    }
    if !reason.iter().all(|&b| is_field_byte(b)) {
        return Err(Error::BadStatusLine);
    }
    let status = code.iter().fold(0u16, |n, &d| n * 10 + u16::from(d - b'0'));
    Ok((minor, status, String::from_utf8_lossy(reason).into_owned()))
}

/// Field lines up to the empty line, as (lowercased name, trimmed value).
fn read_fields<S: Read>(
    conn: &mut Conn<S>,
    line: &mut Vec<u8>,
    budget: &mut usize,
) -> io::Result<Vec<(String, String)>> {
    let mut fields = Vec::new();
    loop {
        conn.read_line(line, budget, Error::HeadTooLarge)?;
        if line.is_empty() {
            return Ok(fields);
        }
        if fields.len() == MAX_HEADERS {
            return Err(Error::TooManyHeaders.into());
        }
        fields.push(parse_field(line)?);
    }
}

fn parse_field(line: &[u8]) -> Result<(String, String), Error> {
    if matches!(line.first(), Some(b' ' | b'\t')) {
        return Err(Error::ObsFold);
    }
    let colon = line
        .iter()
        .position(|&b| b == b':')
        .ok_or(Error::BadHeader)?;
    // Whitespace before the colon is refused by is_token, as RFC 9112
    // section 5.1 requires: it is a known smuggling vector.
    let (name, value) = (&line[..colon], trim_ows(&line[colon + 1..]));
    if !is_token(name) || !value.iter().all(|&b| is_field_byte(b)) {
        return Err(Error::BadHeader);
    }
    let value = String::from_utf8(value.to_vec()).map_err(|_| Error::BadHeader)?;
    let name = String::from_utf8(name.to_ascii_lowercase()).map_err(|_| Error::BadHeader)?;
    Ok((name, value))
}

struct Conn<S> {
    stream: S,
    buf: Box<[u8]>,
    pos: usize,
    end: usize,
}

impl<S: Read> Conn<S> {
    /// Refills the empty buffer. It may take in more than the response
    /// framed; [`Response::reusable`] notices what is left over.
    fn fill(&mut self) -> io::Result<usize> {
        debug_assert_eq!(self.pos, self.end);
        let n = read_retry(&mut self.stream, &mut self.buf)?;
        self.pos = 0;
        self.end = n;
        Ok(n)
    }

    /// Reads one line into `line`, without its CRLF, spending `budget`
    /// on every byte including the line ending.
    fn read_line(
        &mut self,
        line: &mut Vec<u8>,
        budget: &mut usize,
        too_long: Error,
    ) -> io::Result<()> {
        line.clear();
        loop {
            if self.pos == self.end && self.fill()? == 0 {
                return Err(Error::Truncated.into());
            }
            let avail = &self.buf[self.pos..self.end];
            let (take, done) = match avail.iter().position(|&b| b == b'\n') {
                Some(i) => (i + 1, true),
                None => (avail.len(), false),
            };
            if take > *budget {
                return Err(too_long.into());
            }
            *budget -= take;
            line.extend_from_slice(&avail[..take]);
            self.pos += take;
            if done {
                line.pop();
                if line.pop() != Some(b'\r') || line.contains(&b'\r') {
                    return Err(Error::BadLineEnding.into());
                }
                return Ok(());
            }
        }
    }

    /// Up to `max` body bytes; large reads bypass the buffer.
    fn read_some(&mut self, out: &mut [u8], max: u64) -> io::Result<usize> {
        let want = usize::try_from(max).map_or(out.len(), |m| m.min(out.len()));
        if self.pos == self.end {
            if want >= self.buf.len() {
                return read_retry(&mut self.stream, &mut out[..want]);
            }
            if self.fill()? == 0 {
                return Ok(0);
            }
        }
        let n = want.min(self.end - self.pos);
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

fn read_retry<S: Read>(stream: &mut S, out: &mut [u8]) -> io::Result<usize> {
    loop {
        match stream.read(out) {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            r => return r,
        }
    }
}

enum Body {
    Length(u64),
    Chunked(Chunk),
    Close,
    Done,
    Failed,
}

#[derive(Clone, Copy)]
enum Chunk {
    Size,
    Data(u64),
    DataEnd,
    Trailers,
}

/// The response head, and the body through `Read`.
///
/// The body ends where its framing says: Content-Length, the last chunk
/// (trailers are read and dropped), or the connection closing. HEAD
/// responses and 204 and 304 have none.
pub struct Response<S> {
    pub status: u16,
    pub reason: String,
    /// Names lowercased, in the order received.
    pub headers: Vec<(String, String)>,
    conn: Conn<S>,
    line: Vec<u8>,
    body: Body,
    keep_alive: bool,
}

impl<S> fmt::Debug for Response<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .field("reason", &self.reason)
            .field("headers", &self.headers)
            .finish_non_exhaustive()
    }
}

impl<S: Read> Response<S> {
    /// The first field with this name. Names are compared ignoring case.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// True when the body has been read to its end, the server did not
    /// send more than it framed, and neither side asked to close: the
    /// stream from [`Response::into_inner`] can carry the next request.
    pub fn reusable(&self) -> bool {
        self.keep_alive && matches!(self.body, Body::Done) && self.conn.pos == self.conn.end
    }

    /// The stream, whatever state it is in. Only pass it to [`send`]
    /// again when [`Response::reusable`] said so.
    pub fn into_inner(self) -> S {
        self.conn.stream
    }

    fn read_body(&mut self, out: &mut [u8]) -> io::Result<usize> {
        loop {
            match self.body {
                Body::Done => return Ok(0),
                Body::Failed => return Err(Error::EarlierFailure.into()),
                Body::Close => {
                    let n = self.conn.read_some(out, u64::MAX)?;
                    if n == 0 {
                        self.body = Body::Done;
                    }
                    return Ok(n);
                }
                Body::Length(left) => {
                    let n = self.conn.read_some(out, left)?;
                    if n == 0 {
                        return Err(Error::Truncated.into());
                    }
                    let left = left - n as u64;
                    self.body = if left == 0 {
                        Body::Done
                    } else {
                        Body::Length(left)
                    };
                    return Ok(n);
                }
                Body::Chunked(Chunk::Data(left)) => {
                    let n = self.conn.read_some(out, left)?;
                    if n == 0 {
                        return Err(Error::Truncated.into());
                    }
                    let left = left - n as u64;
                    self.body = Body::Chunked(if left == 0 {
                        Chunk::DataEnd
                    } else {
                        Chunk::Data(left)
                    });
                    return Ok(n);
                }
                Body::Chunked(Chunk::Size) => {
                    let mut budget = MAX_CHUNK_LINE;
                    self.conn
                        .read_line(&mut self.line, &mut budget, Error::ChunkLineTooLong)?;
                    let size = parse_chunk_size(&self.line)?;
                    self.body = Body::Chunked(if size == 0 {
                        Chunk::Trailers
                    } else {
                        Chunk::Data(size)
                    });
                }
                Body::Chunked(Chunk::DataEnd) => {
                    let mut budget = 2;
                    self.conn
                        .read_line(&mut self.line, &mut budget, Error::BadChunk)?;
                    if !self.line.is_empty() {
                        return Err(Error::BadChunk.into());
                    }
                    self.body = Body::Chunked(Chunk::Size);
                }
                Body::Chunked(Chunk::Trailers) => {
                    let mut budget = MAX_HEAD;
                    read_fields(&mut self.conn, &mut self.line, &mut budget)?;
                    self.body = Body::Done;
                }
            }
        }
    }
}

impl<S: Read> Read for Response<S> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let r = self.read_body(out);
        if r.is_err() {
            self.body = Body::Failed;
        }
        r
    }
}

/// chunk-size [ chunk-ext ] (RFC 9112 section 7.1). Extensions are
/// skipped, but may not carry control bytes.
fn parse_chunk_size(line: &[u8]) -> Result<u64, Error> {
    let digits = line.iter().take_while(|b| b.is_ascii_hexdigit()).count();
    if digits == 0 {
        return Err(Error::BadChunk);
    }
    let mut size: u64 = 0;
    for &b in &line[..digits] {
        let d = (b as char).to_digit(16).ok_or(Error::BadChunk)?;
        size = size
            .checked_mul(16)
            .and_then(|s| s.checked_add(u64::from(d)))
            .ok_or(Error::BadChunk)?;
    }
    let ext = trim_ows(&line[digits..]);
    if !(ext.is_empty() || ext[0] == b';') || !ext.iter().all(|&b| is_field_byte(b)) {
        return Err(Error::BadChunk);
    }
    Ok(size)
}

/// An absolute http or https URL, split for connecting and requesting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    /// `http` or `https`, lowercased.
    pub scheme: String,
    /// Lowercased, without brackets for an IPv6 literal, so it can be
    /// passed to a resolver as it is.
    pub host: String,
    pub port: u16,
    /// Path and query, without the fragment, dot segments removed.
    pub target: String,
}

impl Url {
    fn default_port(&self) -> u16 {
        if self.scheme == "https" {
            443
        } else {
            80
        }
    }

    /// The value for the Host field: the port only when it is not the
    /// scheme's default, brackets around an IPv6 literal.
    pub fn authority(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == self.default_port() {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

impl fmt::Display for Url {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}://{}{}", self.scheme, self.authority(), self.target)
    }
}

/// Parses `http(s)://host[:port][/path][?query][#fragment]`. User info is
/// refused: `https://registry.example@evil.example/` is the classic way
/// to make one URL look like another.
pub fn parse_url(s: &str) -> Result<Url, Error> {
    if !s.bytes().all(is_visible) {
        return Err(Error::BadUrl);
    }
    let (scheme, rest) = s.split_once("://").ok_or(Error::BadUrl)?;
    let scheme = scheme.to_ascii_lowercase();
    let default_port = match scheme.as_str() {
        "http" => 80,
        "https" => 443,
        _ => return Err(Error::UnsupportedScheme),
    };
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let (authority, tail) = rest.split_at(end);
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (host, after) = v6.split_once(']').ok_or(Error::BadUrl)?;
        let ok = host.contains(':')
            && host
                .bytes()
                .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.');
        if !ok {
            return Err(Error::BadUrl);
        }
        let port = match after {
            "" => None,
            p => Some(p.strip_prefix(':').ok_or(Error::BadUrl)?),
        };
        (host, port)
    } else {
        let (host, port) = match authority.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, None),
        };
        let ok = !host.is_empty()
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b));
        if !ok {
            return Err(Error::BadUrl);
        }
        (host, port)
    };
    let port = match port {
        None | Some("") => default_port,
        Some(p) if p.bytes().all(|b| b.is_ascii_digit()) => match p.parse::<u16>() {
            Ok(n) if n != 0 => n,
            _ => return Err(Error::BadUrl),
        },
        Some(_) => return Err(Error::BadUrl),
    };
    let tail = tail.split('#').next().unwrap_or("");
    let (path, query) = match tail.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (tail, None),
    };
    let path = if path.is_empty() { "/" } else { path };
    Ok(Url {
        scheme,
        host: host.to_ascii_lowercase(),
        port,
        target: join_target(&remove_dot_segments(path), query),
    })
}

fn join_target(path: &str, query: Option<&str>) -> String {
    match query {
        Some(q) => format!("{path}?{q}"),
        None => path.to_string(),
    }
}

/// Resolves a Location value or a reference against `base`, as RFC 3986
/// section 5.2 does. Whether to follow it, and whether credentials may go
/// to another host or from https to http, is the caller's decision.
pub fn resolve(base: &Url, location: &str) -> Result<Url, Error> {
    if !location.bytes().all(is_visible) {
        return Err(Error::BadUrl);
    }
    let reference = location.split('#').next().unwrap_or("");
    if has_scheme(reference) {
        return parse_url(reference);
    }
    if let Some(rest) = reference.strip_prefix("//") {
        return parse_url(&format!("{}://{rest}", base.scheme));
    }
    let (base_path, base_query) = match base.target.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (base.target.as_str(), None),
    };
    let (path, query) = match reference.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (reference, None),
    };
    let target = if path.is_empty() {
        join_target(base_path, query.or(base_query))
    } else if path.starts_with('/') {
        join_target(&remove_dot_segments(path), query)
    } else {
        let dir = &base_path[..base_path.rfind('/').map_or(0, |i| i + 1)];
        join_target(&remove_dot_segments(&format!("{dir}{path}")), query)
    };
    Ok(Url {
        target,
        ..base.clone()
    })
}

fn has_scheme(s: &str) -> bool {
    let Some(colon) = s.find(':') else {
        return false;
    };
    let scheme = &s.as_bytes()[..colon];
    scheme.first().is_some_and(u8::is_ascii_alphabetic)
        && scheme
            .iter()
            .all(|&b| b.is_ascii_alphanumeric() || b"+-.".contains(&b))
}

/// RFC 3986 section 5.2.4.
fn remove_dot_segments(path: &str) -> String {
    let mut input = path;
    let mut out = String::with_capacity(path.len());
    let pop = |out: &mut String| out.truncate(out.rfind('/').unwrap_or(0));
    while !input.is_empty() {
        if let Some(r) = input.strip_prefix("../").or(input.strip_prefix("./")) {
            input = r;
        } else if input.starts_with("/./") {
            input = &input[2..];
        } else if input == "/." {
            input = "/";
        } else if input.starts_with("/../") {
            input = &input[3..];
            pop(&mut out);
        } else if input == "/.." {
            input = "/";
            pop(&mut out);
        } else if input == "." || input == ".." {
            input = "";
        } else {
            let start = usize::from(input.starts_with('/'));
            let end = input[start..].find('/').map_or(input.len(), |i| i + start);
            out.push_str(&input[..end]);
            input = &input[end..];
        }
    }
    if out.is_empty() {
        out.push('/');
    }
    out
}

/// The first challenge of a WWW-Authenticate value (RFC 9110 section
/// 11.6.1), as the lowercased scheme and its parameters with lowercased
/// names and unescaped values. A challenge in token68 form, such as
/// `Basic` with a blob, has no parameters. `None` when the value is
/// malformed or names a parameter twice.
pub fn parse_www_authenticate(v: &str) -> Option<(String, Vec<(String, String)>)> {
    let s = v.as_bytes();
    let mut i = skip_ows(s, 0);
    let scheme = take_token(s, &mut i)?.to_ascii_lowercase();
    let mut params: Vec<(String, String)> = Vec::new();
    let after = skip_ows(s, i);
    if after == s.len() || s[after] == b',' {
        return Some((scheme, params));
    }
    if s[i] != b' ' {
        return None;
    }
    i = after;
    if let Some(end) = token68_end(s, i) {
        let next = skip_ows(s, end);
        if next == s.len() || s[next] == b',' {
            return Some((scheme, params));
        }
    }
    loop {
        let name = take_token(s, &mut i)?.to_ascii_lowercase();
        i = skip_ows(s, i);
        if s.get(i) != Some(&b'=') {
            return None;
        }
        i = skip_ows(s, i + 1);
        let value = if s.get(i) == Some(&b'"') {
            take_quoted(s, &mut i)?
        } else {
            take_token(s, &mut i)?.to_string()
        };
        if params.iter().any(|(n, _)| *n == name) {
            return None;
        }
        params.push((name, value));
        i = skip_ows(s, i);
        if i == s.len() {
            break;
        }
        if s[i] != b',' {
            return None;
        }
        while i < s.len() && matches!(s[i], b',' | b' ' | b'\t') {
            i += 1;
        }
        if i == s.len() {
            break;
        }
        // A token not followed by '=' starts the next challenge.
        let mut j = i;
        take_token(s, &mut j)?;
        j = skip_ows(s, j);
        if s.get(j) != Some(&b'=') {
            break;
        }
    }
    Some((scheme, params))
}

fn skip_ows(s: &[u8], mut i: usize) -> usize {
    while i < s.len() && matches!(s[i], b' ' | b'\t') {
        i += 1;
    }
    i
}

fn take_token<'a>(s: &'a [u8], i: &mut usize) -> Option<&'a str> {
    let start = *i;
    while *i < s.len() && is_tchar(s[*i]) {
        *i += 1;
    }
    if *i == start {
        return None;
    }
    std::str::from_utf8(&s[start..*i]).ok()
}

fn token68_end(s: &[u8], mut i: usize) -> Option<usize> {
    let start = i;
    while i < s.len() && (s[i].is_ascii_alphanumeric() || b"-._~+/".contains(&s[i])) {
        i += 1;
    }
    if i == start {
        return None;
    }
    while i < s.len() && s[i] == b'=' {
        i += 1;
    }
    Some(i)
}

fn take_quoted(s: &[u8], i: &mut usize) -> Option<String> {
    let mut out = Vec::new();
    *i += 1;
    loop {
        let b = *s.get(*i)?;
        *i += 1;
        match b {
            b'"' => return String::from_utf8(out).ok(),
            b'\\' => {
                let e = *s.get(*i)?;
                if !is_field_byte(e) {
                    return None;
                }
                out.push(e);
                *i += 1;
            }
            _ if is_field_byte(b) => out.push(b),
            _ => return None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// Serves `input` at most `step` bytes per read and records writes.
    struct Mock {
        input: Cursor<Vec<u8>>,
        step: usize,
        output: Vec<u8>,
    }

    impl Mock {
        fn new(input: &[u8]) -> Mock {
            Mock {
                input: Cursor::new(input.to_vec()),
                step: usize::MAX,
                output: Vec::new(),
            }
        }
    }

    impl Read for Mock {
        fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
            let n = out.len().min(self.step);
            self.input.read(&mut out[..n])
        }
    }

    impl Write for Mock {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.output.extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn get(target: &str) -> Request<'_> {
        Request {
            method: "GET",
            target,
            host: "registry.example:5000",
            headers: &[],
        }
    }

    fn kind(e: &io::Error) -> Option<Error> {
        e.get_ref().and_then(|e| e.downcast_ref::<Error>()).copied()
    }

    fn body(r: &mut Response<Mock>) -> io::Result<Vec<u8>> {
        let mut out = Vec::new();
        r.read_to_end(&mut out)?;
        Ok(out)
    }

    #[test]
    fn request_bytes() {
        let req = Request {
            method: "GET",
            target: "/v2/library/busybox/manifests/1.36?x=1",
            host: "registry.example:5000",
            headers: &[
                ("Accept", "application/vnd.oci.image.index.v1+json"),
                ("Authorization", "Bearer abc.def"),
            ],
        };
        let r = send(Mock::new(b"HTTP/1.1 204 No Content\r\n\r\n"), &req).unwrap();
        assert_eq!(
            r.into_inner().output,
            b"GET /v2/library/busybox/manifests/1.36?x=1 HTTP/1.1\r\n\
              Host: registry.example:5000\r\n\
              Accept: application/vnd.oci.image.index.v1+json\r\n\
              Authorization: Bearer abc.def\r\n\r\n"
        );
    }

    #[test]
    fn request_injection_refused() {
        let h = |headers| Request {
            headers,
            ..get("/")
        };
        let cases = [
            Request {
                method: "GET /x",
                ..get("/")
            },
            Request {
                method: "",
                ..get("/")
            },
            get("/a b"),
            get("/a\r\nX: y"),
            get("v2/"),
            get("/#frag"),
            Request {
                host: "a\r\nX: y",
                ..get("/")
            },
            Request {
                host: "evil.example/x?",
                ..get("/")
            },
            Request {
                host: "",
                ..get("/")
            },
            h(&[("X-A", "1\r\nInjected: 2")]),
            h(&[("X-A", "nul\0")]),
            h(&[("X A", "1")]),
            h(&[("X-A:", "1")]),
            h(&[("Content-Length", "5")]),
            h(&[("transfer-encoding", "chunked")]),
            h(&[("HOST", "other")]),
        ];
        for req in &cases {
            let mut stream = Mock::new(b"");
            let e = send(&mut stream, req).unwrap_err();
            assert_eq!(kind(&e), Some(Error::InvalidRequest), "{:?}", req.target);
            assert!(stream.output.is_empty());
        }
    }

    #[test]
    fn content_length_and_reuse() {
        let wire = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello";
        let mut r = send(Mock::new(wire), &get("/a")).unwrap();
        assert_eq!((r.status, r.reason.as_str()), (200, "OK"));
        assert_eq!(r.header("CONTENT-length"), Some("5"));
        assert!(!r.reusable());
        assert_eq!(body(&mut r).unwrap(), b"hello");
        assert!(r.reusable());
        let mut stream = r.into_inner();
        stream.input = Cursor::new(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nbye".to_vec());
        let mut r = send(stream, &get("/b")).unwrap();
        assert_eq!(body(&mut r).unwrap(), b"bye");

        let mut extra = wire.to_vec();
        extra.extend_from_slice(b"HTTP/1.1 200 OK\r\n");
        let mut r = send(Mock::new(&extra), &get("/a")).unwrap();
        assert_eq!(body(&mut r).unwrap(), b"hello");
        assert!(!r.reusable());

        let mut r = send(
            Mock::new(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nhello"),
            &get("/"),
        )
        .unwrap();
        let e = body(&mut r).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
        assert_eq!(
            kind(&r.read(&mut [0; 1]).unwrap_err()),
            Some(Error::EarlierFailure)
        );
    }

    #[test]
    fn chunked_with_extensions_and_trailers() {
        let wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\n\
                     5;name=\"va;l\"\r\nhello\r\n\
                     0006 ; a=b\r\n world\r\n\
                     0\r\nDigest: sha-256=x\r\nX-T: y\r\n\r\n";
        for step in [1, 3, usize::MAX] {
            let mut stream = Mock::new(wire);
            stream.step = step;
            let mut r = send(stream, &get("/")).unwrap();
            assert_eq!(body(&mut r).unwrap(), b"hello world", "step {step}");
            assert!(r.reusable());
        }
        let mut extra = wire.to_vec();
        extra.extend_from_slice(b"junk");
        let mut r = send(Mock::new(&extra), &get("/")).unwrap();
        body(&mut r).unwrap();
        assert!(!r.reusable());
    }

    #[test]
    fn close_delimited() {
        let big = vec![7u8; 100_000];
        let mut wire = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        wire.extend_from_slice(&big);
        let mut r = send(Mock::new(&wire), &get("/")).unwrap();
        assert_eq!(body(&mut r).unwrap(), big);
        assert!(!r.reusable());
    }

    #[test]
    fn responses_without_body() {
        let head = Request {
            method: "HEAD",
            ..get("/")
        };
        let wire = b"HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\
                     Docker-Content-Digest: sha256:00\r\n\r\n";
        let mut r = send(Mock::new(wire), &head).unwrap();
        assert_eq!(r.header("docker-content-digest"), Some("sha256:00"));
        assert_eq!(body(&mut r).unwrap(), b"");
        assert!(r.reusable());

        let wire = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\n\
                     HTTP/1.1 304 Not Modified\r\nContent-Length: 9\r\n\r\n";
        let mut r = send(Mock::new(wire), &get("/")).unwrap();
        assert_eq!(r.status, 304);
        assert_eq!(body(&mut r).unwrap(), b"");

        let mut r = send(Mock::new(b"HTTP/1.0 204\r\n\r\n"), &get("/")).unwrap();
        assert_eq!((r.status, r.reason.as_str()), (204, ""));
        assert_eq!(body(&mut r).unwrap(), b"");
        assert!(!r.reusable());
    }

    #[test]
    fn hostile_responses_refused() {
        let many: String = (0..=MAX_HEADERS).map(|i| format!("X-{i}: v\r\n")).collect();
        let huge = format!("X: {}\r\n", "a".repeat(MAX_HEAD));
        let long_ext = format!("1;{}\r\nx\r\n0\r\n\r\n", "e".repeat(MAX_CHUNK_LINE));
        let te = "Transfer-Encoding: chunked\r\n\r\n";
        let cases: Vec<(String, Error)> = vec![
            ("HTTP/1.1 200 OK\r\nX: a\r\n b\r\n\r\n".into(), Error::ObsFold),
            ("HTTP/1.1 200 OK\r\n X: a\r\n\r\n".into(), Error::ObsFold),
            ("HTTP/1.1 200 OK\r\nX : a\r\n\r\n".into(), Error::BadHeader),
            ("HTTP/1.1 200 OK\r\nX: a\0b\r\n\r\n".into(), Error::BadHeader),
            ("HTTP/1.1 200 OK\r\nX: a\rb\r\n\r\n".into(), Error::BadLineEnding),
            ("HTTP/1.1 200 OK\nX: a\r\n\r\n".into(), Error::BadLineEnding),
            ("HTTP/1.1 200 OK\r\nNoColon\r\n\r\n".into(), Error::BadHeader),
            (format!("HTTP/1.1 200 OK\r\n{many}\r\n"), Error::TooManyHeaders),
            (format!("HTTP/1.1 200 OK\r\n{huge}\r\n"), Error::HeadTooLarge),
            ("HTTP/2.0 200 OK\r\n\r\n".into(), Error::BadStatusLine),
            ("HTTP/1.1 20 OK\r\n\r\n".into(), Error::BadStatusLine),
            ("HTTP/1.1 099 OK\r\n\r\n".into(), Error::BadStatusLine),
            ("HTTP/1.1 101 Switching\r\n\r\n".into(), Error::UnexpectedUpgrade),
            ("HTTP/1.1 200 OK\r\nContent-Length: +5\r\n\r\n".into(), Error::BadContentLength),
            ("HTTP/1.1 200 OK\r\nContent-Length: 0x5\r\n\r\n".into(), Error::BadContentLength),
            ("HTTP/1.1 200 OK\r\nContent-Length: 5, 6\r\n\r\n".into(), Error::BadContentLength),
            ("HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n".into(), Error::BadContentLength),
            ("HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999\r\n\r\n".into(), Error::BadContentLength),
            ("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n".into(), Error::BadTransferEncoding),
            ("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n".into(), Error::BadTransferEncoding),
            ("HTTP/1.1 200 OK\r\nTransfer-Encoding: identity\r\n\r\n".into(), Error::BadTransferEncoding),
            (format!("HTTP/1.0 200 OK\r\n{te}0\r\n\r\n"), Error::BadTransferEncoding),
            (format!("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n{te}0\r\n\r\n"), Error::LengthAndChunked),
            (format!("HTTP/1.1 200 OK\r\n{te}10000000000000000\r\n"), Error::BadChunk),
            (format!("HTTP/1.1 200 OK\r\n{te}-1\r\n"), Error::BadChunk),
            (format!("HTTP/1.1 200 OK\r\n{te}1 x\r\na\r\n0\r\n\r\n"), Error::BadChunk),
            (format!("HTTP/1.1 200 OK\r\n{te}1;a\x01\r\na\r\n0\r\n\r\n"), Error::BadChunk),
            (format!("HTTP/1.1 200 OK\r\n{te}1\r\nab\r\n0\r\n\r\n"), Error::BadChunk),
            (format!("HTTP/1.1 200 OK\r\n{te}{long_ext}"), Error::ChunkLineTooLong),
            (format!("HTTP/1.1 200 OK\r\n{te}0\r\nX : y\r\n\r\n"), Error::BadHeader),
            (format!("HTTP/1.1 200 OK\r\n{te}1\r\na\r\n"), Error::Truncated),
        ];
        for (wire, want) in cases {
            let got = match send(Mock::new(wire.as_bytes()), &get("/")) {
                Ok(mut r) => body(&mut r).map(|_| ()),
                Err(e) => Err(e),
            };
            let got = got.err().and_then(|e| kind(&e));
            assert_eq!(got, Some(want), "{:?}", &wire[..wire.len().min(80)]);
        }
    }

    #[test]
    fn urls() {
        let u = parse_url("HTTPS://Registry-1.Docker.IO/v2/?a=b#frag").unwrap();
        assert_eq!(
            u,
            Url {
                scheme: "https".into(),
                host: "registry-1.docker.io".into(),
                port: 443,
                target: "/v2/?a=b".into(),
            }
        );
        assert_eq!(u.authority(), "registry-1.docker.io");
        let u = parse_url("http://[::1]:5000?q").unwrap();
        assert_eq!(
            (u.host.as_str(), u.port, u.target.as_str()),
            ("::1", 5000, "/?q")
        );
        assert_eq!(u.authority(), "[::1]:5000");
        assert_eq!(parse_url("http://h:/").unwrap().port, 80);

        for bad in [
            "ftp://h/",
            "file:///etc/passwd",
            "https://registry.example@evil.example/",
            "http://h:0/",
            "http://h:65536/",
            "http://h:8a/",
            "http:///x",
            "http://h x/",
            "http://h/\u{e9}",
            "http://[zz]/",
            "http://[::1/",
            "//h/x",
        ] {
            assert!(parse_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn rfc3986_resolution() {
        let base = parse_url("http://a/b/c/d;p?q").unwrap();
        // RFC 3986 section 5.4, all examples with an http result.
        let cases = [
            ("g", "http://a/b/c/g"),
            ("./g", "http://a/b/c/g"),
            ("g/", "http://a/b/c/g/"),
            ("/g", "http://a/g"),
            ("//g", "http://g/"),
            ("?y", "http://a/b/c/d;p?y"),
            ("g?y", "http://a/b/c/g?y"),
            ("#s", "http://a/b/c/d;p?q"),
            ("g#s", "http://a/b/c/g"),
            ("g?y#s", "http://a/b/c/g?y"),
            (";x", "http://a/b/c/;x"),
            ("g;x", "http://a/b/c/g;x"),
            ("", "http://a/b/c/d;p?q"),
            (".", "http://a/b/c/"),
            ("./", "http://a/b/c/"),
            ("..", "http://a/b/"),
            ("../", "http://a/b/"),
            ("../g", "http://a/b/g"),
            ("../..", "http://a/"),
            ("../../", "http://a/"),
            ("../../g", "http://a/g"),
            ("../../../g", "http://a/g"),
            ("../../../../g", "http://a/g"),
            ("/./g", "http://a/g"),
            ("/../g", "http://a/g"),
            ("g.", "http://a/b/c/g."),
            (".g", "http://a/b/c/.g"),
            ("g..", "http://a/b/c/g.."),
            ("..g", "http://a/b/c/..g"),
            ("./../g", "http://a/b/g"),
            ("./g/.", "http://a/b/c/g/"),
            ("g/./h", "http://a/b/c/g/h"),
            ("g/../h", "http://a/b/c/h"),
            ("g;x=1/./y", "http://a/b/c/g;x=1/y"),
            ("g;x=1/../y", "http://a/b/c/y"),
            ("g?y/./x", "http://a/b/c/g?y/./x"),
            ("g#s/../x", "http://a/b/c/g"),
            (
                "https://s3.example/blob?sig=1",
                "https://s3.example/blob?sig=1",
            ),
        ];
        for (reference, want) in cases {
            assert_eq!(
                resolve(&base, reference).unwrap().to_string(),
                want,
                "{reference}"
            );
        }
        let tls = parse_url("https://r.example:5000/v2/x").unwrap();
        assert_eq!(
            resolve(&tls, "//cdn.example/y").unwrap().to_string(),
            "https://cdn.example/y"
        );
        assert!(resolve(&base, "/a b").is_err());
        assert!(resolve(&base, "gopher://x/").is_err());
    }

    #[test]
    fn www_authenticate() {
        let v = r#"Bearer realm="https://auth.docker.io/token",service="registry.docker.io",scope="repository:library/busybox:pull,push""#;
        let (scheme, params) = parse_www_authenticate(v).unwrap();
        assert_eq!(scheme, "bearer");
        let p = |n: &str, v: &str| (n.to_string(), v.to_string());
        assert_eq!(
            params,
            [
                p("realm", "https://auth.docker.io/token"),
                p("service", "registry.docker.io"),
                p("scope", "repository:library/busybox:pull,push"),
            ]
        );
        let (_, params) = parse_www_authenticate(
            r#"Bearer  Realm = "a \"q\", \\ b" , error=invalid_token, Basic realm="x""#,
        )
        .unwrap();
        assert_eq!(
            params,
            [p("realm", r#"a "q", \ b"#), p("error", "invalid_token")]
        );
        assert_eq!(
            parse_www_authenticate("Basic dGVzdA=="),
            Some(("basic".into(), vec![]))
        );
        assert_eq!(
            parse_www_authenticate("Negotiate"),
            Some(("negotiate".into(), vec![]))
        );
        for bad in [
            "",
            r#"Bearer realm="unterminated"#,
            r#"Bearer realm="a",realm="b""#,
            r#"Bearer realm=a b"#,
            "Bearer realm=\"a\x01\"",
            r#"Bearer="x""#,
        ] {
            assert_eq!(parse_www_authenticate(bad), None, "{bad}");
        }
    }

    #[test]
    fn over_tcp() {
        use std::net::{TcpListener, TcpStream};
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut seen = Vec::new();
            for reply in [
                &b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nblob\r\n0\r\n\r\n"[..],
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
            ] {
                let mut req = Vec::new();
                let mut b = [0u8; 1];
                while !req.ends_with(b"\r\n\r\n") {
                    s.read_exact(&mut b).unwrap();
                    req.push(b[0]);
                }
                seen.push(req);
                s.write_all(reply).unwrap();
            }
            seen
        });
        let url = parse_url(&format!("http://{addr}/v2/x/blobs/sha256:00")).unwrap();
        let stream = TcpStream::connect((url.host.as_str(), url.port)).unwrap();
        let host = url.authority();
        let req = Request {
            method: "GET",
            target: &url.target,
            host: &host,
            headers: &[],
        };
        let mut r = send(stream, &req).unwrap();
        let mut got = String::new();
        r.read_to_string(&mut got).unwrap();
        assert_eq!(got, "blob");
        assert!(r.reusable());
        let mut r = send(r.into_inner(), &req).unwrap();
        got.clear();
        r.read_to_string(&mut got).unwrap();
        assert_eq!(got, "ok");
        assert!(!r.reusable());
        let want = format!("GET /v2/x/blobs/sha256:00 HTTP/1.1\r\nHost: {addr}\r\n\r\n");
        assert_eq!(server.join().unwrap(), [want.as_bytes(), want.as_bytes()]);
    }
}
