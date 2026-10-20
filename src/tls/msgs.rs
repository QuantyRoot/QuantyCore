//! Handshake messages and extensions of TLS 1.3 (RFC 8446 section 4), and
//! the numbers that name things on the wire.
//!
//! Extensions are kept as raw `(type, data)` pairs in the order they
//! arrived and parsed on demand. That keeps a received message byte for
//! byte re-encodable, which the transcript hash depends on, and lets
//! unknown extensions pass through untouched as the RFC requires.

use super::codec::{put_bytes, put_u16, put_u24, put_vec, Reader};
use super::error::Error;

pub mod content {
    pub const CHANGE_CIPHER_SPEC: u8 = 20;
    pub const ALERT: u8 = 21;
    pub const HANDSHAKE: u8 = 22;
    pub const APPLICATION_DATA: u8 = 23;
}

pub mod hs {
    pub const CLIENT_HELLO: u8 = 1;
    pub const SERVER_HELLO: u8 = 2;
    pub const NEW_SESSION_TICKET: u8 = 4;
    pub const END_OF_EARLY_DATA: u8 = 5;
    pub const ENCRYPTED_EXTENSIONS: u8 = 8;
    pub const CERTIFICATE: u8 = 11;
    pub const SERVER_KEY_EXCHANGE: u8 = 12;
    pub const CERTIFICATE_REQUEST: u8 = 13;
    pub const SERVER_HELLO_DONE: u8 = 14;
    pub const CERTIFICATE_VERIFY: u8 = 15;
    pub const CLIENT_KEY_EXCHANGE: u8 = 16;
    pub const FINISHED: u8 = 20;
    pub const KEY_UPDATE: u8 = 24;
    pub const MESSAGE_HASH: u8 = 254;
}

pub mod ext {
    pub const SERVER_NAME: u16 = 0;
    pub const STATUS_REQUEST: u16 = 5;
    pub const SUPPORTED_GROUPS: u16 = 10;
    pub const EC_POINT_FORMATS: u16 = 11;
    pub const SIGNATURE_ALGORITHMS: u16 = 13;
    pub const ALPN: u16 = 16;
    pub const EXTENDED_MASTER_SECRET: u16 = 23;
    pub const RECORD_SIZE_LIMIT: u16 = 28;
    pub const SESSION_TICKET: u16 = 35;
    pub const PRE_SHARED_KEY: u16 = 41;
    pub const EARLY_DATA: u16 = 42;
    pub const SUPPORTED_VERSIONS: u16 = 43;
    pub const COOKIE: u16 = 44;
    pub const PSK_KEY_EXCHANGE_MODES: u16 = 45;
    pub const CERTIFICATE_AUTHORITIES: u16 = 47;
    pub const SIGNATURE_ALGORITHMS_CERT: u16 = 50;
    pub const KEY_SHARE: u16 = 51;
    pub const RENEGOTIATION_INFO: u16 = 0xff01;
}

pub mod group {
    pub const SECP256R1: u16 = 0x0017;
    pub const SECP384R1: u16 = 0x0018;
    pub const X25519: u16 = 0x001d;
    pub const X25519MLKEM768: u16 = 0x11ec;
}

pub mod version {
    pub const TLS12: u16 = 0x0303;
    pub const TLS13: u16 = 0x0304;
}

/// `HelloRetryRequest` is a ServerHello with this random (RFC 8446 4.1.3),
/// the SHA-256 of "HelloRetryRequest".
pub const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// The last 8 bytes of a TLS 1.3 server's random when it negotiates TLS
/// 1.2, and of a 1.2 server's when it would have done 1.1 (RFC 8446
/// 4.1.3). A client that sees them downgraded by an attacker aborts.
pub const DOWNGRADE_TLS12: [u8; 8] = *b"DOWNGRD\x01";
pub const DOWNGRADE_TLS11: [u8; 8] = *b"DOWNGRD\x00";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extension {
    pub typ: u16,
    pub data: Vec<u8>,
}

fn read_extensions(r: &mut Reader) -> Result<Vec<Extension>, Error> {
    // A hello with no extensions block at all is valid TLS 1.2 (RFC 5246
    // 7.4.1.2); everything here reads it as an empty block.
    if r.is_empty() {
        return Ok(Vec::new());
    }
    read_extension_list(r.vec16().ok_or(Error::decode("extensions"))?)
}

/// The extensions of a block whose length prefix was already read.
fn read_extension_list(data: &[u8]) -> Result<Vec<Extension>, Error> {
    let mut block = Reader::new(data);
    let mut out: Vec<Extension> = Vec::new();
    while !block.is_empty() {
        let typ = block.u16().ok_or(Error::decode("extension type"))?;
        let data = block.vec16().ok_or(Error::decode("extension body"))?;
        if out.iter().any(|e| e.typ == typ) {
            return Err(Error::illegal("duplicate extension"));
        }
        out.push(Extension {
            typ,
            data: data.to_vec(),
        });
    }
    Ok(out)
}

fn write_extensions(out: &mut Vec<u8>, exts: &[Extension]) {
    put_vec(out, 2, |o| {
        for e in exts {
            put_u16(o, e.typ);
            put_bytes(o, 2, &e.data);
        }
    });
}

pub fn find(exts: &[Extension], typ: u16) -> Option<&[u8]> {
    exts.iter()
        .find(|e| e.typ == typ)
        .map(|e| e.data.as_slice())
}

/// One handshake message: its type and body, without the four byte
/// header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Handshake {
    pub typ: u8,
    pub body: Vec<u8>,
}

impl Handshake {
    pub fn new(typ: u8, body: Vec<u8>) -> Handshake {
        Handshake { typ, body }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.body.len());
        out.push(self.typ);
        put_u24(&mut out, self.body.len() as u32);
        out.extend_from_slice(&self.body);
        out
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientHello {
    pub legacy_version: u16,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suites: Vec<u16>,
    pub compression: Vec<u8>,
    pub extensions: Vec<Extension>,
}

impl ClientHello {
    pub fn parse(body: &[u8]) -> Result<ClientHello, Error> {
        let d = || Error::decode("ClientHello");
        let mut r = Reader::new(body);
        let legacy_version = r.u16().ok_or_else(d)?;
        let random = r.take(32).ok_or_else(d)?.try_into().unwrap();
        let session_id = r.vec8().ok_or_else(d)?.to_vec();
        if session_id.len() > 32 {
            return Err(Error::illegal("session id longer than 32 bytes"));
        }
        let suites = r.vec16().ok_or_else(d)?;
        if suites.len() % 2 != 0 {
            return Err(d());
        }
        let cipher_suites = suites
            .chunks(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        let compression = r.vec8().ok_or_else(d)?.to_vec();
        let extensions = read_extensions(&mut r)?;
        r.end().ok_or_else(d)?;
        Ok(ClientHello {
            legacy_version,
            random,
            session_id,
            cipher_suites,
            compression,
            extensions,
        })
    }

    pub fn encode(&self) -> Handshake {
        let mut b = Vec::new();
        put_u16(&mut b, self.legacy_version);
        b.extend_from_slice(&self.random);
        put_bytes(&mut b, 1, &self.session_id);
        put_vec(&mut b, 2, |o| {
            for s in &self.cipher_suites {
                put_u16(o, *s);
            }
        });
        put_bytes(&mut b, 1, &self.compression);
        write_extensions(&mut b, &self.extensions);
        Handshake::new(hs::CLIENT_HELLO, b)
    }

    pub fn ext(&self, typ: u16) -> Option<&[u8]> {
        find(&self.extensions, typ)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerHello {
    pub legacy_version: u16,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub cipher_suite: u16,
    pub compression: u8,
    pub extensions: Vec<Extension>,
}

impl ServerHello {
    pub fn parse(body: &[u8]) -> Result<ServerHello, Error> {
        let d = || Error::decode("ServerHello");
        let mut r = Reader::new(body);
        let legacy_version = r.u16().ok_or_else(d)?;
        let random = r.take(32).ok_or_else(d)?.try_into().unwrap();
        let session_id = r.vec8().ok_or_else(d)?.to_vec();
        if session_id.len() > 32 {
            return Err(Error::illegal("session id longer than 32 bytes"));
        }
        let cipher_suite = r.u16().ok_or_else(d)?;
        let compression = r.u8().ok_or_else(d)?;
        let extensions = read_extensions(&mut r)?;
        r.end().ok_or_else(d)?;
        Ok(ServerHello {
            legacy_version,
            random,
            session_id,
            cipher_suite,
            compression,
            extensions,
        })
    }

    pub fn encode(&self) -> Handshake {
        let mut b = Vec::new();
        put_u16(&mut b, self.legacy_version);
        b.extend_from_slice(&self.random);
        put_bytes(&mut b, 1, &self.session_id);
        put_u16(&mut b, self.cipher_suite);
        b.push(self.compression);
        write_extensions(&mut b, &self.extensions);
        Handshake::new(hs::SERVER_HELLO, b)
    }

    pub fn is_retry_request(&self) -> bool {
        self.random == HRR_RANDOM
    }

    pub fn ext(&self, typ: u16) -> Option<&[u8]> {
        find(&self.extensions, typ)
    }
}

/// A message whose whole body is one extensions block:
/// EncryptedExtensions.
pub fn parse_extensions_only(body: &[u8]) -> Result<Vec<Extension>, Error> {
    let mut r = Reader::new(body);
    if r.is_empty() {
        return Err(Error::decode("missing extensions block"));
    }
    let exts = read_extensions(&mut r)?;
    r.end().ok_or(Error::decode("trailing data"))?;
    Ok(exts)
}

pub fn encode_extensions_only(typ: u8, exts: &[Extension]) -> Handshake {
    let mut b = Vec::new();
    write_extensions(&mut b, exts);
    Handshake::new(typ, b)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateRequest {
    pub context: Vec<u8>,
    pub extensions: Vec<Extension>,
}

impl CertificateRequest {
    pub fn parse(body: &[u8]) -> Result<CertificateRequest, Error> {
        let d = || Error::decode("CertificateRequest");
        let mut r = Reader::new(body);
        let context = r.vec8().ok_or_else(d)?.to_vec();
        if r.is_empty() {
            return Err(d());
        }
        let extensions = read_extensions(&mut r)?;
        r.end().ok_or_else(d)?;
        Ok(CertificateRequest {
            context,
            extensions,
        })
    }

    pub fn encode(&self) -> Handshake {
        let mut b = Vec::new();
        put_bytes(&mut b, 1, &self.context);
        write_extensions(&mut b, &self.extensions);
        Handshake::new(hs::CERTIFICATE_REQUEST, b)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateEntry {
    pub der: Vec<u8>,
    pub extensions: Vec<Extension>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    pub context: Vec<u8>,
    pub entries: Vec<CertificateEntry>,
}

impl Certificate {
    pub fn parse(body: &[u8]) -> Result<Certificate, Error> {
        let d = || Error::decode("Certificate");
        let mut r = Reader::new(body);
        let context = r.vec8().ok_or_else(d)?.to_vec();
        let mut list = Reader::new(r.vec24().ok_or_else(d)?);
        r.end().ok_or_else(d)?;
        let mut entries = Vec::new();
        while !list.is_empty() {
            let der = list.vec24().ok_or_else(d)?;
            if der.is_empty() {
                return Err(d());
            }
            let extensions = read_extension_list(list.vec16().ok_or_else(d)?)?;
            entries.push(CertificateEntry {
                der: der.to_vec(),
                extensions,
            });
        }
        Ok(Certificate { context, entries })
    }

    pub fn encode(&self) -> Handshake {
        let mut b = Vec::new();
        put_bytes(&mut b, 1, &self.context);
        put_vec(&mut b, 3, |o| {
            for e in &self.entries {
                put_bytes(o, 3, &e.der);
                write_extensions(o, &e.extensions);
            }
        });
        Handshake::new(hs::CERTIFICATE, b)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateVerify {
    pub scheme: u16,
    pub signature: Vec<u8>,
}

impl CertificateVerify {
    pub fn parse(body: &[u8]) -> Result<CertificateVerify, Error> {
        let d = || Error::decode("CertificateVerify");
        let mut r = Reader::new(body);
        let scheme = r.u16().ok_or_else(d)?;
        let signature = r.vec16().ok_or_else(d)?.to_vec();
        r.end().ok_or_else(d)?;
        Ok(CertificateVerify { scheme, signature })
    }

    pub fn encode(&self) -> Handshake {
        let mut b = Vec::new();
        put_u16(&mut b, self.scheme);
        put_bytes(&mut b, 2, &self.signature);
        Handshake::new(hs::CERTIFICATE_VERIFY, b)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NewSessionTicket {
    pub lifetime: u32,
    pub age_add: u32,
    pub nonce: Vec<u8>,
    pub ticket: Vec<u8>,
    pub extensions: Vec<Extension>,
}

impl NewSessionTicket {
    pub fn parse(body: &[u8]) -> Result<NewSessionTicket, Error> {
        let d = || Error::decode("NewSessionTicket");
        let mut r = Reader::new(body);
        let lifetime = r.u32().ok_or_else(d)?;
        let age_add = r.u32().ok_or_else(d)?;
        let nonce = r.vec8().ok_or_else(d)?.to_vec();
        let ticket = r.vec16().ok_or_else(d)?.to_vec();
        if ticket.is_empty() || r.is_empty() {
            return Err(d());
        }
        let extensions = read_extensions(&mut r)?;
        r.end().ok_or_else(d)?;
        Ok(NewSessionTicket {
            lifetime,
            age_add,
            nonce,
            ticket,
            extensions,
        })
    }

    pub fn encode(&self) -> Handshake {
        let mut b = Vec::new();
        b.extend_from_slice(&self.lifetime.to_be_bytes());
        b.extend_from_slice(&self.age_add.to_be_bytes());
        put_bytes(&mut b, 1, &self.nonce);
        put_bytes(&mut b, 2, &self.ticket);
        write_extensions(&mut b, &self.extensions);
        Handshake::new(hs::NEW_SESSION_TICKET, b)
    }
}

pub fn put_u16_list(out: &mut Vec<u8>, len_bytes: usize, list: &[u16]) {
    put_vec(out, len_bytes, |o| {
        for v in list {
            put_u16(o, *v);
        }
    });
}

/// A list of `u16` behind a length of `len_bytes` bytes, the whole of
/// `data`. Empty lists are refused: no extension here allows one.
pub fn read_u16_list(data: &[u8], len_bytes: usize) -> Result<Vec<u16>, Error> {
    let d = || Error::decode("list of u16");
    let mut r = Reader::new(data);
    let body = match len_bytes {
        1 => r.vec8(),
        _ => r.vec16(),
    }
    .ok_or_else(d)?;
    r.end().ok_or_else(d)?;
    if body.is_empty() || body.len() % 2 != 0 {
        return Err(d());
    }
    Ok(body
        .chunks(2)
        .map(|c| u16::from_be_bytes([c[0], c[1]]))
        .collect())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyShareEntry {
    pub group: u16,
    pub key: Vec<u8>,
}

pub fn read_client_key_shares(data: &[u8]) -> Result<Vec<KeyShareEntry>, Error> {
    let d = || Error::decode("key_share");
    let mut r = Reader::new(data);
    let mut list = Reader::new(r.vec16().ok_or_else(d)?);
    r.end().ok_or_else(d)?;
    let mut out: Vec<KeyShareEntry> = Vec::new();
    while !list.is_empty() {
        let group = list.u16().ok_or_else(d)?;
        let key = list.vec16().ok_or_else(d)?;
        if key.is_empty() {
            return Err(d());
        }
        if out.iter().any(|e| e.group == group) {
            return Err(Error::illegal("two key shares for one group"));
        }
        out.push(KeyShareEntry {
            group,
            key: key.to_vec(),
        });
    }
    Ok(out)
}

pub fn write_client_key_shares(shares: &[KeyShareEntry]) -> Vec<u8> {
    let mut out = Vec::new();
    put_vec(&mut out, 2, |o| {
        for s in shares {
            put_u16(o, s.group);
            put_bytes(o, 2, &s.key);
        }
    });
    out
}

pub fn read_server_key_share(data: &[u8]) -> Result<KeyShareEntry, Error> {
    let d = || Error::decode("key_share");
    let mut r = Reader::new(data);
    let group = r.u16().ok_or_else(d)?;
    let key = r.vec16().ok_or_else(d)?.to_vec();
    r.end().ok_or_else(d)?;
    if key.is_empty() {
        return Err(d());
    }
    Ok(KeyShareEntry { group, key })
}

pub fn write_server_key_share(s: &KeyShareEntry) -> Vec<u8> {
    let mut out = Vec::new();
    put_u16(&mut out, s.group);
    put_bytes(&mut out, 2, &s.key);
    out
}

/// The host name from a client's server_name extension. Only `host_name`
/// entries exist (RFC 6066 3); a list with two of them is invalid.
pub fn read_server_name(data: &[u8]) -> Result<Option<String>, Error> {
    let d = || Error::decode("server_name");
    let mut r = Reader::new(data);
    let mut list = Reader::new(r.vec16().ok_or_else(d)?);
    r.end().ok_or_else(d)?;
    let mut name = None;
    while !list.is_empty() {
        let typ = list.u8().ok_or_else(d)?;
        let v = list.vec16().ok_or_else(d)?;
        if typ != 0 {
            continue;
        }
        if name.is_some() {
            return Err(Error::illegal("two host names"));
        }
        let s = std::str::from_utf8(v).map_err(|_| d())?;
        if s.is_empty() || !s.is_ascii() || s.ends_with('.') {
            return Err(Error::illegal("host name"));
        }
        name = Some(s.to_ascii_lowercase());
    }
    Ok(name)
}

pub fn write_server_name(host: &str) -> Vec<u8> {
    let mut out = Vec::new();
    put_vec(&mut out, 2, |o| {
        o.push(0);
        put_bytes(o, 2, host.as_bytes());
    });
    out
}

/// ALPN protocol names (RFC 7301): a nonempty list of nonempty names.
pub fn read_alpn(data: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    let d = || Error::decode("application_layer_protocol_negotiation");
    let mut r = Reader::new(data);
    let mut list = Reader::new(r.vec16().ok_or_else(d)?);
    r.end().ok_or_else(d)?;
    let mut out = Vec::new();
    while !list.is_empty() {
        let p = list.vec8().ok_or_else(d)?;
        if p.is_empty() {
            return Err(d());
        }
        out.push(p.to_vec());
    }
    if out.is_empty() {
        return Err(d());
    }
    Ok(out)
}

pub fn write_alpn(protocols: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    put_vec(&mut out, 2, |o| {
        for p in protocols {
            put_bytes(o, 1, p);
        }
    });
    out
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PskIdentity {
    pub identity: Vec<u8>,
    pub obfuscated_age: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OfferedPsks {
    pub identities: Vec<PskIdentity>,
    pub binders: Vec<Vec<u8>>,
}

pub fn read_offered_psks(data: &[u8]) -> Result<OfferedPsks, Error> {
    let d = || Error::decode("pre_shared_key");
    let mut r = Reader::new(data);
    let mut ids = Reader::new(r.vec16().ok_or_else(d)?);
    let mut bs = Reader::new(r.vec16().ok_or_else(d)?);
    r.end().ok_or_else(d)?;
    let mut identities = Vec::new();
    while !ids.is_empty() {
        let identity = ids.vec16().ok_or_else(d)?;
        let obfuscated_age = ids.u32().ok_or_else(d)?;
        if identity.is_empty() {
            return Err(d());
        }
        identities.push(PskIdentity {
            identity: identity.to_vec(),
            obfuscated_age,
        });
    }
    let mut binders = Vec::new();
    while !bs.is_empty() {
        let b = bs.vec8().ok_or_else(d)?;
        if b.len() < 32 {
            return Err(d());
        }
        binders.push(b.to_vec());
    }
    if identities.is_empty() || identities.len() != binders.len() {
        return Err(Error::illegal("pre_shared_key identities and binders"));
    }
    Ok(OfferedPsks {
        identities,
        binders,
    })
}

pub fn write_offered_psks(p: &OfferedPsks) -> Vec<u8> {
    let mut out = Vec::new();
    put_vec(&mut out, 2, |o| {
        for id in &p.identities {
            put_bytes(o, 2, &id.identity);
            o.extend_from_slice(&id.obfuscated_age.to_be_bytes());
        }
    });
    put_vec(&mut out, 2, |o| {
        for b in &p.binders {
            put_bytes(o, 1, b);
        }
    });
    out
}

/// The length of the binders list as it will be encoded, which is what
/// the partial ClientHello for the binder hash leaves off (RFC 8446
/// 4.2.11.2).
pub fn binders_len(binders: &[Vec<u8>]) -> usize {
    2 + binders.iter().map(|b| 1 + b.len()).sum::<usize>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_extensions_are_refused() {
        let mut ch = ClientHello {
            legacy_version: version::TLS12,
            random: [0; 32],
            session_id: vec![],
            cipher_suites: vec![0x1301],
            compression: vec![0],
            extensions: vec![
                Extension {
                    typ: ext::SUPPORTED_GROUPS,
                    data: vec![0, 2, 0, 0x1d],
                },
                Extension {
                    typ: ext::KEY_SHARE,
                    data: vec![0, 0],
                },
            ],
        };
        let body = ch.encode().body;
        assert_eq!(ClientHello::parse(&body).unwrap(), ch);
        ch.extensions[1].typ = ext::SUPPORTED_GROUPS;
        assert_eq!(
            ClientHello::parse(&ch.encode().body),
            Err(Error::illegal("duplicate extension"))
        );
    }

    #[test]
    fn truncated_messages_are_decode_errors() {
        let sh = ServerHello {
            legacy_version: version::TLS12,
            random: [7; 32],
            session_id: vec![1; 32],
            cipher_suite: 0x1301,
            compression: 0,
            extensions: vec![Extension {
                typ: ext::SUPPORTED_VERSIONS,
                data: vec![3, 4],
            }],
        };
        let body = sh.encode().body;
        // Cut just before the extensions block it is a valid TLS 1.2
        // ServerHello without extensions; everywhere else it is broken.
        let no_ext = body.len() - 8;
        for n in 0..body.len() {
            if let Ok(h) = ServerHello::parse(&body[..n]) {
                assert!(n == no_ext && h.extensions.is_empty(), "length {n}");
            }
        }
        assert_eq!(ServerHello::parse(&body).unwrap(), sh);
    }
}
