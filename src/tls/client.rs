//! The TLS 1.3 client handshake (RFC 8446 section 4 and appendix A.1).

use super::auth::{signed_content, with_pkcs1, PublicKey};
use super::client12;
use super::config::{ClientConfig, StoredTicket, TicketCache};
use super::conn::{Connected, Connection, Core, State, Transcript};
use super::crypto::ct::Secret;
use super::crypto::rand;
use super::error::{alert, Error};
use super::key_schedule::{finished_verify_data, resumption_psk, verify_finished, KeySchedule};
use super::kx::KxSecret;
use super::msgs::*;
use super::suites::{tls13_suite, Suite, ALL_TLS12};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// The longest ticket lifetime a server may announce (RFC 8446 4.6.1).
const MAX_TICKET_LIFETIME: u32 = 7 * 24 * 3600;

pub struct ClientConnection(Connection);

impl std::ops::Deref for ClientConnection {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        &self.0
    }
}

impl std::ops::DerefMut for ClientConnection {
    fn deref_mut(&mut self) -> &mut Connection {
        &mut self.0
    }
}

/// What the client sent in its ClientHello and keeps to check the
/// server's answers against.
pub(super) struct Offer {
    pub(super) config: Arc<ClientConfig>,
    pub(super) name: Option<String>,
    pub(super) session_id: Vec<u8>,
    pub(super) suites: Vec<u16>,
    pub(super) extensions: Vec<u16>,
    /// One share, or two when the first group is the hybrid: X25519 as
    /// well, so that a server without ML-KEM needs no second round trip.
    pub(super) kx: Vec<KxSecret>,
    ticket: Option<StoredTicket>,
}

impl ClientConnection {
    /// Starts a handshake with the server called `name`, which is sent as
    /// SNI and checked against the server's certificate. The ClientHello
    /// is ready in `take_tls` when this returns.
    pub fn new(config: Arc<ClientConfig>, name: &str) -> Result<ClientConnection, Error> {
        let mut random = [0u8; 32];
        let mut session_id = vec![0u8; 32];
        rand::fill(&mut random).map_err(|_| Error::internal("no randomness"))?;
        rand::fill(&mut session_id).map_err(|_| Error::internal("no randomness"))?;
        let group = *config.groups.first().ok_or(Error::internal("no groups"))?;
        let mut kx = vec![KxSecret::generate(group)?];
        if group == group::X25519MLKEM768 && config.groups.contains(&group::X25519) {
            kx.push(KxSecret::generate(group::X25519)?);
        }
        let ticket = config.tickets.as_ref().and_then(|c| c.take(name));
        let hello = build_hello(&config, name, random, session_id, &kx, ticket.as_ref());
        Self::from_hello(config, Some(name.to_string()), hello, kx, ticket)
    }

    /// Continues from a ClientHello that is already built. Every
    /// connection goes through here; the RFC 8448 test enters here with
    /// the trace's hello and key.
    pub(crate) fn from_hello(
        config: Arc<ClientConfig>,
        name: Option<String>,
        mut hello: ClientHello,
        kx: Vec<KxSecret>,
        ticket: Option<StoredTicket>,
    ) -> Result<ClientConnection, Error> {
        let mut core = Core::new();
        core.first_record_version = Some(0x0301);
        let mut transcript = Transcript::new();
        if let Some(t) = &ticket {
            fill_binder(&mut hello, t, &transcript);
        }
        let raw = core.send_hs(&hello.encode());
        transcript.add(&raw);
        core.flush_hs()?;
        let offer = Offer {
            config,
            name,
            session_id: hello.session_id.clone(),
            suites: hello.cipher_suites.clone(),
            extensions: hello.extensions.iter().map(|e| e.typ).collect(),
            kx,
            ticket,
        };
        let state = ExpectServerHello {
            offer,
            hello,
            transcript,
            retried: false,
        };
        Ok(ClientConnection(Connection::new(core, Box::new(state))))
    }
}

fn build_hello(
    config: &ClientConfig,
    name: &str,
    random: [u8; 32],
    session_id: Vec<u8>,
    kx: &[KxSecret],
    ticket: Option<&StoredTicket>,
) -> ClientHello {
    let mut exts = Vec::new();
    let mut add = |typ: u16, data: Vec<u8>| exts.push(Extension { typ, data });
    // SNI carries host names only; an address is matched against the
    // certificate's IP entries instead (RFC 6066 3).
    if name.parse::<std::net::IpAddr>().is_err() {
        add(ext::SERVER_NAME, write_server_name(name));
    }
    let mut v = Vec::new();
    if config.tls12 {
        put_u16_list_u8(&mut v, &[version::TLS13, version::TLS12]);
    } else {
        put_u16_list_u8(&mut v, &[version::TLS13]);
    }
    add(ext::SUPPORTED_VERSIONS, v);
    let mut g = Vec::new();
    put_u16_list(&mut g, 2, &config.groups);
    add(ext::SUPPORTED_GROUPS, g);
    add(
        ext::KEY_SHARE,
        write_client_key_shares(
            &kx.iter()
                .map(|k| KeyShareEntry {
                    group: k.group(),
                    key: k.public(),
                })
                .collect::<Vec<_>>(),
        ),
    );
    let mut s = Vec::new();
    put_u16_list(&mut s, 2, &offered_schemes(config));
    add(ext::SIGNATURE_ALGORITHMS, s);
    if config.tls12 {
        add(ext::EC_POINT_FORMATS, vec![1, 0]);
        add(ext::EXTENDED_MASTER_SECRET, Vec::new());
        add(ext::RENEGOTIATION_INFO, vec![0]);
    }
    if !config.alpn.is_empty() {
        add(ext::ALPN, write_alpn(&config.alpn));
    }
    if config.tickets.is_some() {
        // psk_dhe_ke only: resumption always runs a fresh key exchange, so
        // a stolen ticket does not decrypt the resumed connection.
        add(ext::PSK_KEY_EXCHANGE_MODES, vec![1, 1]);
    }
    if let Some(t) = ticket {
        let age = SystemTime::now()
            .duration_since(t.received)
            .unwrap_or_default()
            .as_millis() as u32;
        let psks = OfferedPsks {
            identities: vec![PskIdentity {
                identity: t.ticket.clone(),
                obfuscated_age: age.wrapping_add(t.age_add),
            }],
            binders: vec![vec![0; t.suite.hash.output_len()]],
        };
        add(ext::PRE_SHARED_KEY, write_offered_psks(&psks));
    }
    let mut cipher_suites: Vec<u16> = config.suites.iter().map(|s| s.id).collect();
    if config.tls12 {
        cipher_suites.extend(ALL_TLS12.iter().map(|s| s.id));
    }
    ClientHello {
        legacy_version: version::TLS12,
        random,
        session_id,
        cipher_suites,
        compression: vec![0],
        extensions: exts,
    }
}

/// The signature_algorithms list: what the verifier accepts, and for
/// TLS 1.2 also RSA PKCS#1 v1.5.
pub(super) fn offered_schemes(config: &ClientConfig) -> Vec<u16> {
    if config.tls12 {
        with_pkcs1(config.verifier.schemes())
    } else {
        config.verifier.schemes()
    }
}

fn put_u16_list_u8(out: &mut Vec<u8>, list: &[u16]) {
    put_u16_list(out, 1, list);
}

/// Computes the PSK binder over the ClientHello up to the binders and
/// writes it in (RFC 8446 4.2.11.2). The pre_shared_key extension is the
/// last one, so the binders are the last bytes of the message.
fn fill_binder(hello: &mut ClientHello, t: &StoredTicket, transcript: &Transcript) {
    let raw = hello.encode().encode();
    let psks = read_offered_psks(hello.ext(ext::PRE_SHARED_KEY).unwrap()).unwrap();
    let cut = raw.len() - binders_len(&psks.binders);
    let hash = t.suite.hash;
    let th = transcript.buffered_hash_with(hash, &raw[..cut]);
    let ks = KeySchedule::new(hash, Some(t.psk.expose()));
    let binder = finished_verify_data(hash, ks.resumption_binder_key().expose(), &th);
    let psks = OfferedPsks {
        identities: psks.identities,
        binders: vec![binder],
    };
    hello.extensions.last_mut().unwrap().data = write_offered_psks(&psks);
}

struct ExpectServerHello {
    offer: Offer,
    hello: ClientHello,
    transcript: Transcript,
    retried: bool,
}

impl State for ExpectServerHello {
    fn handle(
        self: Box<Self>,
        core: &mut Core,
        msg: Handshake,
        raw: Vec<u8>,
    ) -> Result<Box<dyn State>, Error> {
        let mut s = *self;
        if msg.typ != hs::SERVER_HELLO {
            return Err(Error::unexpected("expected ServerHello"));
        }
        let sh = ServerHello::parse(&msg.body)?;
        let Some(v) = sh.ext(ext::SUPPORTED_VERSIONS) else {
            // A server that ignores supported_versions speaks TLS 1.2 or
            // older.
            if s.offer.config.tls12 && !s.retried && sh.legacy_version == version::TLS12 {
                let ch = s
                    .transcript
                    .into_buffer()
                    .ok_or(Error::internal("transcript"))?;
                return client12::server_hello(core, s.offer, s.hello.random, ch, sh, raw);
            }
            return Err(Error::new(
                alert::PROTOCOL_VERSION,
                "server does not speak TLS 1.3",
            ));
        };
        if v != version::TLS13.to_be_bytes() {
            return Err(Error::illegal(
                "server chose a version that was not offered",
            ));
        }
        if sh.legacy_version != version::TLS12 || sh.compression != 0 {
            return Err(Error::illegal("ServerHello legacy fields"));
        }
        if sh.session_id != s.offer.session_id {
            return Err(Error::illegal("session id not echoed"));
        }
        if !s.offer.suites.contains(&sh.cipher_suite) {
            return Err(Error::illegal("cipher suite not offered"));
        }
        let suite = tls13_suite(sh.cipher_suite).ok_or(Error::illegal("cipher suite"))?;
        for e in &sh.extensions {
            if !s.offer.extensions.contains(&e.typ) {
                return Err(Error::new(
                    alert::UNSUPPORTED_EXTENSION,
                    "extension not offered",
                ));
            }
        }
        if sh.is_retry_request() {
            return s.retry(core, sh, raw, suite);
        }
        if s.retried && core.suite.is_some_and(|c| c != suite) {
            return Err(Error::illegal(
                "cipher suite changed after HelloRetryRequest",
            ));
        }
        for e in &sh.extensions {
            if !matches!(
                e.typ,
                ext::KEY_SHARE | ext::SUPPORTED_VERSIONS | ext::PRE_SHARED_KEY
            ) {
                return Err(Error::illegal("extension not allowed in ServerHello"));
            }
        }

        let share = read_server_key_share(
            sh.ext(ext::KEY_SHARE)
                .ok_or(Error::new(alert::MISSING_EXTENSION, "no key_share"))?,
        )?;
        let kx = s
            .offer
            .kx
            .iter()
            .find(|k| k.group() == share.group)
            .ok_or(Error::illegal("key share for a group not offered"))?;
        let shared = kx.agree(&share.key)?;
        core.group = Some(share.group);

        let psk = match sh.ext(ext::PRE_SHARED_KEY) {
            None => None,
            Some(sel) => {
                let t = s
                    .offer
                    .ticket
                    .take()
                    .ok_or(Error::illegal("pre_shared_key not offered"))?;
                if sel != [0, 0] {
                    return Err(Error::illegal("selected PSK out of range"));
                }
                if t.suite.hash != suite.hash {
                    return Err(Error::illegal("PSK used with a different hash"));
                }
                Some(t)
            }
        };

        core.suite = Some(suite);
        s.transcript.start_hash(suite.hash);
        s.transcript.add(&raw);
        let mut ks = KeySchedule::new(suite.hash, psk.as_ref().map(|t| t.psk.expose()));
        ks.into_handshake(shared.expose());
        let th = s.transcript.current();
        let c_hs = ks.derive(b"c hs traffic", &th);
        let s_hs = ks.derive(b"s hs traffic", &th);
        core.set_read_handshake(suite, s_hs.expose())?;
        core.resumed = psk.is_some();
        Ok(Box::new(ExpectEncryptedExtensions {
            hs: Hs {
                offer: s.offer,
                transcript: s.transcript,
                ks,
                suite,
                c_hs,
                s_hs,
                alpn_from_ticket: psk.and_then(|t| t.alpn),
            },
        }))
    }
}

impl ExpectServerHello {
    fn retry(
        mut self,
        core: &mut Core,
        hrr: ServerHello,
        raw: Vec<u8>,
        suite: Suite,
    ) -> Result<Box<dyn State>, Error> {
        if self.retried {
            return Err(Error::unexpected("second HelloRetryRequest"));
        }
        for e in &hrr.extensions {
            if !matches!(
                e.typ,
                ext::KEY_SHARE | ext::SUPPORTED_VERSIONS | ext::COOKIE
            ) {
                return Err(Error::illegal("extension not allowed in HelloRetryRequest"));
            }
        }
        let cookie = hrr.ext(ext::COOKIE).map(|c| c.to_vec());
        let group = match hrr.ext(ext::KEY_SHARE) {
            Some(&[a, b]) => Some(u16::from_be_bytes([a, b])),
            Some(_) => return Err(Error::decode("HelloRetryRequest key_share")),
            None => None,
        };
        if let Some(g) = group {
            if !self.offer.config.groups.contains(&g)
                || self.offer.kx.iter().any(|k| k.group() == g)
            {
                return Err(Error::illegal(
                    "HelloRetryRequest asks for an unusable group",
                ));
            }
        }
        // A retry that would change nothing is refused (4.1.4).
        if group.is_none() && cookie.is_none() {
            return Err(Error::illegal("HelloRetryRequest changes nothing"));
        }
        core.suite = Some(suite);
        self.transcript.replace_with_message_hash(suite.hash);
        self.transcript.add(&raw);
        if let Some(g) = group {
            self.offer.kx = vec![KxSecret::generate(g)?];
        }
        let mut hello = self.hello.clone();
        hello.extensions.retain(|e| e.typ != ext::EARLY_DATA);
        for e in hello.extensions.iter_mut() {
            if e.typ == ext::KEY_SHARE {
                e.data = write_client_key_shares(
                    &self
                        .offer
                        .kx
                        .iter()
                        .map(|k| KeyShareEntry {
                            group: k.group(),
                            key: k.public(),
                        })
                        .collect::<Vec<_>>(),
                );
            }
        }
        if let Some(c) = cookie {
            let mut data = Vec::new();
            super::codec::put_bytes(&mut data, 2, &c);
            let at = hello
                .extensions
                .iter()
                .position(|e| e.typ == ext::PRE_SHARED_KEY)
                .unwrap_or(hello.extensions.len());
            hello.extensions.insert(
                at,
                Extension {
                    typ: ext::COOKIE,
                    data,
                },
            );
        }
        // A ticket for a different hash cannot be used with this suite
        // and is dropped from the second hello (4.1.4).
        if self
            .offer
            .ticket
            .as_ref()
            .is_some_and(|t| t.suite.hash != suite.hash)
        {
            self.offer.ticket = None;
            hello.extensions.retain(|e| e.typ != ext::PRE_SHARED_KEY);
        }
        if let Some(t) = &self.offer.ticket {
            fill_binder_after_retry(&mut hello, t, &self.transcript);
        }
        if !self.offer.session_id.is_empty() {
            core.send_ccs()?;
        }
        let raw2 = core.send_hs(&hello.encode());
        self.transcript.add(&raw2);
        core.flush_hs()?;
        self.offer.extensions = hello.extensions.iter().map(|e| e.typ).collect();
        Ok(Box::new(ExpectServerHello {
            offer: self.offer,
            hello,
            transcript: self.transcript,
            retried: true,
        }))
    }
}

fn fill_binder_after_retry(hello: &mut ClientHello, t: &StoredTicket, transcript: &Transcript) {
    let raw = hello.encode().encode();
    let psks = read_offered_psks(hello.ext(ext::PRE_SHARED_KEY).unwrap()).unwrap();
    let cut = raw.len() - binders_len(&psks.binders);
    let mut tr = transcript.current_with(&raw[..cut]);
    let hash = t.suite.hash;
    let ks = KeySchedule::new(hash, Some(t.psk.expose()));
    let binder = finished_verify_data(hash, ks.resumption_binder_key().expose(), &tr);
    tr.clear();
    let psks = OfferedPsks {
        identities: psks.identities,
        binders: vec![binder],
    };
    hello.extensions.last_mut().unwrap().data = write_offered_psks(&psks);
}

/// The handshake after ServerHello.
struct Hs {
    offer: Offer,
    transcript: Transcript,
    ks: KeySchedule,
    suite: Suite,
    c_hs: Secret,
    s_hs: Secret,
    alpn_from_ticket: Option<Vec<u8>>,
}

struct ExpectEncryptedExtensions {
    hs: Hs,
}

impl State for ExpectEncryptedExtensions {
    fn handle(
        self: Box<Self>,
        core: &mut Core,
        msg: Handshake,
        raw: Vec<u8>,
    ) -> Result<Box<dyn State>, Error> {
        let mut hs = self.hs;
        if msg.typ != hs::ENCRYPTED_EXTENSIONS {
            return Err(Error::unexpected("expected EncryptedExtensions"));
        }
        let exts = parse_extensions_only(&msg.body)?;
        for e in &exts {
            match e.typ {
                ext::KEY_SHARE
                | ext::SUPPORTED_VERSIONS
                | ext::PRE_SHARED_KEY
                | ext::SIGNATURE_ALGORITHMS
                | ext::PSK_KEY_EXCHANGE_MODES
                | ext::COOKIE => {
                    return Err(Error::illegal(
                        "extension not allowed in EncryptedExtensions",
                    ))
                }
                t if !hs.offer.extensions.contains(&t) => {
                    return Err(Error::new(
                        alert::UNSUPPORTED_EXTENSION,
                        "extension not offered",
                    ))
                }
                _ => {}
            }
        }
        if let Some(sn) = find(&exts, ext::SERVER_NAME) {
            if !sn.is_empty() {
                return Err(Error::decode("server_name in EncryptedExtensions"));
            }
        }
        if find(&exts, ext::EARLY_DATA).is_some() {
            return Err(Error::illegal("early data was not offered"));
        }
        if let Some(a) = find(&exts, ext::ALPN) {
            let list = read_alpn(a)?;
            if list.len() != 1 || !hs.offer.config.alpn.contains(&list[0]) {
                return Err(Error::illegal("ALPN protocol not offered"));
            }
            if hs.alpn_from_ticket.as_ref().is_some_and(|t| t != &list[0]) {
                return Err(Error::illegal("ALPN differs from the resumed session"));
            }
            core.alpn = Some(list[0].clone());
        }
        hs.transcript.add(&raw);
        if core.resumed {
            Ok(Box::new(ExpectFinished {
                hs,
                cert_request: None,
            }))
        } else {
            Ok(Box::new(ExpectCertificate {
                hs,
                cert_request: None,
            }))
        }
    }
}

/// A server's request for a client certificate: its context and the
/// schemes it accepts.
struct CertRequest {
    context: Vec<u8>,
    schemes: Vec<u16>,
}

struct ExpectCertificate {
    hs: Hs,
    cert_request: Option<CertRequest>,
}

impl State for ExpectCertificate {
    fn handle(
        self: Box<Self>,
        _core: &mut Core,
        msg: Handshake,
        raw: Vec<u8>,
    ) -> Result<Box<dyn State>, Error> {
        let mut hs = self.hs;
        if msg.typ == hs::CERTIFICATE_REQUEST && self.cert_request.is_none() {
            let cr = CertificateRequest::parse(&msg.body)?;
            if !cr.context.is_empty() {
                return Err(Error::illegal(
                    "CertificateRequest context in the handshake",
                ));
            }
            let schemes = read_u16_list(
                find(&cr.extensions, ext::SIGNATURE_ALGORITHMS).ok_or(Error::new(
                    alert::MISSING_EXTENSION,
                    "no signature_algorithms",
                ))?,
                2,
            )?;
            hs.transcript.add(&raw);
            return Ok(Box::new(ExpectCertificate {
                hs,
                cert_request: Some(CertRequest {
                    context: cr.context,
                    schemes,
                }),
            }));
        }
        if msg.typ != hs::CERTIFICATE {
            return Err(Error::unexpected("expected Certificate"));
        }
        let cert = Certificate::parse(&msg.body)?;
        if !cert.context.is_empty() {
            return Err(Error::illegal("Certificate context"));
        }
        if cert.entries.is_empty() {
            return Err(Error::decode("server sent no certificate"));
        }
        let chain: Vec<Vec<u8>> = cert.entries.into_iter().map(|e| e.der).collect();
        let key = hs
            .offer
            .config
            .verifier
            .verify(&chain, hs.offer.name.as_deref())?;
        hs.transcript.add(&raw);
        Ok(Box::new(ExpectCertificateVerify {
            hs,
            cert_request: self.cert_request,
            key,
            chain,
        }))
    }
}

struct ExpectCertificateVerify {
    hs: Hs,
    cert_request: Option<CertRequest>,
    key: PublicKey,
    chain: Vec<Vec<u8>>,
}

impl State for ExpectCertificateVerify {
    fn handle(
        self: Box<Self>,
        core: &mut Core,
        msg: Handshake,
        raw: Vec<u8>,
    ) -> Result<Box<dyn State>, Error> {
        let mut hs = self.hs;
        if msg.typ != hs::CERTIFICATE_VERIFY {
            return Err(Error::unexpected("expected CertificateVerify"));
        }
        let cv = CertificateVerify::parse(&msg.body)?;
        if !hs.offer.config.verifier.schemes().contains(&cv.scheme) {
            return Err(Error::illegal("signature scheme not offered"));
        }
        let content = signed_content(true, &hs.transcript.current());
        self.key.verify(cv.scheme, &content, &cv.signature)?;
        hs.transcript.add(&raw);
        core.peer_chain = Some(self.chain);
        Ok(Box::new(ExpectFinished {
            hs,
            cert_request: self.cert_request,
        }))
    }
}

struct ExpectFinished {
    hs: Hs,
    cert_request: Option<CertRequest>,
}

impl State for ExpectFinished {
    fn handle(
        self: Box<Self>,
        core: &mut Core,
        msg: Handshake,
        raw: Vec<u8>,
    ) -> Result<Box<dyn State>, Error> {
        let mut hs = self.hs;
        if msg.typ != hs::FINISHED {
            return Err(Error::unexpected("expected Finished"));
        }
        let expected =
            finished_verify_data(hs.suite.hash, hs.s_hs.expose(), &hs.transcript.current());
        if !verify_finished(&expected, &msg.body) {
            return Err(Error::new(
                alert::DECRYPT_ERROR,
                "server Finished does not verify",
            ));
        }
        hs.transcript.add(&raw);
        core.no_buffered_handshake()?;

        hs.ks.into_master();
        let th = hs.transcript.current();
        let c_ap = hs.ks.derive(b"c ap traffic", &th);
        let s_ap = hs.ks.derive(b"s ap traffic", &th);
        core.exporter = Some(hs.ks.derive(b"exp master", &th));

        if !hs.offer.session_id.is_empty() {
            core.send_ccs()?;
        }
        core.set_write_handshake(hs.suite, hs.c_hs.expose())?;
        if let Some(cr) = &self.cert_request {
            send_client_certificate(core, &mut hs, cr)?;
        }
        let fin = finished_verify_data(hs.suite.hash, hs.c_hs.expose(), &hs.transcript.current());
        let raw_fin = core.send_hs(&Handshake::new(hs::FINISHED, fin));
        hs.transcript.add(&raw_fin);
        let res_master = hs.ks.derive(b"res master", &hs.transcript.current());

        core.set_read_app(hs.suite, s_ap)?;
        core.set_write_app(hs.suite, c_ap)?;

        let suite = hs.suite;
        let cache: Option<Arc<TicketCache>> = hs.offer.config.tickets.clone();
        let name = hs.offer.name.clone();
        let alpn = core.alpn.clone();
        Ok(Box::new(Connected {
            on_ticket: move |_core: &mut Core, m: &Handshake| {
                let t = NewSessionTicket::parse(&m.body)?;
                if t.lifetime > MAX_TICKET_LIFETIME {
                    return Err(Error::illegal("ticket lifetime above seven days"));
                }
                if let (Some(cache), Some(name)) = (&cache, &name) {
                    if t.lifetime > 0 {
                        cache.put(
                            name,
                            StoredTicket {
                                suite,
                                psk: resumption_psk(suite.hash, res_master.expose(), &t.nonce),
                                ticket: t.ticket,
                                age_add: t.age_add,
                                received: SystemTime::now(),
                                lifetime: Duration::from_secs(t.lifetime as u64),
                                alpn: alpn.clone(),
                            },
                        );
                    }
                }
                Ok(())
            },
        }))
    }
}

fn send_client_certificate(core: &mut Core, hs: &mut Hs, cr: &CertRequest) -> Result<(), Error> {
    let chosen = hs
        .offer
        .config
        .client_cert
        .as_ref()
        .and_then(|(chain, key)| key.choose_scheme(&cr.schemes).map(|s| (chain, key, s)));
    let entries = match &chosen {
        Some((chain, _, _)) => chain
            .iter()
            .map(|der| CertificateEntry {
                der: der.clone(),
                extensions: Vec::new(),
            })
            .collect(),
        // No usable certificate: an empty one, and the server decides.
        None => Vec::new(),
    };
    let raw = core.send_hs(
        &Certificate {
            context: cr.context.clone(),
            entries,
        }
        .encode(),
    );
    hs.transcript.add(&raw);
    if let Some((_, key, scheme)) = chosen {
        let content = signed_content(false, &hs.transcript.current());
        let signature = key.sign(scheme, &content)?;
        let raw = core.send_hs(&CertificateVerify { scheme, signature }.encode());
        hs.transcript.add(&raw);
    }
    Ok(())
}
