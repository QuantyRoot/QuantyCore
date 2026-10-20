//! The TLS 1.3 server handshake (RFC 8446 section 4 and appendix A.2).

use super::auth::{signed_content, PublicKey};
use super::codec::{put_bytes, put_u16, Reader};
use super::config::{ClientAuth, ServerConfig};
use super::conn::{Connected, Connection, Core, State, Transcript};
use super::crypto::aead::{Aead, NONCE_LEN};
use super::crypto::ct::Secret;
use super::crypto::rand;
use super::error::{alert, Error};
use super::key_schedule::{finished_verify_data, resumption_psk, verify_finished, KeySchedule};
use super::kx::{self, KxSecret};
use super::msgs::*;
use super::server12;
use super::suites::{tls13_suite, Suite};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct ServerConnection(Connection);

impl std::ops::Deref for ServerConnection {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        &self.0
    }
}

impl std::ops::DerefMut for ServerConnection {
    fn deref_mut(&mut self) -> &mut Connection {
        &mut self.0
    }
}

impl ServerConnection {
    pub fn new(config: Arc<ServerConfig>) -> ServerConnection {
        let state = ExpectClientHello {
            config,
            retry: None,
            fixed: None,
        };
        ServerConnection(Connection::new(Core::new(), Box::new(state)))
    }

    /// The host name the client asked for with SNI, if any.
    pub fn server_name(&self) -> Option<&str> {
        self.0.core.server_name.as_deref()
    }

    /// A server whose random value and key share are given instead of
    /// drawn, for the RFC 8448 test.
    #[cfg(test)]
    pub(crate) fn with_fixed(
        config: Arc<ServerConfig>,
        random: [u8; 32],
        kx: KxSecret,
    ) -> ServerConnection {
        let state = ExpectClientHello {
            config,
            retry: None,
            fixed: Some((random, kx)),
        };
        ServerConnection(Connection::new(Core::new(), Box::new(state)))
    }
}

/// What the server decided when it sent a HelloRetryRequest, and must
/// hold the second ClientHello to.
struct Retry {
    transcript: Transcript,
    suite: Suite,
    group: u16,
    session_id: Vec<u8>,
}

struct ExpectClientHello {
    config: Arc<ServerConfig>,
    retry: Option<Retry>,
    fixed: Option<([u8; 32], KxSecret)>,
}

/// A session restored from a ticket the client presented.
pub(super) struct Resumed {
    psk: Secret,
    alpn: Option<Vec<u8>>,
}

impl State for ExpectClientHello {
    fn handle(
        self: Box<Self>,
        core: &mut Core,
        msg: Handshake,
        raw: Vec<u8>,
    ) -> Result<Box<dyn State>, Error> {
        let mut s = *self;
        if msg.typ != hs::CLIENT_HELLO {
            return Err(Error::unexpected("expected ClientHello"));
        }
        let after_retry = s.retry.is_some();
        let ch = ClientHello::parse(&msg.body)?;
        if s.config.tls12 && !after_retry && server12::wants_tls12(&s.config, &ch)? {
            return server12::client_hello(core, s.config, ch, raw);
        }
        if s.config.max_tls12 {
            return Err(Error::new(
                alert::PROTOCOL_VERSION,
                "client does not offer TLS 1.2",
            ));
        }
        let versions = read_u16_list(
            ch.ext(ext::SUPPORTED_VERSIONS).ok_or(Error::new(
                alert::PROTOCOL_VERSION,
                "client does not offer TLS 1.3",
            ))?,
            1,
        )?;
        if !versions.contains(&version::TLS13) {
            return Err(Error::new(
                alert::PROTOCOL_VERSION,
                "client does not offer TLS 1.3",
            ));
        }
        if ch.compression != [0] {
            return Err(Error::illegal("compression offered with TLS 1.3"));
        }
        if let Some(i) = ch
            .extensions
            .iter()
            .position(|e| e.typ == ext::PRE_SHARED_KEY)
        {
            if i != ch.extensions.len() - 1 {
                return Err(Error::illegal("pre_shared_key is not the last extension"));
            }
        }
        if ch.ext(ext::EARLY_DATA).is_some() && s.retry.is_some() {
            return Err(Error::illegal("early_data after HelloRetryRequest"));
        }

        let suite = match &s.retry {
            Some(r) => {
                if !ch.cipher_suites.contains(&r.suite.id) || ch.session_id != r.session_id {
                    return Err(Error::illegal("second ClientHello differs"));
                }
                r.suite
            }
            None => s
                .config
                .suites
                .iter()
                .copied()
                .find(|x| ch.cipher_suites.contains(&x.id))
                .ok_or(Error::handshake_failure("no common cipher suite"))?,
        };

        let groups = read_u16_list(
            ch.ext(ext::SUPPORTED_GROUPS)
                .ok_or(Error::new(alert::MISSING_EXTENSION, "no supported_groups"))?,
            2,
        )?;
        let shares = read_client_key_shares(
            ch.ext(ext::KEY_SHARE)
                .ok_or(Error::new(alert::MISSING_EXTENSION, "no key_share"))?,
        )?;
        if shares.iter().any(|k| !groups.contains(&k.group)) {
            return Err(Error::illegal(
                "key share for a group not in supported_groups",
            ));
        }
        let share = match &s.retry {
            Some(r) => {
                if shares.len() != 1 || shares[0].group != r.group {
                    return Err(Error::illegal(
                        "second ClientHello without the requested share",
                    ));
                }
                shares[0].clone()
            }
            None => {
                let usable = s
                    .config
                    .groups
                    .iter()
                    .find_map(|g| shares.iter().find(|k| k.group == *g));
                match usable {
                    Some(k) => k.clone(),
                    None => {
                        let g = s
                            .config
                            .groups
                            .iter()
                            .copied()
                            .find(|g| groups.contains(g))
                            .ok_or(Error::handshake_failure("no common group"))?;
                        return s.retry(core, &ch, raw, suite, g);
                    }
                }
            }
        };

        let mut transcript = match s.retry.take() {
            Some(r) => r.transcript,
            None => {
                let mut t = Transcript::new();
                t.start_hash(suite.hash);
                t
            }
        };

        if let Some(sn) = ch.ext(ext::SERVER_NAME) {
            core.server_name = read_server_name(sn)?;
        }
        let resumed = resume(&s.config, &ch, suite, &transcript, &raw)?;
        let alpn = choose_alpn(&s.config, &ch, resumed.as_ref())?;
        let schemes = match ch.ext(ext::SIGNATURE_ALGORITHMS) {
            Some(d) => read_u16_list(d, 2)?,
            None if resumed.is_some() => Vec::new(),
            None => {
                return Err(Error::new(
                    alert::MISSING_EXTENSION,
                    "no signature_algorithms",
                ))
            }
        };
        transcript.add(&raw);

        let (random, server_share, shared) = match s.fixed.take() {
            Some((r, kx)) => {
                if kx.group() != share.group {
                    return Err(Error::internal("key share group"));
                }
                let shared = kx.agree(&share.key)?;
                (r, kx.public(), shared)
            }
            None => {
                let mut r = [0u8; 32];
                rand::fill(&mut r).map_err(|_| Error::internal("no randomness"))?;
                let (public, shared) = kx::respond(share.group, &share.key)?;
                (r, public, shared)
            }
        };
        core.group = Some(share.group);

        let mut exts = vec![
            Extension {
                typ: ext::KEY_SHARE,
                data: write_server_key_share(&KeyShareEntry {
                    group: share.group,
                    key: server_share,
                }),
            },
            Extension {
                typ: ext::SUPPORTED_VERSIONS,
                data: version::TLS13.to_be_bytes().to_vec(),
            },
        ];
        if resumed.is_some() {
            exts.push(Extension {
                typ: ext::PRE_SHARED_KEY,
                data: vec![0, 0],
            });
        }
        let sh = ServerHello {
            legacy_version: version::TLS12,
            random,
            session_id: ch.session_id.clone(),
            cipher_suite: suite.id,
            compression: 0,
            extensions: exts,
        };
        let raw_sh = core.send_hs(&sh.encode());
        transcript.add(&raw_sh);
        core.suite = Some(suite);
        // In compatibility mode the one dummy change_cipher_spec follows
        // the server's first handshake message, which was the
        // HelloRetryRequest if there was one.
        if !ch.session_id.is_empty() && !after_retry {
            core.send_ccs()?;
        }

        let mut ks = KeySchedule::new(suite.hash, resumed.as_ref().map(|r| r.psk.expose()));
        ks.into_handshake(shared.expose());
        let th = transcript.current();
        let c_hs = ks.derive(b"c hs traffic", &th);
        let s_hs = ks.derive(b"s hs traffic", &th);
        core.set_write_handshake(suite, s_hs.expose())?;

        let mut ee = Vec::new();
        if core.server_name.is_some() {
            ee.push(Extension {
                typ: ext::SERVER_NAME,
                data: Vec::new(),
            });
        }
        if let Some(p) = &alpn {
            ee.push(Extension {
                typ: ext::ALPN,
                data: write_alpn(std::slice::from_ref(p)),
            });
        }
        core.alpn = alpn;
        transcript.add(&core.send_hs(&encode_extensions_only(hs::ENCRYPTED_EXTENSIONS, &ee)));

        let mut client_verifier = None;
        if resumed.is_none() {
            if let ClientAuth::Required(v) = &s.config.client_auth {
                let mut sig = Vec::new();
                put_u16_list(&mut sig, 2, &v.schemes());
                let cr = CertificateRequest {
                    context: Vec::new(),
                    extensions: vec![Extension {
                        typ: ext::SIGNATURE_ALGORITHMS,
                        data: sig,
                    }],
                };
                transcript.add(&core.send_hs(&cr.encode()));
                client_verifier = Some(v.clone());
            }
            let cert = Certificate {
                context: Vec::new(),
                entries: s
                    .config
                    .chain
                    .iter()
                    .map(|der| CertificateEntry {
                        der: der.clone(),
                        extensions: Vec::new(),
                    })
                    .collect(),
            };
            transcript.add(&core.send_hs(&cert.encode()));
            let scheme = s
                .config
                .signer
                .choose_scheme(&schemes)
                .ok_or(Error::handshake_failure("no signature scheme in common"))?;
            let content = signed_content(true, &transcript.current());
            let signature = s.config.signer.sign(scheme, &content)?;
            transcript.add(&core.send_hs(&CertificateVerify { scheme, signature }.encode()));
        }
        core.resumed = resumed.is_some();

        let fin = finished_verify_data(suite.hash, s_hs.expose(), &transcript.current());
        transcript.add(&core.send_hs(&Handshake::new(hs::FINISHED, fin)));

        ks.into_master();
        let th = transcript.current();
        let c_ap = ks.derive(b"c ap traffic", &th);
        let s_ap = ks.derive(b"s ap traffic", &th);
        core.exporter = Some(ks.derive(b"exp master", &th));
        core.set_read_handshake(suite, c_hs.expose())?;
        core.set_write_app(suite, s_ap)?;

        let hs = Hs {
            config: s.config,
            transcript,
            ks,
            suite,
            c_hs,
            c_ap,
        };
        Ok(match client_verifier {
            Some(_) => Box::new(ExpectCertificate { hs }),
            None => Box::new(ExpectFinished { hs, peer: None }),
        })
    }
}

impl ExpectClientHello {
    fn retry(
        self,
        core: &mut Core,
        ch: &ClientHello,
        raw: Vec<u8>,
        suite: Suite,
        group: u16,
    ) -> Result<Box<dyn State>, Error> {
        let mut transcript = Transcript::new();
        transcript.add(&raw);
        transcript.replace_with_message_hash(suite.hash);
        let hrr = ServerHello {
            legacy_version: version::TLS12,
            random: HRR_RANDOM,
            session_id: ch.session_id.clone(),
            cipher_suite: suite.id,
            compression: 0,
            extensions: vec![
                Extension {
                    typ: ext::SUPPORTED_VERSIONS,
                    data: version::TLS13.to_be_bytes().to_vec(),
                },
                Extension {
                    typ: ext::KEY_SHARE,
                    data: group.to_be_bytes().to_vec(),
                },
            ],
        };
        transcript.add(&core.send_hs(&hrr.encode()));
        if !ch.session_id.is_empty() {
            core.send_ccs()?;
        }
        core.flush_hs()?;
        Ok(Box::new(ExpectClientHello {
            config: self.config,
            retry: Some(Retry {
                transcript,
                suite,
                group,
                session_id: ch.session_id.clone(),
            }),
            fixed: self.fixed,
        }))
    }
}

/// The application protocol: the server's first preference that the
/// client offered. A client offering only protocols the server does not
/// speak is refused (RFC 7301 3.2). A resumed session must keep its
/// protocol.
pub(super) fn choose_alpn(
    config: &ServerConfig,
    ch: &ClientHello,
    resumed: Option<&Resumed>,
) -> Result<Option<Vec<u8>>, Error> {
    let Some(data) = ch.ext(ext::ALPN) else {
        return Ok(None);
    };
    let offered = read_alpn(data)?;
    if config.alpn.is_empty() {
        return Ok(None);
    }
    let chosen = config
        .alpn
        .iter()
        .find(|p| offered.contains(p))
        .cloned()
        .ok_or(Error::new(
            alert::NO_APPLICATION_PROTOCOL,
            "no common application protocol",
        ))?;
    if let Some(r) = resumed {
        if r.alpn.as_ref().is_some_and(|a| a != &chosen) {
            return Err(Error::illegal("ALPN differs from the resumed session"));
        }
    }
    Ok(Some(chosen))
}

const TICKET_AAD: &[u8] = b"quantycore tls13 ticket v1";

/// A ticket is the session sealed under the server's ticket key: the
/// suite, creation time, age_add, lifetime, ALPN and the PSK. The server
/// keeps nothing itself.
fn seal_ticket(
    config: &ServerConfig,
    suite: Suite,
    age_add: u32,
    alpn: Option<&[u8]>,
    psk: &[u8],
) -> Result<Option<Vec<u8>>, Error> {
    let Some(key) = &config.tickets else {
        return Ok(None);
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut plain = Vec::new();
    put_u16(&mut plain, suite.id);
    plain.extend_from_slice(&now.to_be_bytes());
    plain.extend_from_slice(&age_add.to_be_bytes());
    plain.extend_from_slice(&(config.ticket_lifetime.as_secs() as u32).to_be_bytes());
    put_bytes(&mut plain, 1, alpn.unwrap_or(&[]));
    put_bytes(&mut plain, 1, psk);
    let mut nonce = [0u8; NONCE_LEN];
    rand::fill(&mut nonce).map_err(|_| Error::internal("no randomness"))?;
    key.cipher.seal(&nonce, TICKET_AAD, &mut plain);
    let mut out = nonce.to_vec();
    out.extend_from_slice(&plain);
    Ok(Some(out))
}

struct OpenedTicket {
    suite: u16,
    created: u64,
    lifetime: u32,
    alpn: Option<Vec<u8>>,
    psk: Secret,
}

fn open_ticket(config: &ServerConfig, ticket: &[u8]) -> Option<OpenedTicket> {
    let key = config.tickets.as_ref()?;
    if ticket.len() < NONCE_LEN + 16 {
        return None;
    }
    let nonce: [u8; NONCE_LEN] = ticket[..NONCE_LEN].try_into().unwrap();
    let mut buf = ticket[NONCE_LEN..].to_vec();
    key.cipher.open(&nonce, TICKET_AAD, &mut buf).ok()?;
    let buf = Secret::new(buf);
    let mut r = Reader::new(buf.expose());
    let suite = r.u16()?;
    let created = u64::from_be_bytes(r.take(8)?.try_into().unwrap());
    // age_add only matters for 0-RTT replay checks, which are not built.
    r.u32()?;
    let lifetime = r.u32()?;
    let alpn = r.vec8()?;
    let psk = r.vec8()?;
    r.end()?;
    Some(OpenedTicket {
        suite,
        created,
        lifetime,
        alpn: (!alpn.is_empty()).then(|| alpn.to_vec()),
        psk: Secret::from(psk),
    })
}

/// Accepts the client's first offered ticket if it is ours, unexpired,
/// for a suite with the same hash, and its binder verifies. Anything
/// else about the ticket only means a full handshake; a binder that does
/// not verify is an attack and fails the handshake (RFC 8446 4.2.11).
fn resume(
    config: &ServerConfig,
    ch: &ClientHello,
    suite: Suite,
    transcript: &Transcript,
    raw: &[u8],
) -> Result<Option<Resumed>, Error> {
    let Some(data) = ch.ext(ext::PRE_SHARED_KEY) else {
        return Ok(None);
    };
    let modes = ch.ext(ext::PSK_KEY_EXCHANGE_MODES).ok_or(Error::new(
        alert::MISSING_EXTENSION,
        "pre_shared_key without psk_key_exchange_modes",
    ))?;
    let modes = Reader::new(modes)
        .vec8()
        .ok_or(Error::decode("psk_key_exchange_modes"))?;
    let psks = read_offered_psks(data)?;
    if !modes.contains(&1) {
        return Ok(None);
    }
    let first = &psks.identities[0];
    let Some(t) = open_ticket(config, &first.identity) else {
        return Ok(None);
    };
    let Some(ticket_suite) = tls13_suite(t.suite) else {
        return Ok(None);
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if ticket_suite.hash != suite.hash || now.saturating_sub(t.created) > t.lifetime as u64 {
        return Ok(None);
    }
    let cut = raw.len() - binders_len(&psks.binders);
    let th = transcript.current_with(&raw[..cut]);
    let ks = KeySchedule::new(suite.hash, Some(t.psk.expose()));
    let expected = finished_verify_data(suite.hash, ks.resumption_binder_key().expose(), &th);
    if !verify_finished(&expected, &psks.binders[0]) {
        return Err(Error::new(
            alert::DECRYPT_ERROR,
            "PSK binder does not verify",
        ));
    }
    Ok(Some(Resumed {
        psk: t.psk,
        alpn: t.alpn,
    }))
}

struct Hs {
    config: Arc<ServerConfig>,
    transcript: Transcript,
    ks: KeySchedule,
    suite: Suite,
    c_hs: Secret,
    c_ap: Secret,
}

struct ExpectCertificate {
    hs: Hs,
}

impl State for ExpectCertificate {
    fn handle(
        self: Box<Self>,
        _core: &mut Core,
        msg: Handshake,
        raw: Vec<u8>,
    ) -> Result<Box<dyn State>, Error> {
        let mut hs = self.hs;
        if msg.typ != hs::CERTIFICATE {
            return Err(Error::unexpected("expected Certificate"));
        }
        let cert = Certificate::parse(&msg.body)?;
        if !cert.context.is_empty() {
            return Err(Error::illegal("Certificate context"));
        }
        if cert.entries.is_empty() {
            return Err(Error::new(
                alert::CERTIFICATE_REQUIRED,
                "client sent no certificate",
            ));
        }
        let chain: Vec<Vec<u8>> = cert.entries.into_iter().map(|e| e.der).collect();
        let ClientAuth::Required(v) = &hs.config.client_auth else {
            return Err(Error::internal("client certificate not requested"));
        };
        let key = v.verify(&chain, None)?;
        hs.transcript.add(&raw);
        Ok(Box::new(ExpectCertificateVerify { hs, key, chain }))
    }
}

struct ExpectCertificateVerify {
    hs: Hs,
    key: PublicKey,
    chain: Vec<Vec<u8>>,
}

impl State for ExpectCertificateVerify {
    fn handle(
        self: Box<Self>,
        _core: &mut Core,
        msg: Handshake,
        raw: Vec<u8>,
    ) -> Result<Box<dyn State>, Error> {
        let mut hs = self.hs;
        if msg.typ != hs::CERTIFICATE_VERIFY {
            return Err(Error::unexpected("expected CertificateVerify"));
        }
        let cv = CertificateVerify::parse(&msg.body)?;
        let ClientAuth::Required(v) = &hs.config.client_auth else {
            return Err(Error::internal("client certificate not requested"));
        };
        if !v.schemes().contains(&cv.scheme) {
            return Err(Error::illegal("signature scheme not offered"));
        }
        let content = signed_content(false, &hs.transcript.current());
        self.key.verify(cv.scheme, &content, &cv.signature)?;
        hs.transcript.add(&raw);
        Ok(Box::new(ExpectFinished {
            hs,
            peer: Some(self.chain),
        }))
    }
}

struct ExpectFinished {
    hs: Hs,
    peer: Option<Vec<Vec<u8>>>,
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
            finished_verify_data(hs.suite.hash, hs.c_hs.expose(), &hs.transcript.current());
        if !verify_finished(&expected, &msg.body) {
            return Err(Error::new(
                alert::DECRYPT_ERROR,
                "client Finished does not verify",
            ));
        }
        hs.transcript.add(&raw);
        core.no_buffered_handshake()?;
        core.set_read_app(hs.suite, hs.c_ap)?;
        core.peer_chain = self.peer;

        let res_master = hs.ks.derive(b"res master", &hs.transcript.current());
        for i in 0..hs.config.tickets_per_handshake {
            let mut age = [0u8; 4];
            rand::fill(&mut age).map_err(|_| Error::internal("no randomness"))?;
            let age_add = u32::from_be_bytes(age);
            let nonce = vec![i as u8];
            let psk = resumption_psk(hs.suite.hash, res_master.expose(), &nonce);
            let Some(ticket) = seal_ticket(
                &hs.config,
                hs.suite,
                age_add,
                core.alpn.as_deref(),
                psk.expose(),
            )?
            else {
                break;
            };
            let nst = NewSessionTicket {
                lifetime: hs.config.ticket_lifetime.as_secs() as u32,
                age_add,
                nonce,
                ticket,
                extensions: Vec::new(),
            };
            core.send_hs(&nst.encode());
        }
        core.flush_hs()?;
        Ok(Box::new(Connected {
            on_ticket: |_: &mut Core, _: &Handshake| {
                Err(Error::unexpected("NewSessionTicket from a client"))
            },
        }))
    }
}
