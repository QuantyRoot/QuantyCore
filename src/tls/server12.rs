//! The TLS 1.2 server handshake, for clients that do not offer 1.3:
//! ECDHE, an AEAD, and the extended master secret.

use super::auth::{fits_auth, with_pkcs1, PeerVerifier, PublicKey};
use super::config::{ClientAuth, ServerConfig};
use super::conn::{Core, State};
use super::crypto::ct::Secret;
use super::crypto::rand;
use super::error::{alert, Error};
use super::key_schedule::verify_finished;
use super::kx::KxSecret;
use super::msgs::*;
use super::record::Protection;
use super::server::choose_alpn;
use super::suites::Suite12;
use super::tls12::*;
use std::sync::Arc;

/// TLS_EMPTY_RENEGOTIATION_INFO_SCSV (RFC 5746 3.3).
const RENEGOTIATION_SCSV: u16 = 0x00ff;

/// True for a ClientHello that offers TLS 1.2 and not 1.3.
pub(super) fn wants_tls12(config: &ServerConfig, ch: &ClientHello) -> Result<bool, Error> {
    match ch.ext(ext::SUPPORTED_VERSIONS) {
        Some(d) => {
            let v = read_u16_list(d, 1)?;
            Ok((config.max_tls12 || !v.contains(&version::TLS13)) && v.contains(&version::TLS12))
        }
        None => Ok(ch.legacy_version >= version::TLS12),
    }
}

struct Hs {
    suite: Suite12,
    client_random: [u8; 32],
    server_random: [u8; 32],
    transcript: Vec<u8>,
}

pub(super) fn client_hello(
    core: &mut Core,
    config: Arc<ServerConfig>,
    ch: ClientHello,
    raw: Vec<u8>,
) -> Result<Box<dyn State>, Error> {
    if !ch.compression.contains(&0) {
        return Err(Error::illegal("no null compression"));
    }
    match ch.ext(ext::EXTENDED_MASTER_SECRET) {
        Some([]) => {}
        Some(_) => return Err(Error::decode("extended_master_secret")),
        None => {
            return Err(Error::handshake_failure(
                "the extended master secret is required",
            ))
        }
    }
    // A first handshake carries an empty renegotiated_connection.
    if ch.ext(ext::RENEGOTIATION_INFO).is_some_and(|r| r != [0]) {
        return Err(Error::handshake_failure("renegotiation_info"));
    }
    let secure_renegotiation =
        ch.ext(ext::RENEGOTIATION_INFO).is_some() || ch.cipher_suites.contains(&RENEGOTIATION_SCSV);
    if let Some(f) = ch.ext(ext::EC_POINT_FORMATS) {
        check_point_formats(f)?;
    }
    let groups = match ch.ext(ext::SUPPORTED_GROUPS) {
        Some(d) => read_u16_list(d, 2)?,
        None => Vec::new(),
    };
    let group = config
        .groups
        .iter()
        .copied()
        .find(|g| groups.contains(g))
        .ok_or(Error::handshake_failure("no common group"))?;
    // Without signature_algorithms the default would be SHA-1, which is
    // not supported.
    let schemes = read_u16_list(
        ch.ext(ext::SIGNATURE_ALGORITHMS)
            .ok_or(Error::handshake_failure("no signature_algorithms"))?,
        2,
    )?;
    let (suite, scheme) = config
        .suites12
        .iter()
        .filter(|s| ch.cipher_suites.contains(&s.id))
        .find_map(|s| {
            let fit: Vec<u16> = schemes
                .iter()
                .copied()
                .filter(|&x| fits_auth(x, s.auth))
                .collect();
            config.signer.choose_scheme12(&fit).map(|sc| (*s, sc))
        })
        .ok_or(Error::handshake_failure("no common cipher suite"))?;
    if let Some(sn) = ch.ext(ext::SERVER_NAME) {
        core.server_name = read_server_name(sn)?;
    }
    core.alpn = choose_alpn(&config, &ch, None)?;
    core.tls12 = Some(suite);

    // RFC 8446 4.1.3: the last eight bytes tell a client that also
    // speaks 1.3 that it was talked down.
    let mut random = [0u8; 32];
    rand::fill(&mut random).map_err(|_| Error::internal("no randomness"))?;
    if !config.max_tls12 {
        random[24..].copy_from_slice(&DOWNGRADE_TLS12);
    }
    let mut exts = Vec::new();
    if secure_renegotiation {
        exts.push(Extension {
            typ: ext::RENEGOTIATION_INFO,
            data: vec![0],
        });
    }
    exts.push(Extension {
        typ: ext::EXTENDED_MASTER_SECRET,
        data: Vec::new(),
    });
    if ch.ext(ext::EC_POINT_FORMATS).is_some() {
        exts.push(Extension {
            typ: ext::EC_POINT_FORMATS,
            data: vec![1, 0],
        });
    }
    if let Some(p) = &core.alpn {
        exts.push(Extension {
            typ: ext::ALPN,
            data: write_alpn(std::slice::from_ref(p)),
        });
    }
    let sh = ServerHello {
        legacy_version: version::TLS12,
        random,
        // No session id: TLS 1.2 sessions are not resumed (ADR-028).
        session_id: Vec::new(),
        cipher_suite: suite.id,
        compression: 0,
        extensions: exts,
    };
    let mut transcript = raw;
    transcript.extend_from_slice(&core.send_hs(&sh.encode()));
    transcript.extend_from_slice(&core.send_hs(&encode_certificate(&config.chain)));

    let kx = KxSecret::generate(group)?;
    let point = kx.public();
    let signed = signed_params(&ch.random, &random, &params(group, &point));
    let signature = config.signer.sign(scheme, &signed)?;
    let skx = ServerKx {
        group,
        point,
        scheme,
        signature,
    };
    transcript.extend_from_slice(&core.send_hs(&skx.encode()));

    let client_verifier = match &config.client_auth {
        ClientAuth::Required(v) => {
            let cr = encode_cert_request(&with_pkcs1(v.schemes()));
            transcript.extend_from_slice(&core.send_hs(&cr));
            Some(v.clone())
        }
        ClientAuth::None => None,
    };
    transcript.extend_from_slice(&core.send_hs(&Handshake::new(hs::SERVER_HELLO_DONE, Vec::new())));
    core.flush_hs()?;

    let hs = Hs {
        suite,
        client_random: ch.random,
        server_random: random,
        transcript,
    };
    Ok(match client_verifier {
        Some(v) => Box::new(ExpectCertificate {
            hs,
            kx,
            verifier: v,
        }),
        None => Box::new(ExpectClientKx { hs, kx, peer: None }),
    })
}

struct ExpectCertificate {
    hs: Hs,
    kx: KxSecret,
    verifier: Arc<dyn PeerVerifier>,
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
        let chain = parse_certificate(&msg.body)?;
        if chain.is_empty() {
            return Err(Error::handshake_failure("client sent no certificate"));
        }
        let key = self.verifier.verify(&chain, None)?;
        hs.transcript.extend_from_slice(&raw);
        Ok(Box::new(ExpectClientKx {
            hs,
            kx: self.kx,
            peer: Some(Peer {
                chain,
                key,
                verifier: self.verifier,
            }),
        }))
    }
}

struct Peer {
    chain: Vec<Vec<u8>>,
    key: PublicKey,
    verifier: Arc<dyn PeerVerifier>,
}

struct ExpectClientKx {
    hs: Hs,
    kx: KxSecret,
    peer: Option<Peer>,
}

impl State for ExpectClientKx {
    fn handle(
        self: Box<Self>,
        core: &mut Core,
        msg: Handshake,
        raw: Vec<u8>,
    ) -> Result<Box<dyn State>, Error> {
        let mut hs = self.hs;
        if msg.typ != hs::CLIENT_KEY_EXCHANGE {
            return Err(Error::unexpected("expected ClientKeyExchange"));
        }
        let shared = self.kx.agree(parse_client_kx(&msg.body)?)?;
        hs.transcript.extend_from_slice(&raw);
        let session_hash = hs.suite.hash.digest(&hs.transcript);
        let keys = derive_keys(
            hs.suite,
            shared.expose(),
            &session_hash,
            &hs.client_random,
            &hs.server_random,
        );
        let next = Keyed {
            hs,
            master: keys.master,
            write: keys.server,
        };
        Ok(match self.peer {
            Some(peer) => Box::new(ExpectCertificateVerify {
                next,
                read: keys.client,
                peer,
            }),
            None => {
                core.expect_ccs(keys.client);
                Box::new(ExpectFinished { next, chain: None })
            }
        })
    }
}

/// The handshake once the keys are known.
struct Keyed {
    hs: Hs,
    master: Secret,
    write: Protection,
}

struct ExpectCertificateVerify {
    next: Keyed,
    read: Protection,
    peer: Peer,
}

impl State for ExpectCertificateVerify {
    fn handle(
        self: Box<Self>,
        core: &mut Core,
        msg: Handshake,
        raw: Vec<u8>,
    ) -> Result<Box<dyn State>, Error> {
        let mut next = self.next;
        if msg.typ != hs::CERTIFICATE_VERIFY {
            return Err(Error::unexpected("expected CertificateVerify"));
        }
        let cv = CertificateVerify::parse(&msg.body)?;
        if !with_pkcs1(self.peer.verifier.schemes()).contains(&cv.scheme) {
            return Err(Error::illegal("signature scheme not offered"));
        }
        self.peer
            .key
            .verify12(cv.scheme, &next.hs.transcript, &cv.signature)?;
        next.hs.transcript.extend_from_slice(&raw);
        // Only now: change_cipher_spec before CertificateVerify is out of
        // order.
        core.expect_ccs(self.read);
        Ok(Box::new(ExpectFinished {
            next,
            chain: Some(self.peer.chain),
        }))
    }
}

struct ExpectFinished {
    next: Keyed,
    chain: Option<Vec<Vec<u8>>>,
}

impl State for ExpectFinished {
    fn handle(
        self: Box<Self>,
        core: &mut Core,
        msg: Handshake,
        raw: Vec<u8>,
    ) -> Result<Box<dyn State>, Error> {
        let Keyed {
            mut hs,
            master,
            write,
        } = self.next;
        if msg.typ != hs::FINISHED || !core.read_protected() {
            return Err(Error::unexpected(
                "expected change_cipher_spec and Finished",
            ));
        }
        let expected = verify_data(hs.suite, &master, b"client finished", &hs.transcript);
        if !verify_finished(&expected, &msg.body) {
            return Err(Error::new(
                alert::DECRYPT_ERROR,
                "client Finished does not verify",
            ));
        }
        hs.transcript.extend_from_slice(&raw);
        core.no_buffered_handshake()?;
        core.change_write_keys(write)?;
        let fin = verify_data(hs.suite, &master, b"server finished", &hs.transcript);
        core.send_hs(&Handshake::new(hs::FINISHED, fin));
        core.peer_chain = self.chain;
        exporter(core, master, &hs.client_random, &hs.server_random);
        core.open_read();
        core.open_write()?;
        Ok(Box::new(Connected12))
    }
}
