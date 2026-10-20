//! The TLS 1.2 client handshake after a ServerHello without
//! supported_versions: ECDHE, an AEAD, and the extended master secret.

use super::auth::{fits_auth, PublicKey};
use super::client::{offered_schemes, Offer};
use super::conn::{Core, State};
use super::crypto::ct::Secret;
use super::error::{alert, Error};
use super::key_schedule::verify_finished;
use super::kx::{self, KxSecret};
use super::msgs::*;
use super::suites::{tls12_suite, Suite12};
use super::tls12::*;

struct Hs {
    offer: Offer,
    suite: Suite12,
    client_random: [u8; 32],
    server_random: [u8; 32],
    /// Every handshake message so far. TLS 1.2 signs the messages
    /// themselves in CertificateVerify, not a hash of them.
    transcript: Vec<u8>,
}

pub(super) fn server_hello(
    core: &mut Core,
    offer: Offer,
    client_random: [u8; 32],
    client_hello: Vec<u8>,
    sh: ServerHello,
    raw: Vec<u8>,
) -> Result<Box<dyn State>, Error> {
    // RFC 8446 4.1.3: a TLS 1.3 server that was talked down to 1.2 says
    // so in its random. Seeing it means someone removed 1.3 from the
    // ClientHello.
    if sh.random[24..] == DOWNGRADE_TLS12 || sh.random[24..] == DOWNGRADE_TLS11 {
        return Err(Error::illegal("downgrade from TLS 1.3"));
    }
    if sh.compression != 0 {
        return Err(Error::illegal("compression"));
    }
    // The session id sent is random and resumes nothing; a server
    // claiming to resume it is lying.
    if !sh.session_id.is_empty() && sh.session_id == offer.session_id {
        return Err(Error::illegal(
            "server resumes a session that was not offered",
        ));
    }
    let suite = tls12_suite(sh.cipher_suite)
        .filter(|s| offer.suites.contains(&s.id))
        .ok_or(Error::illegal("cipher suite not offered"))?;
    for e in &sh.extensions {
        match e.typ {
            ext::RENEGOTIATION_INFO => {
                if e.data != [0] {
                    return Err(Error::handshake_failure("renegotiation_info"));
                }
            }
            ext::SERVER_NAME if !offer.extensions.contains(&ext::SERVER_NAME) => {
                return Err(Error::new(
                    alert::UNSUPPORTED_EXTENSION,
                    "extension not offered",
                ))
            }
            ext::EXTENDED_MASTER_SECRET | ext::SERVER_NAME => {
                if !e.data.is_empty() {
                    return Err(Error::decode("extension in ServerHello"));
                }
            }
            ext::EC_POINT_FORMATS => check_point_formats(&e.data)?,
            ext::ALPN => {
                let list = read_alpn(&e.data)?;
                if list.len() != 1 || !offer.config.alpn.contains(&list[0]) {
                    return Err(Error::illegal("ALPN protocol not offered"));
                }
                core.alpn = Some(list[0].clone());
            }
            t if !offer.extensions.contains(&t) => {
                return Err(Error::new(
                    alert::UNSUPPORTED_EXTENSION,
                    "extension not offered",
                ))
            }
            _ => {
                return Err(Error::illegal(
                    "extension not allowed in a TLS 1.2 ServerHello",
                ))
            }
        }
    }
    if sh.ext(ext::EXTENDED_MASTER_SECRET).is_none() {
        return Err(Error::handshake_failure(
            "server does not support the extended master secret",
        ));
    }
    core.tls12 = Some(suite);
    let mut transcript = client_hello;
    transcript.extend_from_slice(&raw);
    Ok(Box::new(ExpectCertificate {
        hs: Hs {
            offer,
            suite,
            client_random,
            server_random: sh.random,
            transcript,
        },
    }))
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
        let chain = parse_certificate(&msg.body)?;
        if chain.is_empty() {
            return Err(Error::decode("server sent no certificate"));
        }
        let key = hs
            .offer
            .config
            .verifier
            .verify(&chain, hs.offer.name.as_deref())?;
        if !key.fits(hs.suite.auth) {
            return Err(Error::new(
                alert::UNSUPPORTED_CERTIFICATE,
                "certificate key does not fit the cipher suite",
            ));
        }
        hs.transcript.extend_from_slice(&raw);
        Ok(Box::new(ExpectServerKx { hs, key, chain }))
    }
}

struct ExpectServerKx {
    hs: Hs,
    key: PublicKey,
    chain: Vec<Vec<u8>>,
}

impl State for ExpectServerKx {
    fn handle(
        self: Box<Self>,
        core: &mut Core,
        msg: Handshake,
        raw: Vec<u8>,
    ) -> Result<Box<dyn State>, Error> {
        let mut hs = self.hs;
        if msg.typ != hs::SERVER_KEY_EXCHANGE {
            return Err(Error::unexpected("expected ServerKeyExchange"));
        }
        let skx = ServerKx::parse(&msg.body)?;
        if !kx::is_ecdhe(skx.group) || !hs.offer.config.groups.contains(&skx.group) {
            return Err(Error::illegal("group not offered"));
        }
        if !offered_schemes(&hs.offer.config).contains(&skx.scheme)
            || !fits_auth(skx.scheme, hs.suite.auth)
        {
            return Err(Error::illegal("signature scheme not offered"));
        }
        let signed = signed_params(&hs.client_random, &hs.server_random, &skx.params());
        self.key.verify12(skx.scheme, &signed, &skx.signature)?;
        let kx = KxSecret::generate(skx.group)?;
        core.group = Some(skx.group);
        let shared = kx.agree(&skx.point)?;
        hs.transcript.extend_from_slice(&raw);
        Ok(Box::new(ExpectServerHelloDone {
            hs,
            chain: self.chain,
            kx,
            shared,
            cert_request: None,
        }))
    }
}

struct ExpectServerHelloDone {
    hs: Hs,
    chain: Vec<Vec<u8>>,
    kx: KxSecret,
    shared: Secret,
    cert_request: Option<Vec<u16>>,
}

impl State for ExpectServerHelloDone {
    fn handle(
        self: Box<Self>,
        core: &mut Core,
        msg: Handshake,
        raw: Vec<u8>,
    ) -> Result<Box<dyn State>, Error> {
        let mut s = *self;
        if msg.typ == hs::CERTIFICATE_REQUEST && s.cert_request.is_none() {
            s.cert_request = Some(parse_cert_request(&msg.body)?);
            s.hs.transcript.extend_from_slice(&raw);
            return Ok(Box::new(s));
        }
        if msg.typ != hs::SERVER_HELLO_DONE {
            return Err(Error::unexpected("expected ServerHelloDone"));
        }
        if !msg.body.is_empty() {
            return Err(Error::decode("ServerHelloDone"));
        }
        let mut hs = s.hs;
        hs.transcript.extend_from_slice(&raw);

        let chosen = match &s.cert_request {
            None => None,
            Some(schemes) => {
                let chosen = hs
                    .offer
                    .config
                    .client_cert
                    .as_ref()
                    .and_then(|(chain, key)| {
                        key.choose_scheme12(schemes)
                            .map(|sc| (chain.clone(), key.clone(), sc))
                    });
                let chain = chosen.as_ref().map(|c| c.0.clone()).unwrap_or_default();
                let raw = core.send_hs(&encode_certificate(&chain));
                hs.transcript.extend_from_slice(&raw);
                chosen
            }
        };
        let raw = core.send_hs(&encode_client_kx(&s.kx.public()));
        hs.transcript.extend_from_slice(&raw);
        let session_hash = hs.suite.hash.digest(&hs.transcript);
        let keys = derive_keys(
            hs.suite,
            s.shared.expose(),
            &session_hash,
            &hs.client_random,
            &hs.server_random,
        );
        if let Some((_, key, scheme)) = chosen {
            let signature = key.sign(scheme, &hs.transcript)?;
            let raw = core.send_hs(&CertificateVerify { scheme, signature }.encode());
            hs.transcript.extend_from_slice(&raw);
        }
        core.change_write_keys(keys.client)?;
        let fin = verify_data(hs.suite, &keys.master, b"client finished", &hs.transcript);
        let raw = core.send_hs(&Handshake::new(hs::FINISHED, fin));
        hs.transcript.extend_from_slice(&raw);
        core.flush_hs()?;
        core.expect_ccs(keys.server);
        Ok(Box::new(ExpectFinished {
            hs,
            master: keys.master,
            chain: s.chain,
        }))
    }
}

struct ExpectFinished {
    hs: Hs,
    master: Secret,
    chain: Vec<Vec<u8>>,
}

impl State for ExpectFinished {
    fn handle(
        self: Box<Self>,
        core: &mut Core,
        msg: Handshake,
        _raw: Vec<u8>,
    ) -> Result<Box<dyn State>, Error> {
        let hs = self.hs;
        if msg.typ != hs::FINISHED || !core.read_protected() {
            return Err(Error::unexpected(
                "expected change_cipher_spec and Finished",
            ));
        }
        let expected = verify_data(hs.suite, &self.master, b"server finished", &hs.transcript);
        if !verify_finished(&expected, &msg.body) {
            return Err(Error::new(
                alert::DECRYPT_ERROR,
                "server Finished does not verify",
            ));
        }
        core.peer_chain = Some(self.chain);
        exporter(core, self.master, &hs.client_random, &hs.server_random);
        core.open_read();
        core.open_write()?;
        Ok(Box::new(Connected12))
    }
}
