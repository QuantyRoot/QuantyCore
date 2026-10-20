//! What the TLS 1.2 client and server share: the messages that differ
//! from TLS 1.3 (RFC 5246, RFC 8422) and the key derivation with the
//! extended master secret (RFC 7627).

use super::codec::{put_bytes, put_u16, put_vec, Reader};
use super::conn::{Core, State};
use super::crypto::ct::Secret;
use super::error::Error;
use super::key_schedule::prf12;
use super::msgs::{hs, Handshake};
use super::record::Protection;
use super::suites::Suite12;

/// A Certificate message: a list of certificates, without the context
/// and per-entry extensions of TLS 1.3.
pub(super) fn encode_certificate(chain: &[Vec<u8>]) -> Handshake {
    let mut b = Vec::new();
    put_vec(&mut b, 3, |o| {
        for der in chain {
            put_bytes(o, 3, der);
        }
    });
    Handshake::new(hs::CERTIFICATE, b)
}

pub(super) fn parse_certificate(body: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    let d = || Error::decode("Certificate");
    let mut r = Reader::new(body);
    let list = r.vec24().ok_or_else(d)?;
    r.end().ok_or_else(d)?;
    let mut l = Reader::new(list);
    let mut chain = Vec::new();
    while !l.is_empty() {
        let der = l.vec24().ok_or_else(d)?;
        if der.is_empty() {
            return Err(d());
        }
        chain.push(der.to_vec());
    }
    Ok(chain)
}

/// The ECDHE parameters of a ServerKeyExchange and their signature.
pub(super) struct ServerKx {
    pub group: u16,
    pub point: Vec<u8>,
    pub scheme: u16,
    pub signature: Vec<u8>,
}

/// curve_type named_curve (RFC 8422 5.4); explicit curves are refused.
const NAMED_CURVE: u8 = 3;

impl ServerKx {
    pub(super) fn parse(body: &[u8]) -> Result<ServerKx, Error> {
        let d = || Error::decode("ServerKeyExchange");
        let mut r = Reader::new(body);
        if r.u8().ok_or_else(d)? != NAMED_CURVE {
            return Err(Error::illegal("ServerKeyExchange without a named curve"));
        }
        let group = r.u16().ok_or_else(d)?;
        let point = r.vec8().ok_or_else(d)?.to_vec();
        let scheme = r.u16().ok_or_else(d)?;
        let signature = r.vec16().ok_or_else(d)?.to_vec();
        r.end().ok_or_else(d)?;
        if point.is_empty() || signature.is_empty() {
            return Err(d());
        }
        Ok(ServerKx {
            group,
            point,
            scheme,
            signature,
        })
    }

    pub(super) fn params(&self) -> Vec<u8> {
        params(self.group, &self.point)
    }

    pub(super) fn encode(&self) -> Handshake {
        let mut b = self.params();
        put_u16(&mut b, self.scheme);
        put_bytes(&mut b, 2, &self.signature);
        Handshake::new(hs::SERVER_KEY_EXCHANGE, b)
    }
}

pub(super) fn params(group: u16, point: &[u8]) -> Vec<u8> {
    let mut b = vec![NAMED_CURVE];
    put_u16(&mut b, group);
    put_bytes(&mut b, 1, point);
    b
}

/// What the ServerKeyExchange signature covers: both randoms, then the
/// parameters.
pub(super) fn signed_params(
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    params: &[u8],
) -> Vec<u8> {
    let mut m = client_random.to_vec();
    m.extend_from_slice(server_random);
    m.extend_from_slice(params);
    m
}

/// certificate_types rsa_sign and ecdsa_sign; RFC 8422 lets the second
/// cover Ed25519.
const CERT_TYPES: [u8; 2] = [1, 64];

pub(super) fn encode_cert_request(schemes: &[u16]) -> Handshake {
    let mut b = Vec::new();
    put_bytes(&mut b, 1, &CERT_TYPES);
    super::msgs::put_u16_list(&mut b, 2, schemes);
    // No certificate_authorities: the client picks its one certificate.
    put_u16(&mut b, 0);
    Handshake::new(hs::CERTIFICATE_REQUEST, b)
}

/// The schemes of a CertificateRequest.
pub(super) fn parse_cert_request(body: &[u8]) -> Result<Vec<u16>, Error> {
    let d = || Error::decode("CertificateRequest");
    let mut r = Reader::new(body);
    if r.vec8().ok_or_else(d)?.is_empty() {
        return Err(d());
    }
    let schemes = r.vec16().ok_or_else(d)?;
    let mut l = Vec::new();
    put_bytes(&mut l, 2, schemes);
    let schemes = super::msgs::read_u16_list(&l, 2)?;
    r.vec16().ok_or_else(d)?;
    r.end().ok_or_else(d)?;
    Ok(schemes)
}

/// A ClientKeyExchange: the client's ECDHE point.
pub(super) fn encode_client_kx(point: &[u8]) -> Handshake {
    let mut b = Vec::new();
    put_bytes(&mut b, 1, point);
    Handshake::new(hs::CLIENT_KEY_EXCHANGE, b)
}

pub(super) fn parse_client_kx(body: &[u8]) -> Result<&[u8], Error> {
    let d = || Error::decode("ClientKeyExchange");
    let mut r = Reader::new(body);
    let p = r.vec8().ok_or_else(d)?;
    r.end().ok_or_else(d)?;
    if p.is_empty() {
        return Err(d());
    }
    Ok(p)
}

/// ec_point_formats must include uncompressed (RFC 8422 5.1.2).
pub(super) fn check_point_formats(data: &[u8]) -> Result<(), Error> {
    let mut r = Reader::new(data);
    let f = r.vec8().ok_or(Error::decode("ec_point_formats"))?;
    r.end().ok_or(Error::decode("ec_point_formats"))?;
    if !f.contains(&0) {
        return Err(Error::illegal(
            "uncompressed points not supported by the peer",
        ));
    }
    Ok(())
}

/// The keys of a TLS 1.2 connection.
pub(super) struct Keys {
    pub master: Secret,
    pub client: Protection,
    pub server: Protection,
}

/// The extended master secret over `session_hash`, the hash of the
/// handshake up to and including ClientKeyExchange (RFC 7627 4), and the
/// key block expanded from it (RFC 5246 6.3).
pub(super) fn derive_keys(
    suite: Suite12,
    pre_master: &[u8],
    session_hash: &[u8],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> Keys {
    let master = prf12(
        suite.hash,
        pre_master,
        b"extended master secret",
        session_hash,
        48,
    );
    let mut seed = server_random.to_vec();
    seed.extend_from_slice(client_random);
    let (k, iv) = (suite.aead.key_len(), suite.aead.tls12_iv_len());
    let block = prf12(
        suite.hash,
        master.expose(),
        b"key expansion",
        &seed,
        2 * (k + iv),
    );
    let b = block.expose();
    let client = Protection::tls12(suite.aead, &b[..k], &b[2 * k..2 * k + iv]);
    let server = Protection::tls12(suite.aead, &b[k..2 * k], &b[2 * k + iv..]);
    Keys {
        master,
        client,
        server,
    }
}

/// Finished.verify_data (RFC 5246 7.4.9).
pub(super) fn verify_data(
    suite: Suite12,
    master: &Secret,
    label: &[u8],
    transcript: &[u8],
) -> Vec<u8> {
    let h = suite.hash.digest(transcript);
    prf12(suite.hash, master.expose(), label, &h, 12)
        .expose()
        .to_vec()
}

/// The randoms in the order the RFC 5705 exporter wants them.
pub(super) fn exporter(
    core: &mut Core,
    master: Secret,
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) {
    let mut r = client_random.to_vec();
    r.extend_from_slice(server_random);
    core.exporter12 = Some((master, r));
}

/// A finished TLS 1.2 connection. Renegotiation is not built, so any
/// handshake message ends the connection.
pub(super) struct Connected12;

impl State for Connected12 {
    fn handle(
        self: Box<Self>,
        _core: &mut Core,
        _msg: Handshake,
        _raw: Vec<u8>,
    ) -> Result<Box<dyn State>, Error> {
        Err(Error::unexpected("renegotiation is not supported"))
    }

    fn is_connected(&self) -> bool {
        true
    }
}
