//! Client and server of this crate connected to each other in memory.
//!
//! Until X.509 exists, a "certificate" here is the raw Ed25519 public key
//! and the verifier compares it with the key it expects. Everything else
//! is the real handshake.

#![cfg(test)]

use super::auth::{scheme, PeerVerifier, PublicKey};
use super::config::{ClientConfig, ServerConfig};
use super::crypto::ed25519::SigningKey;
use super::error::{alert, Error};
use super::{ClientConnection, Connection, ServerConnection};
use std::sync::Arc;

pub(crate) struct KeyVerifier {
    pub key: [u8; 32],
    pub name: Option<String>,
}

impl PeerVerifier for KeyVerifier {
    fn verify(&self, chain: &[Vec<u8>], name: Option<&str>) -> Result<PublicKey, Error> {
        if chain[0] != self.key {
            return Err(Error::new(alert::BAD_CERTIFICATE, "unknown key"));
        }
        if self.name.is_some() && name != self.name.as_deref() {
            return Err(Error::new(alert::BAD_CERTIFICATE, "wrong name"));
        }
        Ok(PublicKey::Ed25519(self.key))
    }
    fn schemes(&self) -> Vec<u16> {
        vec![scheme::ED25519]
    }
}

pub(crate) struct Pair {
    pub server_key: Arc<SigningKey>,
    pub client: ClientConfig,
    pub server: ServerConfig,
}

pub(crate) fn pair() -> Pair {
    let server_key = Arc::new(SigningKey::from_seed(&[7; 32]));
    let pk = server_key.public_key();
    let client = ClientConfig::with_verifier(Arc::new(KeyVerifier {
        key: pk,
        name: Some("example.test".into()),
    }));
    let server = ServerConfig::with_signer(vec![pk.to_vec()], server_key.clone()).unwrap();
    Pair {
        server_key,
        client,
        server,
    }
}

/// Moves bytes both ways until neither side has anything left to send.
/// `max_chunk` limits how many bytes are handed over at once, to exercise
/// records and messages that arrive in pieces.
pub(crate) fn pump(
    c: &mut Connection,
    s: &mut Connection,
    max_chunk: usize,
) -> Result<(), (bool, Error)> {
    loop {
        let a = c.take_tls();
        let b = s.take_tls();
        if a.is_empty() && b.is_empty() {
            return Ok(());
        }
        for chunk in a.chunks(max_chunk) {
            s.read_tls(chunk).map_err(|e| (false, e))?;
        }
        for chunk in b.chunks(max_chunk) {
            c.read_tls(chunk).map_err(|e| (true, e))?;
        }
    }
}

pub(crate) fn connect(
    client: ClientConfig,
    server: ServerConfig,
) -> (ClientConnection, ServerConnection) {
    let mut c = ClientConnection::new(Arc::new(client), "example.test").unwrap();
    let mut s = ServerConnection::new(Arc::new(server));
    pump(&mut c, &mut s, usize::MAX).unwrap();
    (c, s)
}

#[test]
fn handshake_alpn_sni_data_and_close() {
    let mut p = pair();
    p.client.set_alpn(&[b"h2", b"http/1.1"]);
    p.server.set_alpn(&[b"http/1.1", b"h2"]);
    let (mut c, mut s) = connect(p.client, p.server);
    assert!(!c.is_handshaking() && !s.is_handshaking());
    assert_eq!(c.alpn_protocol(), Some(&b"http/1.1"[..]));
    assert_eq!(s.alpn_protocol(), Some(&b"http/1.1"[..]));
    assert_eq!(s.server_name(), Some("example.test"));
    assert_eq!(c.cipher_suite(), Some(0x1303));
    assert_eq!(c.peer_certificates().unwrap()[0], p.server_key.public_key());

    c.write(b"ping").unwrap();
    s.write(b"pong").unwrap();
    pump(&mut c, &mut s, usize::MAX).unwrap();
    assert_eq!(s.take_plaintext(), b"ping");
    assert_eq!(c.take_plaintext(), b"pong");

    assert_eq!(
        c.export_keying_material(b"EXPORTER-test", b"ctx", 32)
            .unwrap(),
        s.export_keying_material(b"EXPORTER-test", b"ctx", 32)
            .unwrap()
    );

    c.close();
    pump(&mut c, &mut s, usize::MAX).unwrap();
    assert!(s.is_peer_closed());
    assert!(!c.is_peer_closed());
}

#[test]
fn every_byte_on_its_own() {
    let p = pair();
    let mut c = ClientConnection::new(Arc::new(p.client), "example.test").unwrap();
    let mut s = ServerConnection::new(Arc::new(p.server));
    c.write(&[0x5a; 40_000]).unwrap();
    pump(&mut c, &mut s, 1).unwrap();
    assert_eq!(s.take_plaintext(), vec![0x5a; 40_000]);
}

#[test]
fn resumption_with_a_ticket() {
    let p = pair();
    let client = Arc::new(p.client);
    let server = Arc::new(p.server);
    let mut c = ClientConnection::new(client.clone(), "example.test").unwrap();
    let mut s = ServerConnection::new(server.clone());
    pump(&mut c, &mut s, usize::MAX).unwrap();
    assert!(!c.is_resumed());

    let mut c = ClientConnection::new(client.clone(), "example.test").unwrap();
    let mut s = ServerConnection::new(server.clone());
    pump(&mut c, &mut s, usize::MAX).unwrap();
    assert!(c.is_resumed() && s.is_resumed());
    assert!(c.peer_certificates().is_none());
    c.write(b"again").unwrap();
    pump(&mut c, &mut s, usize::MAX).unwrap();
    assert_eq!(s.take_plaintext(), b"again");

    // Each ticket is used once; the server sent two per handshake, so a
    // third and fourth connection resume and none is used twice.
    for _ in 0..2 {
        let mut c = ClientConnection::new(client.clone(), "example.test").unwrap();
        let mut s = ServerConnection::new(server.clone());
        pump(&mut c, &mut s, usize::MAX).unwrap();
        assert!(c.is_resumed());
    }
}

#[test]
fn a_ticket_from_another_server_means_a_full_handshake() {
    let p = pair();
    let client = Arc::new(p.client);
    let (pk, key) = (p.server_key.public_key(), p.server_key.clone());
    let mut c = ClientConnection::new(client.clone(), "example.test").unwrap();
    let mut s = ServerConnection::new(Arc::new(p.server));
    pump(&mut c, &mut s, usize::MAX).unwrap();
    let other = Arc::new(ServerConfig::with_signer(vec![pk.to_vec()], key).unwrap());
    let mut c = ClientConnection::new(client, "example.test").unwrap();
    let mut s = ServerConnection::new(other);
    pump(&mut c, &mut s, usize::MAX).unwrap();
    assert!(!c.is_handshaking() && !c.is_resumed());
}

#[test]
fn mutual_authentication() {
    let mut p = pair();
    let client_key = Arc::new(SigningKey::from_seed(&[9; 32]));
    let cpk = client_key.public_key();
    p.server.require_client_verifier(Arc::new(KeyVerifier {
        key: cpk,
        name: None,
    }));
    p.client.set_client_signer(vec![cpk.to_vec()], client_key);
    let (c, s) = connect(p.client, p.server);
    assert!(!c.is_handshaking());
    assert_eq!(s.peer_certificates().unwrap()[0], cpk);
}

#[test]
fn missing_client_certificate_is_refused() {
    let mut p = pair();
    p.server.require_client_verifier(Arc::new(KeyVerifier {
        key: [1; 32],
        name: None,
    }));
    let mut c = ClientConnection::new(Arc::new(p.client), "example.test").unwrap();
    let mut s = ServerConnection::new(Arc::new(p.server));
    let (on_client, e) = pump(&mut c, &mut s, usize::MAX).unwrap_err();
    assert!(!on_client);
    assert!(matches!(
        e,
        Error::Local {
            alert: alert::CERTIFICATE_REQUIRED,
            ..
        }
    ));
    // The alert reaches the client, which reports the server's reason.
    assert_eq!(
        c.read_tls(&s.take_tls()),
        Err(Error::Peer(alert::CERTIFICATE_REQUIRED))
    );
}

#[test]
fn no_common_application_protocol() {
    let mut p = pair();
    p.client.set_alpn(&[b"h2"]);
    p.server.set_alpn(&[b"http/1.1"]);
    let mut c = ClientConnection::new(Arc::new(p.client), "example.test").unwrap();
    let mut s = ServerConnection::new(Arc::new(p.server));
    let (_, e) = pump(&mut c, &mut s, usize::MAX).unwrap_err();
    assert!(matches!(
        e,
        Error::Local {
            alert: alert::NO_APPLICATION_PROTOCOL,
            ..
        }
    ));
}

#[test]
fn wrong_name_or_key_fails_the_handshake() {
    let p = pair();
    let mut c = ClientConnection::new(Arc::new(p.client), "other.test").unwrap();
    let mut s = ServerConnection::new(Arc::new(p.server));
    let (on_client, e) = pump(&mut c, &mut s, usize::MAX).unwrap_err();
    assert!(on_client);
    assert_eq!(e, Error::new(alert::BAD_CERTIFICATE, "wrong name"));

    // A server whose key signs for a different certificate: the
    // signature check in CertificateVerify fails.
    let p = pair();
    let mut server = p.server;
    server.signer = Arc::new(SigningKey::from_seed(&[8; 32]));
    let mut c = ClientConnection::new(Arc::new(p.client), "example.test").unwrap();
    let mut s = ServerConnection::new(Arc::new(server));
    let (_, e) = pump(&mut c, &mut s, usize::MAX).unwrap_err();
    assert!(matches!(
        e,
        Error::Local {
            alert: alert::DECRYPT_ERROR,
            ..
        }
    ));
}

#[test]
fn a_flipped_bit_in_a_record_is_bad_record_mac() {
    let p = pair();
    let (mut c, mut s) = connect(p.client, p.server);
    c.write(b"data").unwrap();
    let mut wire = c.take_tls();
    let last = wire.len() - 1;
    wire[last] ^= 1;
    assert!(matches!(
        s.read_tls(&wire),
        Err(Error::Local {
            alert: alert::BAD_RECORD_MAC,
            ..
        })
    ));
    assert!(s.write(b"x").is_err());
}

#[test]
fn key_update_both_ways() {
    let p = pair();
    let (mut c, mut s) = connect(p.client, p.server);
    pump(&mut c, &mut s, usize::MAX).unwrap();
    c.update_keys().unwrap();
    c.write(b"after").unwrap();
    pump(&mut c, &mut s, usize::MAX).unwrap();
    s.write(b"reply").unwrap();
    pump(&mut c, &mut s, usize::MAX).unwrap();
    assert_eq!(s.take_plaintext(), b"after");
    assert_eq!(c.take_plaintext(), b"reply");
}

#[test]
fn data_written_before_the_handshake_is_sent_after_it() {
    let p = pair();
    let mut c = ClientConnection::new(Arc::new(p.client), "example.test").unwrap();
    let mut s = ServerConnection::new(Arc::new(p.server));
    c.write(b"early").unwrap();
    assert!(c.is_handshaking());
    pump(&mut c, &mut s, usize::MAX).unwrap();
    assert_eq!(s.take_plaintext(), b"early");
}

#[test]
fn garbage_instead_of_a_client_hello() {
    let p = pair();
    let mut s = ServerConnection::new(Arc::new(p.server));
    assert!(s.read_tls(b"GET / HTTP/1.1\r\n\r\n").is_err());
    assert!(!s.is_handshaking());
}

fn record(typ: u8, body: &[u8]) -> Vec<u8> {
    let mut r = vec![typ, 3, 3, (body.len() >> 8) as u8, body.len() as u8];
    r.extend_from_slice(body);
    r
}

/// Runs a ClientHello through `edit` on its way to the server and returns
/// the server's error.
fn tamper_client_hello(edit: impl FnOnce(&mut super::msgs::ClientHello)) -> Error {
    use super::msgs::{hs, ClientHello, Handshake};
    let p = pair();
    let mut c = ClientConnection::new(Arc::new(p.client), "example.test").unwrap();
    let mut s = ServerConnection::new(Arc::new(p.server));
    let wire = c.take_tls();
    let mut ch = ClientHello::parse(&wire[9..]).unwrap();
    edit(&mut ch);
    let body = Handshake::new(hs::CLIENT_HELLO, ch.encode().body).encode();
    s.read_tls(&record(22, &body)).unwrap_err()
}

/// Runs the server's ServerHello through `edit` on its way to the client
/// and returns the client's error.
fn tamper_server_hello(edit: impl FnOnce(&mut super::msgs::ServerHello)) -> Error {
    use super::msgs::{hs, Handshake, ServerHello};
    let p = pair();
    let mut c = ClientConnection::new(Arc::new(p.client), "example.test").unwrap();
    let mut s = ServerConnection::new(Arc::new(p.server));
    s.read_tls(&c.take_tls()).unwrap();
    let wire = s.take_tls();
    let len = u16::from_be_bytes([wire[3], wire[4]]) as usize;
    let mut sh = ServerHello::parse(&wire[9..5 + len]).unwrap();
    edit(&mut sh);
    let body = Handshake::new(hs::SERVER_HELLO, sh.encode().body).encode();
    c.read_tls(&record(22, &body)).unwrap_err()
}

/// What is broken, the alert it must cause, and the edit that breaks it.
type Case<M> = (&'static str, u8, Box<dyn FnOnce(&mut M)>);

fn alert_of(e: &Error) -> u8 {
    match e {
        Error::Local { alert, .. } => *alert,
        other => panic!("not a local error: {other:?}"),
    }
}

#[test]
fn client_refuses_a_broken_server_hello() {
    use super::msgs::{ext, group, Extension, HRR_RANDOM};
    let cases: Vec<Case<super::msgs::ServerHello>> = vec![
        (
            "session id",
            alert::ILLEGAL_PARAMETER,
            Box::new(|sh| sh.session_id[0] ^= 1),
        ),
        (
            "suite",
            alert::ILLEGAL_PARAMETER,
            Box::new(|sh| sh.cipher_suite = 0x1304),
        ),
        (
            "compression",
            alert::ILLEGAL_PARAMETER,
            Box::new(|sh| sh.compression = 1),
        ),
        (
            "no supported_versions",
            alert::PROTOCOL_VERSION,
            Box::new(|sh| sh.extensions.retain(|e| e.typ != ext::SUPPORTED_VERSIONS)),
        ),
        (
            "version",
            alert::ILLEGAL_PARAMETER,
            Box::new(|sh| {
                for e in sh.extensions.iter_mut() {
                    if e.typ == ext::SUPPORTED_VERSIONS {
                        e.data = vec![3, 3];
                    }
                }
            }),
        ),
        (
            "unsolicited extension",
            alert::UNSUPPORTED_EXTENSION,
            Box::new(|sh| {
                sh.extensions.push(Extension {
                    typ: ext::COOKIE,
                    data: vec![0, 1, 0],
                })
            }),
        ),
        (
            "share for another group",
            alert::ILLEGAL_PARAMETER,
            Box::new(|sh| {
                for e in sh.extensions.iter_mut() {
                    if e.typ == ext::KEY_SHARE {
                        e.data[..2].copy_from_slice(&group::SECP256R1.to_be_bytes());
                    }
                }
            }),
        ),
        (
            "share of small order",
            alert::ILLEGAL_PARAMETER,
            Box::new(|sh| {
                for e in sh.extensions.iter_mut() {
                    if e.typ == ext::KEY_SHARE {
                        e.data[4..].fill(0);
                    }
                }
            }),
        ),
        (
            "retry that changes nothing",
            alert::ILLEGAL_PARAMETER,
            Box::new(|sh| {
                sh.random = HRR_RANDOM;
                sh.extensions.retain(|e| e.typ == ext::SUPPORTED_VERSIONS);
            }),
        ),
        (
            "retry for the group already sent",
            alert::ILLEGAL_PARAMETER,
            Box::new(|sh| {
                sh.random = HRR_RANDOM;
                sh.extensions.retain(|e| e.typ == ext::SUPPORTED_VERSIONS);
                sh.extensions.push(Extension {
                    typ: ext::KEY_SHARE,
                    data: group::X25519.to_be_bytes().to_vec(),
                });
            }),
        ),
    ];
    for (what, want, edit) in cases {
        let e = tamper_server_hello(edit);
        assert_eq!(alert_of(&e), want, "{what}: {e}");
    }
}

#[test]
fn server_refuses_a_broken_client_hello() {
    use super::msgs::{ext, group, Extension};
    let cases: Vec<Case<super::msgs::ClientHello>> = vec![
        (
            "compression",
            alert::ILLEGAL_PARAMETER,
            Box::new(|ch| ch.compression = vec![1, 0]),
        ),
        (
            "no TLS 1.3",
            alert::PROTOCOL_VERSION,
            Box::new(|ch| ch.extensions.retain(|e| e.typ != ext::SUPPORTED_VERSIONS)),
        ),
        (
            "no common suite",
            alert::HANDSHAKE_FAILURE,
            Box::new(|ch| ch.cipher_suites = vec![0x00ff]),
        ),
        (
            "no signature_algorithms",
            alert::MISSING_EXTENSION,
            Box::new(|ch| ch.extensions.retain(|e| e.typ != ext::SIGNATURE_ALGORITHMS)),
        ),
        (
            "share outside supported_groups",
            alert::ILLEGAL_PARAMETER,
            Box::new(|ch| {
                for e in ch.extensions.iter_mut() {
                    if e.typ == ext::SUPPORTED_GROUPS {
                        e.data = vec![0, 2, 0, group::SECP256R1 as u8];
                    }
                }
            }),
        ),
        (
            "pre_shared_key not last",
            alert::ILLEGAL_PARAMETER,
            Box::new(|ch| {
                // Well formed, so that only its position is wrong.
                let psks = super::msgs::OfferedPsks {
                    identities: vec![super::msgs::PskIdentity {
                        identity: vec![1; 40],
                        obfuscated_age: 0,
                    }],
                    binders: vec![vec![0; 32]],
                };
                ch.extensions.insert(
                    0,
                    Extension {
                        typ: ext::PRE_SHARED_KEY,
                        data: super::msgs::write_offered_psks(&psks),
                    },
                )
            }),
        ),
        (
            "no common group",
            alert::HANDSHAKE_FAILURE,
            Box::new(|ch| {
                for e in ch.extensions.iter_mut() {
                    // secp521r1, which is not built.
                    if e.typ == ext::SUPPORTED_GROUPS {
                        e.data = vec![0, 2, 0, 0x19];
                    }
                    if e.typ == ext::KEY_SHARE {
                        e.data = vec![0, 0];
                    }
                }
            }),
        ),
    ];
    for (what, want, edit) in cases {
        let e = tamper_client_hello(edit);
        assert_eq!(alert_of(&e), want, "{what}: {e}");
    }
}

#[test]
fn change_cipher_spec_after_the_handshake_is_refused() {
    let p = pair();
    let (_c, mut s) = connect(p.client, p.server);
    let e = s.read_tls(&[20, 3, 3, 0, 1, 1]).unwrap_err();
    assert_eq!(alert_of(&e), alert::UNEXPECTED_MESSAGE);
}

#[test]
fn records_without_content_are_limited() {
    let p = pair();
    let mut c = ClientConnection::new(Arc::new(p.client), "example.test").unwrap();
    let mut s = ServerConnection::new(Arc::new(p.server));
    s.read_tls(&c.take_tls()).unwrap();
    let mut flood = Vec::new();
    for _ in 0..33 {
        flood.extend_from_slice(&[20, 3, 3, 0, 1, 1]);
    }
    let e = s.read_tls(&flood).unwrap_err();
    assert_eq!(alert_of(&e), alert::UNEXPECTED_MESSAGE);
}

#[test]
fn a_wrong_binder_fails_the_handshake() {
    use super::msgs::{ext, hs, ClientHello, Handshake};
    let p = pair();
    let client = Arc::new(p.client);
    let server = Arc::new(p.server);
    let mut c = ClientConnection::new(client.clone(), "example.test").unwrap();
    let mut s = ServerConnection::new(server.clone());
    pump(&mut c, &mut s, usize::MAX).unwrap();

    let mut c = ClientConnection::new(client, "example.test").unwrap();
    let wire = c.take_tls();
    let mut ch = ClientHello::parse(&wire[9..]).unwrap();
    let psk = ch.extensions.last_mut().unwrap();
    assert_eq!(psk.typ, ext::PRE_SHARED_KEY);
    *psk.data.last_mut().unwrap() ^= 1;
    let body = Handshake::new(hs::CLIENT_HELLO, ch.encode().body).encode();
    let mut s = ServerConnection::new(server);
    let e = s.read_tls(&record(22, &body)).unwrap_err();
    assert_eq!(alert_of(&e), alert::DECRYPT_ERROR);
}

#[test]
fn a_requested_key_update_is_answered() {
    let p = pair();
    let (mut c, mut s) = connect(p.client, p.server);
    let before = s.core.write_secret_for_test();
    c.update_keys().unwrap();
    pump(&mut c, &mut s, usize::MAX).unwrap();
    assert_ne!(s.core.write_secret_for_test(), before);
    s.write(b"new key").unwrap();
    pump(&mut c, &mut s, usize::MAX).unwrap();
    assert_eq!(c.take_plaintext(), b"new key");
}

#[test]
fn hello_retry_request_to_a_group_the_server_prefers() {
    use super::msgs::group;
    let mut p = pair();
    p.server.groups = vec![group::SECP256R1];
    let (mut c, mut s) = connect(p.client, p.server);
    assert!(!c.is_handshaking());
    c.write(b"after retry").unwrap();
    pump(&mut c, &mut s, usize::MAX).unwrap();
    assert_eq!(s.take_plaintext(), b"after retry");
}

#[test]
fn every_group_and_suite() {
    use super::msgs::group;
    use super::suites::ALL_TLS13;
    for g in [
        group::X25519MLKEM768,
        group::X25519,
        group::SECP256R1,
        group::SECP384R1,
    ] {
        for suite in ALL_TLS13 {
            let mut p = pair();
            p.client.groups = vec![g];
            p.client.suites = vec![suite];
            let (mut c, mut s) = connect(p.client, p.server);
            assert_eq!(c.cipher_suite(), Some(suite.id));
            assert_eq!(c.key_exchange_group(), Some(g));
            s.write(b"x").unwrap();
            pump(&mut c, &mut s, usize::MAX).unwrap();
            assert_eq!(c.take_plaintext(), b"x");
        }
    }
}

#[test]
fn the_hybrid_by_default_and_x25519_as_its_fallback() {
    use super::msgs::{group, ServerHello, HRR_RANDOM};
    let p = pair();
    let (c, s) = connect(p.client, p.server);
    assert_eq!(c.key_exchange_group(), Some(group::X25519MLKEM768));
    assert_eq!(s.key_exchange_group(), Some(group::X25519MLKEM768));

    // A server without ML-KEM takes the X25519 share sent along with the
    // hybrid one, without a HelloRetryRequest.
    let mut p = pair();
    p.server.groups = vec![group::SECP256R1, group::X25519];
    let mut c = ClientConnection::new(Arc::new(p.client), "example.test").unwrap();
    let mut s = ServerConnection::new(Arc::new(p.server));
    s.read_tls(&c.take_tls()).unwrap();
    let flight = s.take_tls();
    let len = u32::from_be_bytes([0, flight[6], flight[7], flight[8]]) as usize;
    assert_ne!(
        ServerHello::parse(&flight[9..9 + len]).unwrap().random,
        HRR_RANDOM
    );
    c.read_tls(&flight).unwrap();
    pump(&mut c, &mut s, usize::MAX).unwrap();
    assert!(!c.is_handshaking());
    assert_eq!(c.key_exchange_group(), Some(group::X25519));
}

#[test]
fn broken_hybrid_shares_are_refused() {
    use super::msgs::{
        ext, group, read_client_key_shares, read_server_key_share, write_client_key_shares,
        write_server_key_share,
    };
    let edit_share = |f: fn(&mut Vec<u8>)| {
        move |ch: &mut super::msgs::ClientHello| {
            for e in ch.extensions.iter_mut() {
                if e.typ == ext::KEY_SHARE {
                    let mut shares = read_client_key_shares(&e.data).unwrap();
                    assert_eq!(shares[0].group, group::X25519MLKEM768);
                    f(&mut shares[0].key);
                    e.data = write_client_key_shares(&shares);
                }
            }
        }
    };
    type Case = (&'static str, fn(&mut Vec<u8>));
    let cases: [Case; 3] = [
        ("one byte short", |k| {
            k.pop();
        }),
        ("one byte long", |k| k.push(0)),
        // The first coefficient of the ML-KEM key set to 4095, above q:
        // the modulus check of FIPS 203 7.2.
        ("a coefficient not reduced", |k| {
            k[0] = 0xff;
            k[1] |= 0x0f;
        }),
    ];
    for (what, f) in cases {
        let e = tamper_client_hello(edit_share(f));
        assert_eq!(alert_of(&e), alert::ILLEGAL_PARAMETER, "{what}");
    }
    let e = tamper_server_hello(|sh| {
        for e in sh.extensions.iter_mut() {
            if e.typ == ext::KEY_SHARE {
                let mut share = read_server_key_share(&e.data).unwrap();
                share.key.pop();
                e.data = write_server_key_share(&share);
            }
        }
    });
    assert_eq!(alert_of(&e), alert::ILLEGAL_PARAMETER);
}

#[test]
fn groups_can_be_chosen_among_the_supported_ones() {
    use super::msgs::group;
    let mut p = pair();
    assert!(p.client.set_groups(&[0x0019]).is_err());
    assert!(p.client.set_groups(&[]).is_err());
    assert!(p.server.set_groups(&[group::X25519, 0x0100]).is_err());
    p.client
        .set_groups(&[group::SECP384R1, group::SECP384R1])
        .unwrap();
    assert_eq!(p.client.groups, vec![group::SECP384R1]);
    let (c, _) = connect(p.client, p.server);
    assert_eq!(c.key_exchange_group(), Some(group::SECP384R1));
}
