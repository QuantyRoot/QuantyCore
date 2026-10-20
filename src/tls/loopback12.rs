//! The TLS 1.2 handshake between two connections of this crate, the
//! server limited to 1.2 so that both sides take the 1.2 path.

#![cfg(test)]

use super::error::{alert, Error};
use super::loopback::{connect, pair, pump, KeyVerifier, Pair};
use super::msgs::{ext, hs, version, ClientHello, Extension, Handshake, ServerHello};
use super::{ClientConnection, ServerConnection};
use crate::tls::crypto::ed25519::SigningKey;
use std::sync::Arc;

fn pair12() -> Pair {
    let mut p = pair();
    p.client.enable_tls12();
    p.server.only_tls12();
    p
}

fn alert_of(e: &Error) -> u8 {
    match e {
        Error::Local { alert, .. } => *alert,
        other => panic!("not a local error: {other:?}"),
    }
}

fn record(typ: u8, body: &[u8]) -> Vec<u8> {
    let mut r = vec![typ, 3, 3, (body.len() >> 8) as u8, body.len() as u8];
    r.extend_from_slice(body);
    r
}

#[test]
fn handshake_data_exporter_and_close() {
    let mut p = pair12();
    p.client.set_alpn(&[b"h2"]);
    p.server.set_alpn(&[b"h2"]);
    let (mut c, mut s) = connect(p.client, p.server);
    assert!(!c.is_handshaking() && !s.is_handshaking());
    assert_eq!(c.protocol_version(), Some(0x0303));
    assert_eq!(s.protocol_version(), Some(0x0303));
    assert_eq!(c.cipher_suite(), Some(0xcca9));
    assert_eq!(c.alpn_protocol(), Some(&b"h2"[..]));
    assert_eq!(s.server_name(), Some("example.test"));
    assert_eq!(c.peer_certificates().unwrap()[0], p.server_key.public_key());

    c.write(b"ping").unwrap();
    s.write(b"pong").unwrap();
    pump(&mut c, &mut s, usize::MAX).unwrap();
    assert_eq!(s.take_plaintext(), b"ping");
    assert_eq!(c.take_plaintext(), b"pong");

    let e = |x: &ClientConnection, ctx: &[u8]| x.export_keying_material(b"EXPORTER-t", ctx, 32);
    let a = e(&c, b"ctx").unwrap();
    assert_eq!(
        a,
        s.export_keying_material(b"EXPORTER-t", b"ctx", 32).unwrap()
    );
    assert_ne!(a, e(&c, b"ctx2").unwrap());
    assert_ne!(a, e(&c, b"").unwrap());

    c.close();
    pump(&mut c, &mut s, usize::MAX).unwrap();
    assert!(s.is_peer_closed());
}

#[test]
fn every_suite_and_group() {
    use super::msgs::group;
    use super::suites::{Auth, ALL_TLS12};
    for g in [group::X25519, group::SECP256R1, group::SECP384R1] {
        for suite in ALL_TLS12.iter().filter(|s| s.auth == Auth::Ecdsa) {
            let mut p = pair12();
            p.client.groups = vec![g];
            p.server.suites12 = vec![*suite];
            let (mut c, mut s) = connect(p.client, p.server);
            assert_eq!(c.cipher_suite(), Some(suite.id));
            s.write(&[7; 20_000]).unwrap();
            c.write(b"y").unwrap();
            pump(&mut c, &mut s, usize::MAX).unwrap();
            assert_eq!(c.take_plaintext(), vec![7; 20_000]);
            assert_eq!(s.take_plaintext(), b"y");
        }
    }
}

#[test]
fn every_byte_on_its_own() {
    let p = pair12();
    let mut c = ClientConnection::new(Arc::new(p.client), "example.test").unwrap();
    let mut s = ServerConnection::new(Arc::new(p.server));
    c.write(&[0x5a; 40_000]).unwrap();
    pump(&mut c, &mut s, 1).unwrap();
    assert_eq!(s.take_plaintext(), vec![0x5a; 40_000]);
    assert_eq!(c.protocol_version(), Some(0x0303));
}

#[test]
fn mutual_authentication() {
    let mut p = pair12();
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

    // Without a certificate the client sends an empty one, and the
    // server refuses it.
    let mut p = pair12();
    p.server.require_client_verifier(Arc::new(KeyVerifier {
        key: cpk,
        name: None,
    }));
    let mut c = ClientConnection::new(Arc::new(p.client), "example.test").unwrap();
    let mut s = ServerConnection::new(Arc::new(p.server));
    let (on_client, e) = pump(&mut c, &mut s, usize::MAX).unwrap_err();
    assert!(!on_client);
    assert_eq!(alert_of(&e), alert::HANDSHAKE_FAILURE);

    // A client key that does not match its certificate fails in
    // CertificateVerify.
    let mut p = pair12();
    p.server.require_client_verifier(Arc::new(KeyVerifier {
        key: cpk,
        name: None,
    }));
    p.client.set_client_signer(
        vec![cpk.to_vec()],
        Arc::new(SigningKey::from_seed(&[10; 32])),
    );
    let mut c = ClientConnection::new(Arc::new(p.client), "example.test").unwrap();
    let mut s = ServerConnection::new(Arc::new(p.server));
    let (on_client, e) = pump(&mut c, &mut s, usize::MAX).unwrap_err();
    assert!(!on_client);
    assert_eq!(alert_of(&e), alert::DECRYPT_ERROR);
}

#[test]
fn a_wrong_server_key_fails_the_key_exchange_signature() {
    let p = pair12();
    let mut server = p.server;
    server.signer = Arc::new(SigningKey::from_seed(&[8; 32]));
    let mut c = ClientConnection::new(Arc::new(p.client), "example.test").unwrap();
    let mut s = ServerConnection::new(Arc::new(server));
    let (on_client, e) = pump(&mut c, &mut s, usize::MAX).unwrap_err();
    assert!(on_client);
    assert_eq!(alert_of(&e), alert::DECRYPT_ERROR);
}

#[test]
fn tls12_is_off_unless_both_sides_enable_it() {
    let mut p = pair();
    p.client.enable_tls12();
    p.server.enable_tls12();
    let (c, _) = connect(p.client, p.server);
    assert_eq!(c.protocol_version(), Some(0x0304));

    // A server that only speaks 1.2 answers a client that was not told
    // to accept it.
    let mut c = ClientConnection::new(Arc::new(pair().client), "example.test").unwrap();
    let p = pair12();
    let mut c12 = ClientConnection::new(Arc::new(p.client), "example.test").unwrap();
    let mut s = ServerConnection::new(Arc::new(p.server));
    s.read_tls(&c12.take_tls()).unwrap();
    let e = c.read_tls(&s.take_tls()).unwrap_err();
    assert_eq!(alert_of(&e), alert::PROTOCOL_VERSION);

    // And the other way: a client that offers only 1.2 to a server that
    // was not told to accept it.
    let mut e = tamper_client_hello(pair(), |ch| set_versions(ch, &[version::TLS12]));
    assert_eq!(alert_of(&e), alert::PROTOCOL_VERSION);
    let mut p = pair();
    p.server.enable_tls12();
    e = tamper_client_hello(p, |ch| set_versions(ch, &[0x0302]));
    assert_eq!(alert_of(&e), alert::PROTOCOL_VERSION);
}

fn set_versions(ch: &mut ClientHello, v: &[u16]) {
    for e in ch.extensions.iter_mut() {
        if e.typ == ext::SUPPORTED_VERSIONS {
            e.data = vec![2 * v.len() as u8];
            for x in v {
                e.data.extend_from_slice(&x.to_be_bytes());
            }
        }
    }
}

/// Sends the client's hello through `edit` to the server and returns
/// the server's error.
fn tamper_client_hello(p: Pair, edit: impl FnOnce(&mut ClientHello)) -> Error {
    let mut c = ClientConnection::new(Arc::new(p.client), "example.test").unwrap();
    let mut s = ServerConnection::new(Arc::new(p.server));
    let wire = c.take_tls();
    let mut ch = ClientHello::parse(&wire[9..]).unwrap();
    edit(&mut ch);
    let body = Handshake::new(hs::CLIENT_HELLO, ch.encode().body).encode();
    s.read_tls(&record(22, &body)).unwrap_err()
}

/// Sends the server's first flight to the client with its ServerHello
/// through `edit`, and returns the client's error.
fn tamper_server_hello(p: Pair, edit: impl FnOnce(&mut ServerHello)) -> Error {
    let mut c = ClientConnection::new(Arc::new(p.client), "example.test").unwrap();
    let mut s = ServerConnection::new(Arc::new(p.server));
    s.read_tls(&c.take_tls()).unwrap();
    let wire = s.take_tls();
    let len = u16::from_be_bytes([wire[3], wire[4]]) as usize;
    let payload = &wire[5..5 + len];
    let sh_len = u32::from_be_bytes([0, payload[1], payload[2], payload[3]]) as usize;
    let mut sh = ServerHello::parse(&payload[4..4 + sh_len]).unwrap();
    edit(&mut sh);
    let mut body = Handshake::new(hs::SERVER_HELLO, sh.encode().body).encode();
    body.extend_from_slice(&payload[4 + sh_len..]);
    c.read_tls(&record(22, &body)).unwrap_err()
}

#[test]
fn a_downgrade_from_tls13_is_detected() {
    // A server that speaks 1.3 but sees a hello offering only 1.2 marks
    // its random; a client that offered 1.3 refuses that.
    let mut p = pair();
    p.client.enable_tls12();
    p.server.enable_tls12();
    let mut c = ClientConnection::new(Arc::new(p.client), "example.test").unwrap();
    let mut s = ServerConnection::new(Arc::new(p.server));
    let wire = c.take_tls();
    let mut ch = ClientHello::parse(&wire[9..]).unwrap();
    set_versions(&mut ch, &[version::TLS12]);
    let body = Handshake::new(hs::CLIENT_HELLO, ch.encode().body).encode();
    s.read_tls(&record(22, &body)).unwrap();
    let e = c.read_tls(&s.take_tls()).unwrap_err();
    assert_eq!(e, Error::illegal("downgrade from TLS 1.3"));

    let mut p = pair12();
    p.server.only_tls12();
    let e = tamper_server_hello(p, |sh| sh.random[24..].copy_from_slice(b"DOWNGRD\x00"));
    assert_eq!(e, Error::illegal("downgrade from TLS 1.3"));
}

#[test]
fn server_refuses_a_broken_client_hello() {
    type Edit = Box<dyn FnOnce(&mut ClientHello)>;
    let remove = |typ: u16| -> Edit { Box::new(move |ch| ch.extensions.retain(|e| e.typ != typ)) };
    let set = |typ: u16, data: Vec<u8>| -> Edit {
        Box::new(move |ch| {
            for e in ch.extensions.iter_mut() {
                if e.typ == typ {
                    e.data = data.clone();
                }
            }
        })
    };
    let cases: Vec<(&str, u8, Edit)> = vec![
        (
            "no extended master secret",
            alert::HANDSHAKE_FAILURE,
            remove(ext::EXTENDED_MASTER_SECRET),
        ),
        (
            "extended master secret with data",
            alert::DECODE_ERROR,
            set(ext::EXTENDED_MASTER_SECRET, vec![0]),
        ),
        (
            "renegotiation info of a renegotiation",
            alert::HANDSHAKE_FAILURE,
            set(ext::RENEGOTIATION_INFO, vec![1, 9]),
        ),
        (
            "no signature algorithms",
            alert::HANDSHAKE_FAILURE,
            remove(ext::SIGNATURE_ALGORITHMS),
        ),
        (
            "only RSA schemes",
            alert::HANDSHAKE_FAILURE,
            set(ext::SIGNATURE_ALGORITHMS, vec![0, 2, 4, 1]),
        ),
        (
            "compressed points only",
            alert::ILLEGAL_PARAMETER,
            set(ext::EC_POINT_FORMATS, vec![1, 1]),
        ),
        (
            "no common group",
            alert::HANDSHAKE_FAILURE,
            set(ext::SUPPORTED_GROUPS, vec![0, 2, 0, 0x19]),
        ),
        (
            "no supported groups",
            alert::HANDSHAKE_FAILURE,
            remove(ext::SUPPORTED_GROUPS),
        ),
        (
            "only RSA suites",
            alert::HANDSHAKE_FAILURE,
            Box::new(|ch| ch.cipher_suites = vec![0xc02f, 0xc030]),
        ),
        (
            "compression only",
            alert::ILLEGAL_PARAMETER,
            Box::new(|ch| ch.compression = vec![1]),
        ),
    ];
    for (what, expected, edit) in cases {
        let e = tamper_client_hello(pair12(), edit);
        assert_eq!(alert_of(&e), expected, "{what}: {e:?}");
    }
}

#[test]
fn client_refuses_a_broken_server_hello() {
    type Edit = Box<dyn FnOnce(&mut ServerHello)>;
    let remove = |typ: u16| -> Edit { Box::new(move |sh| sh.extensions.retain(|e| e.typ != typ)) };
    let add = |typ: u16, data: Vec<u8>| -> Edit {
        Box::new(move |sh| sh.extensions.push(Extension { typ, data }))
    };
    let cases: Vec<(&str, u8, Edit)> = vec![
        (
            "no extended master secret",
            alert::HANDSHAKE_FAILURE,
            remove(ext::EXTENDED_MASTER_SECRET),
        ),
        (
            "renegotiation info with data",
            alert::HANDSHAKE_FAILURE,
            Box::new(|sh| {
                for e in sh.extensions.iter_mut() {
                    if e.typ == ext::RENEGOTIATION_INFO {
                        e.data = vec![1, 0];
                    }
                }
            }),
        ),
        (
            "an extension not offered",
            alert::UNSUPPORTED_EXTENSION,
            add(ext::SESSION_TICKET, vec![]),
        ),
        (
            "a TLS 1.3 extension",
            alert::ILLEGAL_PARAMETER,
            add(ext::KEY_SHARE, vec![0, 0x1d, 0, 0]),
        ),
        (
            "ALPN not offered",
            alert::ILLEGAL_PARAMETER,
            add(ext::ALPN, vec![0, 3, 2, b'h', b'2']),
        ),
        (
            "compressed points only",
            alert::ILLEGAL_PARAMETER,
            Box::new(|sh| {
                for e in sh.extensions.iter_mut() {
                    if e.typ == ext::EC_POINT_FORMATS {
                        e.data = vec![1, 1];
                    }
                }
            }),
        ),
        (
            "a suite not offered",
            alert::ILLEGAL_PARAMETER,
            Box::new(|sh| sh.cipher_suite = 0x009c),
        ),
        (
            "a TLS 1.3 suite",
            alert::ILLEGAL_PARAMETER,
            Box::new(|sh| sh.cipher_suite = 0x1301),
        ),
        (
            "compression",
            alert::ILLEGAL_PARAMETER,
            Box::new(|sh| sh.compression = 1),
        ),
    ];
    // An RSA suite with the Ed25519 certificate that follows.
    let e = tamper_server_hello(pair12(), |sh| sh.cipher_suite = 0xcca8);
    assert_eq!(alert_of(&e), alert::UNSUPPORTED_CERTIFICATE);
    for (what, expected, edit) in cases {
        let e = tamper_server_hello(pair12(), edit);
        assert_eq!(alert_of(&e), expected, "{what}: {e:?}");
    }
}

#[test]
fn a_server_claiming_to_resume_is_refused() {
    let p = pair12();
    let mut c = ClientConnection::new(Arc::new(p.client), "example.test").unwrap();
    let mut s = ServerConnection::new(Arc::new(p.server));
    let hello = c.take_tls();
    let id = ClientHello::parse(&hello[9..]).unwrap().session_id;
    s.read_tls(&hello).unwrap();
    let wire = s.take_tls();
    let len = u16::from_be_bytes([wire[3], wire[4]]) as usize;
    let payload = &wire[5..5 + len];
    let sh_len = u32::from_be_bytes([0, payload[1], payload[2], payload[3]]) as usize;
    let mut sh = ServerHello::parse(&payload[4..4 + sh_len]).unwrap();
    sh.session_id = id;
    let body = Handshake::new(hs::SERVER_HELLO, sh.encode().body).encode();
    let e = c.read_tls(&record(22, &body)).unwrap_err();
    assert_eq!(alert_of(&e), alert::ILLEGAL_PARAMETER);
}

#[test]
fn change_cipher_spec_only_where_the_handshake_expects_it() {
    let p = pair12();
    let mut c = ClientConnection::new(Arc::new(p.client), "example.test").unwrap();
    let mut s = ServerConnection::new(Arc::new(p.server));
    s.read_tls(&c.take_tls()).unwrap();
    // Before ClientKeyExchange there are no keys to change to.
    let e = s.read_tls(&record(20, &[1])).unwrap_err();
    assert_eq!(alert_of(&e), alert::UNEXPECTED_MESSAGE);

    // A change_cipher_spec of the wrong content.
    let p = pair12();
    let mut c = ClientConnection::new(Arc::new(p.client), "example.test").unwrap();
    let mut s = ServerConnection::new(Arc::new(p.server));
    s.read_tls(&c.take_tls()).unwrap();
    c.read_tls(&s.take_tls()).unwrap();
    let flight = c.take_tls();
    // ClientKeyExchange, then change_cipher_spec: replace its byte.
    let cke_len = u16::from_be_bytes([flight[3], flight[4]]) as usize;
    let mut bad = flight.clone();
    assert_eq!(bad[5 + cke_len], 20);
    bad[5 + cke_len + 5] = 2;
    let e = s.read_tls(&bad).unwrap_err();
    assert_eq!(alert_of(&e), alert::UNEXPECTED_MESSAGE);

    // A second change_cipher_spec after the first.
    let p = pair12();
    let mut c = ClientConnection::new(Arc::new(p.client), "example.test").unwrap();
    let mut s = ServerConnection::new(Arc::new(p.server));
    s.read_tls(&c.take_tls()).unwrap();
    c.read_tls(&s.take_tls()).unwrap();
    let flight = c.take_tls();
    let mut twice = flight[..5 + cke_len + 6].to_vec();
    twice.extend_from_slice(&record(20, &[1]));
    let e = s.read_tls(&twice).unwrap_err();
    assert_eq!(alert_of(&e), alert::UNEXPECTED_MESSAGE);
}

#[test]
fn no_key_update_and_no_renegotiation() {
    let p = pair12();
    let (mut c, mut s) = connect(p.client, p.server);
    assert!(c.update_keys().is_err());
    c.core
        .send_hs(&Handshake::new(hs::CLIENT_HELLO, Vec::new()));
    c.core.flush_hs().unwrap();
    let (on_client, e) = pump(&mut c, &mut s, usize::MAX).unwrap_err();
    assert!(!on_client);
    assert_eq!(alert_of(&e), alert::UNEXPECTED_MESSAGE);
}

#[test]
fn a_flipped_bit_is_bad_record_mac() {
    // With GCM the record starts with the explicit nonce; a change there
    // must fail as surely as one in the ciphertext or the tag.
    for suite in [0, 1] {
        for at in [5, 13, usize::MAX] {
            let mut p = pair12();
            p.server.suites12 = vec![super::suites::ALL_TLS12[suite]];
            let (mut c, mut s) = connect(p.client, p.server);
            c.write(b"data").unwrap();
            let mut wire = c.take_tls();
            let i = at.min(wire.len() - 1);
            wire[i] ^= 1;
            let e = s.read_tls(&wire).unwrap_err();
            assert_eq!(
                alert_of(&e),
                alert::BAD_RECORD_MAC,
                "suite {suite} byte {i}"
            );
        }
    }
}
