//! A seed driven fuzzer for everything that parses input from a peer:
//! the record layer and the handshake (through whole connections), the
//! handshake messages and extensions, DER, X.509, PEM and private keys.
//!
//! Inputs start from real ones (a recorded handshake in both directions,
//! issued certificates) and are mutated: bits flipped, bytes set to
//! boundary values, ranges deleted, duplicated or spliced in from another
//! input, length fields changed. The property is that nothing panics,
//! loops or allocates without bound; errors are expected.
//!
//! Every case is derived from `QUANTY_FUZZ_SEED` (default 1) and its
//! iteration number, so a failure prints both and
//! `QUANTY_FUZZ_SEED=s QUANTY_FUZZ_FROM=i QUANTY_FUZZ_ITERS=1` replays it.
//! The default run is short; CI runs a long one.

// The corpus is built from fresh keys and handshakes, which need the
// operating system's randomness (ADR-040).
#![cfg(unix)]

use quantycore::tls::msgs;
use quantycore::tls::x509::build::{issue, Issuer, Params, SanEntry};
use quantycore::tls::x509::csr::{request, CertificateRequest};
use quantycore::tls::x509::{pem, verify_chain, Certificate, PrivateKey, RootStore, Usage};
use quantycore::tls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Arc;

/// splitmix64: small, fast, and the same everywhere.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

fn env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

/// One to eight mutations of `input`, some splicing from `other`.
fn mutate(rng: &mut Rng, input: &[u8], other: &[u8]) -> Vec<u8> {
    let mut v = input.to_vec();
    for _ in 0..1 + rng.below(8) {
        let len = v.len();
        match rng.below(8) {
            0 if len > 0 => {
                let i = rng.below(len);
                v[i] ^= 1 << rng.below(8);
            }
            1 if len > 0 => {
                let i = rng.below(len);
                v[i] = [0, 0xff, 0x7f, 0x80, 1, 0xfe][rng.below(6)];
            }
            2 if len > 0 => {
                let a = rng.below(len);
                let b = (a + 1 + rng.below(16)).min(len);
                v.drain(a..b);
            }
            3 if len > 0 => {
                let a = rng.below(len);
                let b = (a + 1 + rng.below(32)).min(len);
                let chunk = v[a..b].to_vec();
                let at = rng.below(len);
                v.splice(at..at, chunk);
            }
            4 if !other.is_empty() => {
                let a = rng.below(other.len());
                let b = (a + 1 + rng.below(64)).min(other.len());
                let at = rng.below(len + 1);
                v.splice(at..at, other[a..b].iter().copied());
            }
            // A two byte big endian length somewhere, set to a boundary.
            5 if len > 2 => {
                let i = rng.below(len - 1);
                let n: u16 = [0, 1, 0xffff, 0x8000, 0x4000, 0x4100][rng.below(6)];
                v[i..i + 2].copy_from_slice(&n.to_be_bytes());
            }
            6 if len > 0 => v.truncate(rng.below(len)),
            _ => {
                let at = rng.below(len + 1);
                let n = rng.below(8);
                let bytes: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
                v.splice(at..at, bytes);
            }
        }
    }
    v
}

/// Finds a length prefix of one, two or three bytes that matches the
/// rest of the input exactly, mutates what follows it and rewrites the
/// prefix to the new length. TLS nests such vectors everywhere, and plain
/// byte mutations almost never keep a prefix and its content consistent.
fn mutate_with_length(rng: &mut Rng, input: &[u8]) -> Vec<u8> {
    let mut spots = Vec::new();
    for w in 1..=3usize {
        for at in 0..input.len().saturating_sub(w) {
            let v = input[at..at + w]
                .iter()
                .fold(0usize, |a, &b| (a << 8) | b as usize);
            if v > 0 && v == input.len() - at - w {
                spots.push((at, w));
            }
        }
    }
    if spots.is_empty() {
        return mutate(rng, input, &[]);
    }
    let (at, w) = spots[rng.below(spots.len())];
    let tail = mutate(rng, &input[at + w..], &[]);
    let n = tail.len().min((1 << (8 * w)) - 1);
    let mut out = input[..at].to_vec();
    out.extend_from_slice(&(n as u32).to_be_bytes()[4 - w..]);
    out.extend_from_slice(&tail[..n]);
    out
}

/// Mutates inside one extension of the first handshake message of a
/// flight and re-encodes it with correct lengths, so that the mutation
/// reaches the code that interprets the extension instead of failing at
/// the framing. The rest of the flight is kept.
fn mutate_extension(rng: &mut Rng, flight: &[u8], client_hello: bool) -> Vec<u8> {
    let len = u16::from_be_bytes([flight[3], flight[4]]) as usize;
    let (first, rest) = flight.split_at(5 + len);
    // A TLS 1.2 server sends its whole flight in one record; the
    // messages after the first stay as they are.
    let msg_len = u32::from_be_bytes([0, first[6], first[7], first[8]]) as usize;
    let (body, after) = first[9..].split_at(msg_len);
    let encoded = if client_hello {
        let mut m = msgs::ClientHello::parse(body).unwrap();
        let i = rng.below(m.extensions.len());
        m.extensions[i].data = mutate_with_length(rng, &m.extensions[i].data);
        m.encode().encode()
    } else {
        let mut m = msgs::ServerHello::parse(body).unwrap();
        let i = rng.below(m.extensions.len());
        m.extensions[i].data = mutate_with_length(rng, &m.extensions[i].data);
        m.encode().encode()
    };
    let n = encoded.len() + after.len();
    let mut out = vec![22, 3, 3, (n >> 8) as u8, n as u8];
    out.extend(encoded);
    out.extend_from_slice(after);
    out.extend_from_slice(rest);
    out
}

/// Runs `cases` iterations of `target`, each with its own generator, and
/// reports the seed and iteration of the first panic.
fn run(name: &str, cases: u64, mut target: impl FnMut(&mut Rng)) {
    let seed = env("QUANTY_FUZZ_SEED", 1);
    let from = env("QUANTY_FUZZ_FROM", 0);
    let iters = env("QUANTY_FUZZ_ITERS", cases);
    for i in from..from + iters {
        let mut rng = Rng(seed ^ i.wrapping_mul(0xd1342543de82ef95) ^ name.len() as u64);
        if catch_unwind(AssertUnwindSafe(|| target(&mut rng))).is_err() {
            panic!(
                "{name}: panic at QUANTY_FUZZ_SEED={seed} QUANTY_FUZZ_FROM={i} QUANTY_FUZZ_ITERS=1"
            );
        }
    }
}

const NOW: i64 = 1_800_000_000;

struct Corpus {
    certs: Vec<Vec<u8>>,
    root: Vec<u8>,
    keys: Vec<Vec<u8>>,
    request: Vec<u8>,
    client_flight: Vec<u8>,
    server_flight: Vec<u8>,
    client_config: Arc<ClientConfig>,
    server_config: Arc<ServerConfig>,
    server_config_x25519: Arc<ServerConfig>,
}

fn corpus() -> Corpus {
    let root_key = PrivateKey::generate_ec(quantycore::tls::crypto::ec::Curve::P256).unwrap();
    let root = issue(
        &Params::ca("Fuzz Root", NOW - 1000, NOW + 100_000),
        &root_key.public_spki(),
        None,
        &root_key,
    )
    .unwrap();
    let issuer = Issuer::from_certificate(&root, &root_key).unwrap();
    let leaf_key = PrivateKey::generate_ed25519().unwrap();
    let mut p = Params::end_entity(
        "leaf",
        vec![
            SanEntry::Dns("fuzz.test".into()),
            SanEntry::Ip("10.1.2.3".parse().unwrap()),
        ],
        NOW - 1000,
        NOW + 1000,
    );
    p.name_constraints = None;
    let leaf = issue(&p, &leaf_key.public_spki(), Some(&issuer), &root_key).unwrap();
    let mut roots = RootStore::new();
    roots.add_der(&root).unwrap();
    let mut client = ClientConfig::new(roots);
    client.set_alpn(&[b"h2"]);
    let client_config = Arc::new(client);
    let server_config = Arc::new(
        ServerConfig::new(
            vec![leaf.clone()],
            PrivateKey::from_pkcs8(&leaf_key.to_pkcs8()).unwrap(),
        )
        .unwrap(),
    );
    let mut x = ServerConfig::new(
        vec![leaf.clone()],
        PrivateKey::from_pkcs8(&leaf_key.to_pkcs8()).unwrap(),
    )
    .unwrap();
    x.set_groups(&[msgs::group::X25519]).unwrap();
    let server_config_x25519 = Arc::new(x);

    // One handshake recorded in both directions. The certificate is not
    // valid at the real time, so the client stops after the server's
    // flight; both flights are what the fuzzer needs.
    let mut c = ClientConnection::new(client_config.clone(), "fuzz.test").unwrap();
    let mut s = ServerConnection::new(server_config.clone());
    let client_flight = c.take_tls();
    s.read_tls(&client_flight).unwrap();
    let server_flight = s.take_tls();
    Corpus {
        certs: vec![root.clone(), leaf],
        root,
        keys: vec![root_key.to_pkcs8(), leaf_key.to_pkcs8()],
        request: request(
            "fuzz",
            &[
                SanEntry::Dns("fuzz.test".into()),
                SanEntry::Ip("10.1.2.3".parse().unwrap()),
            ],
            &root_key,
        ),
        client_flight,
        server_flight,
        client_config,
        server_config,
        server_config_x25519,
    }
}

#[test]
fn fuzz_der_and_x509() {
    let c = corpus();
    let mut roots = RootStore::new();
    roots.add_der(&c.root).unwrap();
    run("x509", 3000, |rng| {
        let pick = rng.below(c.certs.len());
        let other = &c.certs[1 - pick];
        let input = if rng.below(2) == 0 {
            mutate_with_length(rng, &c.certs[pick])
        } else {
            mutate(rng, &c.certs[pick], other)
        };
        let _ = Certificate::parse(&input);
        let _ = verify_chain(
            &roots,
            &[input.clone(), c.root.clone()],
            None,
            Usage::Server,
            NOW,
        );
        let _ = RootStore::new().add_der(&input);
        let _ = CertificateRequest::parse(&mutate(rng, &c.request, &input));
        let k = rng.below(2);
        let key = mutate(rng, &c.keys[k], &input);
        let _ = PrivateKey::from_pkcs8(&key);
        let text = pem::encode("CERTIFICATE", &input);
        let _ = pem::decode_all(
            &String::from_utf8_lossy(&mutate(rng, text.as_bytes(), b"-----")),
            "CERTIFICATE",
        );
    });
}

#[test]
fn fuzz_handshake_messages() {
    let c = corpus();
    // The handshake messages inside the client's first flight, after the
    // five byte record header.
    let hello = c.client_flight[5..].to_vec();
    run("messages", 5000, |rng| {
        let m = if rng.below(2) == 0 {
            mutate_with_length(rng, &hello[4..])
        } else {
            mutate(rng, &hello[4..], &c.server_flight)
        };
        let _ = msgs::ClientHello::parse(&m);
        let _ = msgs::ServerHello::parse(&m);
        let _ = msgs::Certificate::parse(&m);
        let _ = msgs::CertificateRequest::parse(&m);
        let _ = msgs::CertificateVerify::parse(&m);
        let _ = msgs::NewSessionTicket::parse(&m);
        let _ = msgs::parse_extensions_only(&m);
        let _ = msgs::read_client_key_shares(&m);
        let _ = msgs::read_server_key_share(&m);
        let _ = msgs::read_alpn(&m);
        let _ = msgs::read_server_name(&m);
        let _ = msgs::read_offered_psks(&m);
        let _ = msgs::read_u16_list(&m, 1 + rng.below(2));
    });
}

/// Whole servers fed mutated ClientHellos, record layer included, in
/// pieces of random size.
#[test]
fn fuzz_server_connection() {
    let c = corpus();
    run("server", 3000, |rng| {
        let input = if rng.below(2) == 0 {
            mutate_extension(rng, &c.client_flight, true)
        } else {
            mutate(rng, &c.client_flight, &c.server_flight)
        };
        let mut s = ServerConnection::new(c.server_config.clone());
        let mut rest = &input[..];
        while !rest.is_empty() {
            let n = 1 + rng.below(rest.len());
            if s.read_tls(&rest[..n]).is_err() {
                break;
            }
            rest = &rest[n..];
        }
        let _ = s.take_tls();
    });
}

/// Whole clients, after sending their hello, fed a mutation of the
/// server's answer to that very hello. A flight recorded for another
/// client would fail at the session id echo and never reach anything
/// deeper.
#[test]
fn fuzz_client_connection() {
    let c = corpus();
    run("client", 3000, |rng| {
        let mut cl = ClientConnection::new(c.client_config.clone(), "fuzz.test").unwrap();
        // Every other case the server answers the X25519 share instead of
        // the hybrid one.
        let server = if rng.below(2) == 0 {
            &c.server_config
        } else {
            &c.server_config_x25519
        };
        let mut s = ServerConnection::new(server.clone());
        s.read_tls(&cl.take_tls()).unwrap();
        let flight = s.take_tls();
        let input = if rng.below(2) == 0 {
            mutate_extension(rng, &flight, false)
        } else {
            mutate(rng, &flight, &c.client_flight)
        };
        let mut rest = &input[..];
        while !rest.is_empty() {
            let n = 1 + rng.below(rest.len());
            if cl.read_tls(&rest[..n]).is_err() {
                break;
            }
            rest = &rest[n..];
        }
    });
}

/// A recorded ClientHello offering only TLS 1.2, and a server that
/// accepts 1.2, for the targets below.
fn corpus12(c: &Corpus) -> (Vec<u8>, Arc<ClientConfig>, Arc<ServerConfig>) {
    let mut roots = RootStore::new();
    roots.add_der(&c.root).unwrap();
    let mut client = ClientConfig::new(roots);
    client.enable_tls12();
    let client = Arc::new(client);
    let mut server = ServerConfig::new(
        vec![c.certs[1].clone()],
        PrivateKey::from_pkcs8(&c.keys[1]).unwrap(),
    )
    .unwrap();
    server.enable_tls12();
    let wire = ClientConnection::new(client.clone(), "fuzz.test")
        .unwrap()
        .take_tls();
    let mut ch = msgs::ClientHello::parse(&wire[9..]).unwrap();
    for e in ch.extensions.iter_mut() {
        if e.typ == msgs::ext::SUPPORTED_VERSIONS {
            e.data = vec![2, 3, 3];
        }
    }
    let body = ch.encode().encode();
    let mut flight = vec![22, 3, 1, (body.len() >> 8) as u8, body.len() as u8];
    flight.extend_from_slice(&body);
    (flight, client, Arc::new(server))
}

/// A TLS 1.2 server fed mutated ClientHellos.
#[test]
fn fuzz_server_connection_tls12() {
    let c = corpus();
    let (hello, _, server) = corpus12(&c);
    run("server12", 3000, |rng| {
        let input = if rng.below(2) == 0 {
            mutate_extension(rng, &hello, true)
        } else {
            mutate(rng, &hello, &c.server_flight)
        };
        let mut s = ServerConnection::new(server.clone());
        let mut rest = &input[..];
        while !rest.is_empty() {
            let n = 1 + rng.below(rest.len());
            if s.read_tls(&rest[..n]).is_err() {
                break;
            }
            rest = &rest[n..];
        }
    });
}

/// A client that offers 1.2 fed a mutated 1.2 server flight: the
/// server's answer to a hello that offered only 1.2, with the downgrade
/// marker in its random cleared. As in the 1.3 target the certificate is
/// not valid at the real time, so this covers the ServerHello and the
/// Certificate message.
#[test]
fn fuzz_client_connection_tls12() {
    let c = corpus();
    let (_, client, server) = corpus12(&c);
    run("client12", 3000, |rng| {
        let mut cl = ClientConnection::new(client.clone(), "fuzz.test").unwrap();
        let wire = cl.take_tls();
        let mut ch = msgs::ClientHello::parse(&wire[9..]).unwrap();
        for e in ch.extensions.iter_mut() {
            if e.typ == msgs::ext::SUPPORTED_VERSIONS {
                e.data = vec![2, 3, 3];
            }
        }
        let body = ch.encode().encode();
        let mut hello = vec![22, 3, 1, (body.len() >> 8) as u8, body.len() as u8];
        hello.extend_from_slice(&body);
        let mut s = ServerConnection::new(server.clone());
        s.read_tls(&hello).unwrap();
        let mut flight = s.take_tls();
        // Record header, handshake header, version, then the random.
        flight[5 + 4 + 2 + 24..5 + 4 + 2 + 32].fill(0);
        let input = if rng.below(2) == 0 {
            mutate_extension(rng, &flight, false)
        } else {
            mutate(rng, &flight, &hello)
        };
        let mut rest = &input[..];
        while !rest.is_empty() {
            let n = 1 + rng.below(rest.len());
            if cl.read_tls(&rest[..n]).is_err() {
                break;
            }
            rest = &rest[n..];
        }
    });
}
