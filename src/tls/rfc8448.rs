//! The TLS 1.3 handshake checked byte for byte against the example traces
//! of RFC 8448.
//!
//! The RFC is read from the file `QUANTY_RFC8448` points to, so that no
//! transcription can go wrong; CI downloads it, pinned by SHA-256. This
//! lives inside the crate rather than under `tests/` because the client
//! path needs the trace's fixed randomness, which only crate code can
//! supply.

#![cfg(test)]

use super::crypto::hkdf;
use super::crypto::sha2::HashAlg;
use super::crypto::x25519;
use super::key_schedule::{expand_label, finished_verify_data, resumption_psk, KeySchedule};
use super::msgs::*;
use super::record::Protection;
use super::suites;

pub(crate) struct Step {
    pub who: String,
    pub what: String,
    pub fields: Vec<(String, Option<Vec<u8>>)>,
}

impl Step {
    pub fn get(&self, name: &str) -> &[u8] {
        self.fields
            .iter()
            .find(|(n, _)| n == name)
            .and_then(|(_, v)| v.as_deref())
            .unwrap_or_else(|| panic!("{} {}: no field {name}", self.who, self.what))
    }
}

fn hex_words(s: &str) -> Option<Vec<u8>> {
    s.split_whitespace()
        .map(|w| {
            (w.len() == 2)
                .then(|| u8::from_str_radix(w, 16).ok())
                .flatten()
        })
        .collect()
}

/// The steps of each numbered section, keyed by the section number.
pub(crate) fn parse(text: &str) -> Vec<(u32, Vec<Step>)> {
    let mut sections: Vec<(u32, Vec<Step>)> = Vec::new();
    let all: Vec<&str> = text
        .lines()
        .filter(|l| {
            !l.starts_with("RFC 8448 ") && !l.starts_with("Thomson ") && !l.starts_with('\u{c}')
        })
        .collect();
    // A page break leaves blank lines in the middle of a hex field. They
    // are dropped when the next text is a continuation of that field,
    // which is indented by nine spaces, and kept otherwise because blank
    // lines also end fields and steps.
    let kept: Vec<&str> = all
        .iter()
        .enumerate()
        .filter(|(i, l)| {
            !l.trim().is_empty()
                || !all[i + 1..]
                    .iter()
                    .find(|n| !n.trim().is_empty())
                    .is_some_and(|n| n.starts_with("         "))
        })
        .map(|(_, l)| *l)
        .collect();
    let mut lines = kept.into_iter().peekable();
    while let Some(line) = lines.next() {
        if let Some((num, _)) = line.split_once(".  ") {
            if let Ok(n) = num.parse::<u32>() {
                if !line.starts_with(' ') {
                    sections.push((n, Vec::new()));
                    continue;
                }
            }
        }
        let Some(rest) = line.strip_prefix("   {") else {
            if let Some(field) = line.strip_prefix("      ") {
                if field.starts_with(' ') {
                    continue;
                }
                let Some((name, value)) = field.split_once(":  ") else {
                    continue;
                };
                let name = name.split(" (").next().unwrap().to_string();
                let mut hex = value.to_string();
                while let Some(next) = lines.peek() {
                    if next.starts_with("         ") && !next.trim().is_empty() {
                        hex.push(' ');
                        hex.push_str(next.trim());
                        lines.next();
                    } else {
                        break;
                    }
                }
                if let Some((_, steps)) = sections.last_mut() {
                    if let Some(step) = steps.last_mut() {
                        step.fields.push((name, hex_words(&hex)));
                    }
                }
            }
            continue;
        };
        let (who, what) = rest.split_once("}  ").unwrap();
        let mut what = what.to_string();
        while let Some(next) = lines.peek() {
            if next.starts_with("      ") && !next.trim().is_empty() && !next.contains(":  ") {
                what.push(' ');
                what.push_str(next.trim());
                lines.next();
            } else {
                break;
            }
        }
        if let Some((_, steps)) = sections.last_mut() {
            steps.push(Step {
                who: who.to_string(),
                what,
                fields: Vec::new(),
            });
        }
    }
    sections
}

pub(crate) fn load() -> Option<Vec<(u32, Vec<Step>)>> {
    let path = match std::env::var("QUANTY_RFC8448") {
        Ok(p) => p,
        Err(_) if std::env::var_os("QUANTY_VECTORS_REQUIRED").is_some() => {
            panic!("QUANTY_RFC8448 not set but QUANTY_VECTORS_REQUIRED is")
        }
        Err(_) => {
            eprintln!("QUANTY_RFC8448 not set, traces not run");
            return None;
        }
    };
    Some(parse(
        &std::fs::read_to_string(path).expect("RFC 8448 text"),
    ))
}

pub(crate) fn section(all: &[(u32, Vec<Step>)], n: u32) -> &[Step] {
    &all.iter().find(|(m, _)| *m == n).expect("section").1
}

/// The first step by `who` whose description starts with `what`, after
/// skipping `skip` earlier matches.
pub(crate) fn step<'a>(steps: &'a [Step], who: &str, what: &str, skip: usize) -> &'a Step {
    steps
        .iter()
        .filter(|s| s.who == who && s.what.starts_with(what))
        .nth(skip)
        .unwrap_or_else(|| panic!("no step {{{who}}} {what} #{skip}"))
}

/// Every HKDF step in every trace: Extract from salt and IKM, and Expand
/// with the label as this crate encodes it. That pins the label encoding
/// for every label the traces use, including those of 0-RTT and PSK
/// binders, independent of the handshake code.
#[test]
fn every_hkdf_step_in_the_traces() {
    let Some(all) = load() else {
        return;
    };
    let (mut extracts, mut expands) = (0, 0);
    for (n, steps) in &all {
        let hash = if *n == 4 || *n == 3 || *n == 5 || *n == 6 || *n == 7 {
            HashAlg::Sha256
        } else {
            continue;
        };
        for s in steps {
            let f = |k: &str| {
                s.fields
                    .iter()
                    .find(|(n, _)| n == k)
                    .map(|(_, v)| v.clone())
            };
            if s.what.starts_with("extract secret") {
                if let (Some(Some(ikm)), Some(Some(secret))) = (f("IKM"), f("secret")) {
                    let salt = f("salt").flatten().unwrap_or_default();
                    assert_eq!(
                        hkdf::extract(hash, &salt, &ikm).expose(),
                        &secret[..],
                        "{n} {}",
                        s.what
                    );
                    extracts += 1;
                }
            }
            if let (Some(Some(prk)), Some(Some(info)), Some(Some(out))) =
                (f("PRK"), f("info"), f("expanded"))
            {
                assert_eq!(
                    hkdf::expand(hash, &prk, &info, out.len()).unwrap().expose(),
                    &out[..],
                    "{n} {}",
                    s.what
                );
                // The label is the quoted part of the description.
                if let Some(label) = s
                    .what
                    .split('"')
                    .nth(1)
                    .and_then(|l| l.strip_prefix("tls13 "))
                {
                    let ctx = f("hash").flatten().unwrap_or_default();
                    let ours = expand_label(hash, &prk, label.as_bytes(), &ctx, out.len());
                    assert_eq!(ours.expose(), &out[..], "label {label} in section {n}");
                }
                expands += 1;
            }
            for (k, v) in [("key", 16), ("iv", 12)] {
                if let (Some(Some(prk)), Some(Some(out))) = (f("PRK"), f(&format!("{k} expanded")))
                {
                    assert_eq!(
                        expand_label(hash, &prk, k.as_bytes(), b"", v).expose(),
                        &out[..]
                    );
                    expands += 1;
                }
            }
        }
    }
    eprintln!("RFC 8448: {extracts} extracts, {expands} expands");
    assert!(extracts >= 15 && expands >= 60, "traces incomplete");
}

/// Parses a handshake message from the trace by its type and checks that
/// encoding the parsed form gives the same bytes back.
fn roundtrip(raw: &[u8]) {
    let body = &raw[4..];
    let back = match raw[0] {
        hs::CLIENT_HELLO => ClientHello::parse(body).unwrap().encode(),
        hs::SERVER_HELLO => ServerHello::parse(body).unwrap().encode(),
        hs::ENCRYPTED_EXTENSIONS => {
            encode_extensions_only(raw[0], &parse_extensions_only(body).unwrap())
        }
        hs::CERTIFICATE_REQUEST => CertificateRequest::parse(body).unwrap().encode(),
        hs::CERTIFICATE => Certificate::parse(body).unwrap().encode(),
        hs::CERTIFICATE_VERIFY => CertificateVerify::parse(body).unwrap().encode(),
        hs::NEW_SESSION_TICKET => NewSessionTicket::parse(body).unwrap().encode(),
        hs::FINISHED => Handshake::new(raw[0], body.to_vec()),
        t => panic!("message type {t} in trace"),
    };
    assert_eq!(
        back.encode(),
        raw,
        "message type {} does not re-encode",
        raw[0]
    );
}

/// Walks one trace in order and recomputes, with this crate's code, every
/// value the trace shows: each message re-encoded from its parsed form,
/// the transcript (including the message_hash substitution after a
/// HelloRetryRequest), every traffic secret, every Finished, the
/// resumption PSK, and every protected record. Returns how many values
/// were compared.
fn walk(t: &[Step]) -> usize {
    let suite = suites::TLS_AES_128_GCM_SHA256;
    let hash = suite.hash;
    let mut transcript: Vec<u8> = Vec::new();
    let mut ks: Option<KeySchedule> = None;
    let mut secrets: Vec<(String, Vec<u8>)> = Vec::new();
    let mut writers: Vec<(String, Protection)> = Vec::new();
    let mut pending_nonce: Vec<u8> = Vec::new();
    let mut checked = 0;
    let th = |m: &[u8]| hash.digest(m);
    let secret = |secrets: &[(String, Vec<u8>)], l: &str| {
        secrets
            .iter()
            .rev()
            .find(|(n, _)| n == l)
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| panic!("secret {l} not derived yet"))
    };
    for s in t {
        let side = if s.who == "client" { "c" } else { "s" };
        if let Some(rest) = s.what.strip_prefix("construct a") {
            let name = rest
                .trim_start_matches('n')
                .trim()
                .split(' ')
                .next()
                .unwrap();
            let raw = s.get(name).to_vec();
            roundtrip(&raw);
            if raw[0] == hs::SERVER_HELLO && raw[6..38] == HRR_RANDOM {
                let mut mh = vec![hs::MESSAGE_HASH, 0, 0, hash.output_len() as u8];
                mh.extend(th(&transcript));
                transcript = mh;
            }
            if raw[0] == hs::NEW_SESSION_TICKET {
                let nonce = NewSessionTicket::parse(&raw[4..]).unwrap().nonce;
                assert_eq!(nonce, pending_nonce, "ticket nonce");
            } else {
                transcript.extend_from_slice(&raw);
            }
            checked += 1;
        } else if s.what.starts_with("extract secret \"early\"") && !s.fields.is_empty() {
            let k = KeySchedule::new(hash, None);
            assert_eq!(k.current(), s.get("secret"));
            ks = Some(k);
            checked += 1;
        } else if s.what.starts_with("extract secret \"handshake\"") && !s.fields.is_empty() {
            let k = ks.as_mut().expect("early secret first");
            k.into_handshake(s.get("IKM"));
            assert_eq!(k.current(), s.get("secret"));
            checked += 1;
        } else if s.what.starts_with("extract secret \"master\"") && !s.fields.is_empty() {
            let k = ks.as_mut().unwrap();
            k.into_master();
            assert_eq!(k.current(), s.get("secret"));
            checked += 1;
        } else if let Some(label) = s.what.strip_prefix("derive secret \"tls13 ") {
            let label = label.split('"').next().unwrap();
            // A step that only says "(same as server)" sits at the other
            // side's point in the trace, where the transcript has moved on.
            if s.fields.is_empty() {
                continue;
            }
            let ours = ks
                .as_ref()
                .unwrap()
                .derive(label.as_bytes(), &th(&transcript));
            assert_eq!(ours.expose(), s.get("expanded"), "{label}");
            checked += 1;
            secrets.push((label.to_string(), ours.expose().to_vec()));
        } else if s.what.starts_with("calculate finished") && !s.fields.is_empty() {
            let base = secret(&secrets, &format!("{side} hs traffic"));
            assert_eq!(
                finished_verify_data(hash, &base, &th(&transcript)),
                s.get("finished"),
                "{} Finished",
                s.who
            );
            checked += 1;
        } else if s.what.starts_with("generate resumption secret") && !s.fields.is_empty() {
            // The ticket nonce is the context of this derivation; the
            // NewSessionTicket that follows must carry the same one.
            let res = secret(&secrets, "res master");
            pending_nonce = s.get("hash").to_vec();
            assert_eq!(
                resumption_psk(hash, &res, &pending_nonce).expose(),
                s.get("expanded")
            );
            checked += 1;
        } else if let Some(kind) = s.what.strip_prefix("derive write traffic keys for ") {
            let label = if kind.starts_with("handshake") {
                format!("{side} hs traffic")
            } else if kind.starts_with("application") {
                format!("{side} ap traffic")
            } else {
                continue;
            };
            let p = Protection::tls13(suite, &secret(&secrets, &label));
            writers.retain(|(w, _)| w != &s.who);
            writers.push((s.who.clone(), p));
        } else if let Some(kind) = s.what.strip_prefix("send ") {
            let payload = s.get("payload").to_vec();
            let complete = s.get("complete record").to_vec();
            if complete[0] != content::APPLICATION_DATA {
                assert_eq!(complete[5..], payload[..], "plaintext record framing");
                continue;
            }
            let typ = match kind.split(' ').next().unwrap() {
                "handshake" => content::HANDSHAKE,
                "application_data" => content::APPLICATION_DATA,
                "alert" => content::ALERT,
                k => panic!("record kind {k}"),
            };
            let w = &mut writers
                .iter_mut()
                .find(|(w, _)| w == &s.who)
                .unwrap_or_else(|| panic!("{} has no keys for {}", s.who, s.what))
                .1;
            let mut out = Vec::new();
            w.seal13(typ, &payload, &mut out).unwrap();
            assert_eq!(out, complete, "{} {}", s.who, s.what);
            checked += 1;
        }
    }
    checked
}

#[test]
fn simple_1rtt_handshake() {
    let Some(all) = load() else {
        return;
    };
    let t = section(&all, 3);
    let n = walk(t);
    eprintln!("section 3: {n} values");
    assert!(n >= 20);

    // The shared secret in the trace is what X25519 gives for the
    // trace's keys.
    let chm = ClientHello::parse(
        &step(t, "client", "construct a ClientHello", 0).get("ClientHello")[4..],
    )
    .unwrap();
    let shares = read_client_key_shares(chm.ext(ext::KEY_SHARE).unwrap()).unwrap();
    let spriv: [u8; 32] = step(t, "server", "create an ephemeral", 0)
        .get("private key")
        .try_into()
        .unwrap();
    let shared = x25519::PrivateKey::from_bytes(&spriv)
        .diffie_hellman(&shares[0].key.clone().try_into().unwrap())
        .unwrap();
    assert_eq!(
        shared.expose(),
        step(t, "server", "extract secret \"handshake\"", 0).get("IKM")
    );
}

#[test]
fn hello_retry_request() {
    let Some(all) = load() else {
        return;
    };
    let n = walk(section(&all, 5));
    eprintln!("section 5: {n} values");
    assert!(n >= 20);
}

#[test]
fn client_authentication() {
    let Some(all) = load() else {
        return;
    };
    let n = walk(section(&all, 6));
    eprintln!("section 6: {n} values");
    assert!(n >= 20);
}

#[test]
fn compatibility_mode() {
    let Some(all) = load() else {
        return;
    };
    let n = walk(section(&all, 7));
    eprintln!("section 7: {n} values");
    assert!(n >= 20);
}

#[test]
fn parser_finds_every_section() {
    let Some(all) = load() else {
        return;
    };
    let numbers: Vec<u32> = all
        .iter()
        .filter(|(_, s)| !s.is_empty())
        .map(|(n, _)| *n)
        .collect();
    assert_eq!(numbers, [3, 4, 5, 6, 7]);
}

/// Stands in for certificate validation in the trace tests: accepts the
/// trace's RSA chain and every signature scheme the trace offers.
struct TraceVerifier;

impl crate::tls::auth::PeerVerifier for TraceVerifier {
    fn verify(
        &self,
        _chain: &[Vec<u8>],
        _name: Option<&str>,
    ) -> Result<crate::tls::auth::PublicKey, crate::tls::Error> {
        Ok(crate::tls::auth::PublicKey::AcceptAny)
    }
    fn schemes(&self) -> Vec<u16> {
        vec![
            0x0403, 0x0503, 0x0603, 0x0203, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601,
        ]
    }
}

/// Signs by returning the signature the trace shows. RSA-PSS is
/// randomized, so the trace's signature cannot be produced again; what is
/// checked is everything around it.
struct TraceSigner {
    scheme: u16,
    signature: Vec<u8>,
}

impl crate::tls::auth::Signer for TraceSigner {
    fn choose_scheme(&self, offered: &[u16]) -> Option<u16> {
        offered.contains(&self.scheme).then_some(self.scheme)
    }
    fn sign(&self, _s: u16, _m: &[u8]) -> Result<Vec<u8>, crate::tls::Error> {
        Ok(self.signature.clone())
    }
}

/// Runs this crate's client from the trace's ClientHello and key share:
/// feeds it every record the server sent, in order, and requires every
/// record the client sends to be the trace's, byte for byte.
fn client_path(t: &[Step]) -> usize {
    use crate::tls::config::ClientConfig;
    use crate::tls::kx::KxSecret;
    use crate::tls::ClientConnection;
    use std::sync::Arc;

    let mut config = ClientConfig::with_verifier(Arc::new(TraceVerifier));
    config.disable_resumption();
    let hellos: Vec<&Step> = t
        .iter()
        .filter(|s| s.who == "client" && s.what.starts_with("construct a ClientHello"))
        .collect();
    let hello = ClientHello::parse(&hellos[0].get("ClientHello")[4..]).unwrap();
    // The client's certificate and signature, when the server asks.
    if let Some(cert) = t
        .iter()
        .find(|s| s.who == "client" && s.what.starts_with("construct a Certificate "))
    {
        let cv = t
            .iter()
            .find(|s| s.who == "client" && s.what.starts_with("construct a CertificateVerify"))
            .unwrap();
        let cv = CertificateVerify::parse(&cv.get("CertificateVerify")[4..]).unwrap();
        let chain = Certificate::parse(&cert.get("Certificate")[4..])
            .unwrap()
            .entries
            .into_iter()
            .map(|e| e.der)
            .collect();
        config.set_client_certificate(
            chain,
            Arc::new(TraceSigner {
                scheme: cv.scheme,
                signature: cv.signature,
            }),
        );
    }
    let key: [u8; 32] = step(t, "client", "create an ephemeral x25519", 0)
        .get("private key")
        .try_into()
        .unwrap();
    let kx = KxSecret::X25519(x25519::PrivateKey::from_bytes(&key));
    let mut c = ClientConnection::from_hello(Arc::new(config), None, hello, kx, None).unwrap();

    let mut checked = 0;
    let mut sent = c.take_tls();
    for s in t.iter().filter(|s| s.what.starts_with("send ")) {
        let complete = s.get("complete record").to_vec();
        if s.who == "server" {
            c.read_tls(&complete)
                .unwrap_or_else(|e| panic!("{}: {e}", s.what));
            sent.extend(c.take_tls());
            continue;
        }
        if s.what.starts_with("send application_data") {
            c.write(s.get("payload")).unwrap();
            sent.extend(c.take_tls());
        } else if s.what.starts_with("send alert") {
            c.close();
            sent.extend(c.take_tls());
        }
        assert!(
            sent.starts_with(&complete),
            "client record for '{}' differs",
            s.what
        );
        sent.drain(..complete.len());
        checked += 1;
    }
    assert!(sent.is_empty(), "client sent more than the trace");
    // The server's application data arrived as plaintext.
    let got = c.take_plaintext();
    let want: Vec<u8> = t
        .iter()
        .filter(|s| s.who == "server" && s.what.starts_with("send application_data"))
        .flat_map(|s| s.get("payload").to_vec())
        .collect();
    assert_eq!(got, want);
    checked
}

#[test]
fn client_follows_the_traces() {
    let Some(all) = load() else {
        return;
    };
    for n in [3, 6, 7] {
        let k = client_path(section(&all, n));
        eprintln!("section {n}: {k} client records");
        assert!(k >= 3, "section {n}");
    }
}

/// The server, given the trace's random and key share, answers the
/// trace's ClientHello with the trace's ServerHello. What follows differs
/// on purpose: the trace's EncryptedExtensions carry extensions this
/// server does not send.
#[test]
fn server_hello_matches_the_trace() {
    use crate::tls::config::ServerConfig;
    use crate::tls::kx::KxSecret;
    use crate::tls::ServerConnection;
    use std::sync::Arc;

    let Some(all) = load() else {
        return;
    };
    let t = section(&all, 3);
    let mut config = ServerConfig::with_signer(
        vec![vec![1]],
        Arc::new(TraceSigner {
            scheme: 0x0804,
            signature: vec![0; 128],
        }),
    )
    .unwrap();
    config.suites = vec![suites::TLS_AES_128_GCM_SHA256];
    let random: [u8; 32] = ServerHello::parse(
        &step(t, "server", "construct a ServerHello", 0).get("ServerHello")[4..],
    )
    .unwrap()
    .random;
    let key: [u8; 32] = step(t, "server", "create an ephemeral x25519", 0)
        .get("private key")
        .try_into()
        .unwrap();
    let mut s = ServerConnection::with_fixed(
        Arc::new(config),
        random,
        KxSecret::X25519(x25519::PrivateKey::from_bytes(&key)),
    );
    s.read_tls(step(t, "client", "send handshake record", 0).get("complete record"))
        .unwrap();
    let out = s.take_tls();
    let sh_record = step(t, "server", "send handshake record", 0).get("complete record");
    assert!(out.starts_with(sh_record));
}

/// A server Finished with one bit changed, re-encrypted under the trace's
/// handshake key so that only the Finished itself is wrong. The client
/// must stop with decrypt_error.
#[test]
fn client_refuses_a_forged_server_finished() {
    use crate::tls::config::ClientConfig;
    use crate::tls::error::{alert, Error};
    use crate::tls::kx::KxSecret;
    use crate::tls::ClientConnection;
    use std::sync::Arc;

    let Some(all) = load() else {
        return;
    };
    let t = section(&all, 3);
    let s_hs = step(t, "server", "derive secret \"tls13 s hs traffic\"", 0).get("expanded");
    let flight = step(t, "server", "send handshake record", 1);
    let mut payload = flight.get("payload").to_vec();
    *payload.last_mut().unwrap() ^= 1;
    let mut forged = Vec::new();
    Protection::tls13(suites::TLS_AES_128_GCM_SHA256, s_hs)
        .seal13(content::HANDSHAKE, &payload, &mut forged)
        .unwrap();

    let mut config = ClientConfig::with_verifier(Arc::new(TraceVerifier));
    config.disable_resumption();
    let hello = ClientHello::parse(
        &step(t, "client", "construct a ClientHello", 0).get("ClientHello")[4..],
    )
    .unwrap();
    let key: [u8; 32] = step(t, "client", "create an ephemeral x25519", 0)
        .get("private key")
        .try_into()
        .unwrap();
    let kx = KxSecret::X25519(x25519::PrivateKey::from_bytes(&key));
    let mut c = ClientConnection::from_hello(Arc::new(config), None, hello, kx, None).unwrap();
    c.read_tls(step(t, "server", "send handshake record", 0).get("complete record"))
        .unwrap();
    let e = c.read_tls(&forged).unwrap_err();
    assert!(
        matches!(
            e,
            Error::Local {
                alert: alert::DECRYPT_ERROR,
                ..
            }
        ),
        "{e}"
    );
}

/// The server, from the trace's ClientHello, derives the trace's client
/// handshake key, because those depend only on the two hellos. Its own
/// EncryptedExtensions differ from the trace's, so the trace's client
/// Finished, which decrypts fine, is over another transcript and must be
/// refused.
#[test]
fn server_refuses_a_finished_over_another_transcript() {
    use crate::tls::config::ServerConfig;
    use crate::tls::error::{alert, Error};
    use crate::tls::kx::KxSecret;
    use crate::tls::ServerConnection;
    use std::sync::Arc;

    let Some(all) = load() else {
        return;
    };
    let t = section(&all, 3);
    let mut config = ServerConfig::with_signer(
        vec![vec![1]],
        Arc::new(TraceSigner {
            scheme: 0x0804,
            signature: vec![0; 128],
        }),
    )
    .unwrap();
    config.suites = vec![suites::TLS_AES_128_GCM_SHA256];
    let random = ServerHello::parse(
        &step(t, "server", "construct a ServerHello", 0).get("ServerHello")[4..],
    )
    .unwrap()
    .random;
    let key: [u8; 32] = step(t, "server", "create an ephemeral x25519", 0)
        .get("private key")
        .try_into()
        .unwrap();
    let mut s = ServerConnection::with_fixed(
        Arc::new(config),
        random,
        KxSecret::X25519(x25519::PrivateKey::from_bytes(&key)),
    );
    s.read_tls(step(t, "client", "send handshake record", 0).get("complete record"))
        .unwrap();
    let e = s
        .read_tls(step(t, "client", "send handshake record", 1).get("complete record"))
        .unwrap_err();
    assert!(
        matches!(
            e,
            Error::Local {
                alert: alert::DECRYPT_ERROR,
                ..
            }
        ),
        "{e}"
    );
}
