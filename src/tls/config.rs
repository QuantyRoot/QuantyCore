//! Configuration of clients and servers. Safe by default: TLS 1.3 only,
//! certificates always verified, and no setting that weakens either.

use super::auth::{PeerVerifier, Signer};
use super::crypto::aead::Aead;
use super::crypto::chacha20poly1305::ChaCha20Poly1305;
use super::crypto::ct::Secret;
use super::crypto::rand;
use super::kx;
use super::suites::{self, Suite};
use super::x509::{PrivateKey, RootStore, Usage, Verifier};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

/// A resumption ticket a client holds for one server.
#[derive(Clone)]
pub(crate) struct StoredTicket {
    pub suite: Suite,
    pub ticket: Vec<u8>,
    pub psk: Secret,
    pub age_add: u32,
    pub received: SystemTime,
    pub lifetime: Duration,
    pub alpn: Option<Vec<u8>>,
}

/// Tickets per server name. Each is used once (RFC 8446 C.4) and the
/// oldest are dropped first.
#[derive(Default)]
pub(crate) struct TicketCache {
    by_name: Mutex<HashMap<String, Vec<StoredTicket>>>,
}

const TICKETS_PER_SERVER: usize = 4;
const SERVERS_CACHED: usize = 256;

impl TicketCache {
    pub(crate) fn put(&self, name: &str, t: StoredTicket) {
        let mut m = self.by_name.lock().unwrap_or_else(|e| e.into_inner());
        if !m.contains_key(name) && m.len() >= SERVERS_CACHED {
            if let Some(k) = m.keys().next().cloned() {
                m.remove(&k);
            }
        }
        let v = m.entry(name.to_string()).or_default();
        v.push(t);
        if v.len() > TICKETS_PER_SERVER {
            v.remove(0);
        }
    }

    pub(crate) fn take(&self, name: &str) -> Option<StoredTicket> {
        let mut m = self.by_name.lock().unwrap_or_else(|e| e.into_inner());
        let v = m.get_mut(name)?;
        let now = SystemTime::now();
        v.retain(|t| {
            now.duration_since(t.received)
                .is_ok_and(|age| age < t.lifetime)
        });
        v.pop()
    }
}

/// A chain to present when a server asks, and the key that signs for it.
pub(crate) type ClientCertificate = (Vec<Vec<u8>>, Arc<dyn Signer>);

pub struct ClientConfig {
    pub(crate) suites: Vec<Suite>,
    pub(crate) groups: Vec<u16>,
    pub(crate) alpn: Vec<Vec<u8>>,
    pub(crate) verifier: Arc<dyn PeerVerifier>,
    pub(crate) client_cert: Option<ClientCertificate>,
    pub(crate) tickets: Option<Arc<TicketCache>>,
}

impl ClientConfig {
    /// A client that trusts the roots in `roots`, for example
    /// `RootStore::system()`. Every server certificate is validated
    /// against them and against the name passed to the connection.
    pub fn new(roots: RootStore) -> ClientConfig {
        ClientConfig::with_verifier(Arc::new(Verifier {
            roots: Arc::new(roots),
            usage: Usage::Server,
        }))
    }

    /// Presents `chain` (leaf first) and signs with `key` when a server
    /// asks for a client certificate.
    pub fn set_client_certificate(&mut self, chain: Vec<Vec<u8>>, key: PrivateKey) {
        self.client_cert = Some((chain, Arc::new(key)));
    }

    pub(crate) fn with_verifier(verifier: Arc<dyn PeerVerifier>) -> ClientConfig {
        ClientConfig {
            suites: suites::ALL_TLS13.to_vec(),
            groups: kx::SUPPORTED_GROUPS.to_vec(),
            alpn: Vec::new(),
            verifier,
            client_cert: None,
            tickets: Some(Arc::new(TicketCache::default())),
        }
    }

    /// Protocols for ALPN, most preferred first. HTTP/2 is `b"h2"`.
    pub fn set_alpn(&mut self, protocols: &[&[u8]]) {
        self.alpn = protocols.iter().map(|p| p.to_vec()).collect();
    }

    /// Turns session resumption off. Every connection then runs a full
    /// handshake with a fresh key exchange.
    pub fn disable_resumption(&mut self) {
        self.tickets = None;
    }

    #[cfg(test)]
    pub(crate) fn set_client_signer(&mut self, chain: Vec<Vec<u8>>, key: Arc<dyn Signer>) {
        self.client_cert = Some((chain, key));
    }
}

/// Whether and how a server asks for client certificates.
pub(crate) enum ClientAuth {
    None,
    Required(Arc<dyn PeerVerifier>),
}

/// The key that seals session tickets. Tickets are the whole session
/// state, encrypted and authenticated, so the server keeps nothing per
/// client. The key lives in memory only: a restart invalidates every
/// ticket, which costs one full handshake per client and nothing else.
pub(crate) struct TicketKey {
    pub(crate) cipher: ChaCha20Poly1305,
}

impl TicketKey {
    pub(crate) fn generate() -> std::io::Result<TicketKey> {
        let mut k = Secret::zeroed(32);
        rand::fill(k.expose_mut())?;
        Ok(TicketKey {
            cipher: ChaCha20Poly1305::new(k.expose()),
        })
    }
}

pub struct ServerConfig {
    pub(crate) suites: Vec<Suite>,
    pub(crate) groups: Vec<u16>,
    pub(crate) alpn: Vec<Vec<u8>>,
    pub(crate) chain: Vec<Vec<u8>>,
    pub(crate) signer: Arc<dyn Signer>,
    pub(crate) client_auth: ClientAuth,
    pub(crate) tickets: Option<TicketKey>,
    pub(crate) ticket_lifetime: Duration,
    pub(crate) tickets_per_handshake: usize,
}

impl ServerConfig {
    /// A server presenting `chain` (leaf first) and signing with `key`.
    pub fn new(chain: Vec<Vec<u8>>, key: PrivateKey) -> std::io::Result<ServerConfig> {
        ServerConfig::with_signer(chain, Arc::new(key))
    }

    /// Requires every client to present a certificate that chains to
    /// `roots` and is valid for client authentication.
    pub fn require_client_certificates(&mut self, roots: RootStore) {
        self.client_auth = ClientAuth::Required(Arc::new(Verifier {
            roots: Arc::new(roots),
            usage: Usage::Client,
        }));
    }

    /// ChaCha20-Poly1305 comes first because it is the faster cipher here
    /// (ADR-021).
    pub(crate) fn with_signer(
        chain: Vec<Vec<u8>>,
        signer: Arc<dyn Signer>,
    ) -> std::io::Result<ServerConfig> {
        Ok(ServerConfig {
            suites: vec![
                suites::TLS_CHACHA20_POLY1305_SHA256,
                suites::TLS_AES_128_GCM_SHA256,
                suites::TLS_AES_256_GCM_SHA384,
            ],
            groups: kx::SUPPORTED_GROUPS.to_vec(),
            alpn: Vec::new(),
            chain,
            signer,
            client_auth: ClientAuth::None,
            tickets: Some(TicketKey::generate()?),
            ticket_lifetime: Duration::from_secs(24 * 3600),
            tickets_per_handshake: 2,
        })
    }

    /// Protocols for ALPN, most preferred first. A client that offers
    /// ALPN and none of these is refused with no_application_protocol.
    pub fn set_alpn(&mut self, protocols: &[&[u8]]) {
        self.alpn = protocols.iter().map(|p| p.to_vec()).collect();
    }

    pub fn disable_resumption(&mut self) {
        self.tickets = None;
    }

    #[cfg(test)]
    pub(crate) fn require_client_verifier(&mut self, verifier: Arc<dyn PeerVerifier>) {
        self.client_auth = ClientAuth::Required(verifier);
    }
}
