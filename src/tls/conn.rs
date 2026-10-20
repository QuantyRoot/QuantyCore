//! The connection: a state machine that takes bytes from the network and
//! gives back bytes for the network, without doing any I/O itself.
//!
//! The caller moves the bytes. `read_tls` hands in whatever arrived,
//! `take_tls` returns what has to be sent, and `write`/`read` carry the
//! application's plaintext. That lets the same code run over a blocking
//! socket (`Stream`), under an event loop, or in a test that wires two
//! connections to each other in memory.

use super::crypto::ct::Secret;
use super::crypto::sha2::{AnyHash, HashAlg};
use super::error::{alert, Error};
use super::key_schedule::prf12;
use super::key_schedule::{export, next_traffic_secret};
use super::msgs::{content, hs, Handshake};
use super::record::{Deframer, HandshakeJoiner, Protection, MAX_CIPHERTEXT_13, MAX_PLAINTEXT};
use super::suites::{Suite, Suite12};

/// One state of a handshake. Each takes the next message and returns the
/// state after it, so a message can only be handled by a state that
/// expects it.
pub(crate) trait State: Send {
    fn handle(
        self: Box<Self>,
        core: &mut Core,
        msg: Handshake,
        raw: Vec<u8>,
    ) -> Result<Box<dyn State>, Error>;

    fn is_connected(&self) -> bool {
        false
    }
}

/// The running transcript hash. Before the cipher suite, and with it the
/// hash, is known, the messages are kept as bytes.
pub(crate) struct Transcript {
    hash: Option<AnyHash>,
    buf: Vec<u8>,
}

impl Transcript {
    pub(crate) fn new() -> Transcript {
        Transcript {
            hash: None,
            buf: Vec::new(),
        }
    }

    pub(crate) fn add(&mut self, raw: &[u8]) {
        match &mut self.hash {
            Some(h) => h.update(raw),
            None => self.buf.extend_from_slice(raw),
        }
    }

    pub(crate) fn start_hash(&mut self, alg: HashAlg) {
        if self.hash.is_none() {
            let mut h = alg.new_hasher();
            h.update(&self.buf);
            self.buf.clear();
            self.hash = Some(h);
        }
    }

    /// The messages buffered before a hash was chosen. TLS 1.2 keeps the
    /// whole transcript as bytes from there on.
    pub(crate) fn into_buffer(self) -> Option<Vec<u8>> {
        self.hash.is_none().then_some(self.buf)
    }

    pub(crate) fn current(&self) -> Vec<u8> {
        self.hash.as_ref().expect("hash chosen").peek()
    }

    /// The current hash with `extra` appended, leaving the transcript as
    /// it is.
    pub(crate) fn current_with(&self, extra: &[u8]) -> Vec<u8> {
        let mut h = self.hash.clone().expect("hash chosen");
        h.update(extra);
        h.finish()
    }

    /// The hash of the buffered messages under `alg`, before a hash is
    /// chosen. A client needs this for its PSK binders.
    pub(crate) fn buffered_hash_with(&self, alg: HashAlg, extra: &[u8]) -> Vec<u8> {
        let mut h = alg.new_hasher();
        h.update(&self.buf);
        h.update(extra);
        h.finish()
    }

    /// After a HelloRetryRequest the first ClientHello is replaced by a
    /// synthetic message_hash message holding its hash (RFC 8446 4.4.1).
    pub(crate) fn replace_with_message_hash(&mut self, alg: HashAlg) {
        let first = match self.hash.take() {
            Some(h) => h.finish(),
            None => alg.digest(&std::mem::take(&mut self.buf)),
        };
        let mut mh = vec![hs::MESSAGE_HASH, 0, 0, alg.output_len() as u8];
        mh.extend_from_slice(&first);
        let mut h = alg.new_hasher();
        h.update(&mh);
        self.hash = Some(h);
    }
}

/// What every connection has, whichever side and state it is in.
pub(crate) struct Core {
    deframer: Deframer,
    joiner: HandshakeJoiner,
    read: Option<Protection>,
    write: Option<Protection>,
    out: Vec<u8>,
    pending_hs: Vec<u8>,
    plain_in: Vec<u8>,
    plain_out: Vec<u8>,
    pub(crate) suite: Option<Suite>,
    read_secret: Option<Secret>,
    write_secret: Option<Secret>,
    pub(crate) exporter: Option<Secret>,
    write_is_app: bool,
    read_is_app: bool,
    /// The first ClientHello goes out with record version 0x0301, as
    /// RFC 8446 5.1 recommends for middleboxes; everything after with
    /// 0x0303.
    pub(crate) first_record_version: Option<u16>,
    ccs_allowed: bool,
    peer_closed: bool,
    sent_close: bool,
    failed: Option<Error>,
    idle_records: u32,
    pub(crate) alpn: Option<Vec<u8>>,
    pub(crate) peer_chain: Option<Vec<Vec<u8>>>,
    pub(crate) server_name: Option<String>,
    pub(crate) resumed: bool,
    /// TLS 1.2 was negotiated: change_cipher_spec switches the read keys
    /// to `pending_read` instead of being ignored.
    pub(crate) tls12: Option<Suite12>,
    pending_read: Option<Protection>,
    /// The master secret and both randoms, for the RFC 5705 exporter.
    pub(crate) exporter12: Option<(Secret, Vec<u8>)>,
}

/// Records that carry nothing (empty application data, ignored
/// change_cipher_spec, warning alerts) in a row before the connection
/// is closed, so a peer cannot keep it busy with them.
const MAX_IDLE_RECORDS: u32 = 32;

impl Core {
    pub(crate) fn new() -> Core {
        Core {
            deframer: Deframer::new(),
            joiner: HandshakeJoiner::default(),
            read: None,
            write: None,
            out: Vec::new(),
            pending_hs: Vec::new(),
            plain_in: Vec::new(),
            plain_out: Vec::new(),
            suite: None,
            read_secret: None,
            write_secret: None,
            exporter: None,
            write_is_app: false,
            read_is_app: false,
            first_record_version: None,
            ccs_allowed: true,
            peer_closed: false,
            sent_close: false,
            failed: None,
            idle_records: 0,
            alpn: None,
            peer_chain: None,
            server_name: None,
            resumed: false,
            tls12: None,
            pending_read: None,
            exporter12: None,
        }
    }

    /// TLS 1.2: the read protection that the peer's change_cipher_spec
    /// will switch to.
    pub(crate) fn expect_ccs(&mut self, p: Protection) {
        self.pending_read = Some(p);
    }

    /// TLS 1.2: sends change_cipher_spec and switches the write keys.
    pub(crate) fn change_write_keys(&mut self, p: Protection) -> Result<(), Error> {
        self.send_ccs()?;
        self.write = Some(p);
        Ok(())
    }

    /// TLS 1.2: the handshake is finished in this direction.
    pub(crate) fn open_write(&mut self) -> Result<(), Error> {
        self.flush_hs()?;
        self.write_is_app = true;
        let pending = std::mem::take(&mut self.plain_out);
        self.write_app(&pending)
    }

    /// TLS 1.2: true once the peer's change_cipher_spec has switched the
    /// read keys, which must happen before its Finished.
    pub(crate) fn read_protected(&self) -> bool {
        self.read.is_some()
    }

    pub(crate) fn open_read(&mut self) {
        self.read_is_app = true;
    }

    pub(crate) fn send_hs(&mut self, msg: &Handshake) -> Vec<u8> {
        let raw = msg.encode();
        self.pending_hs.extend_from_slice(&raw);
        raw
    }

    /// Writes the buffered handshake messages as records under the
    /// current write protection.
    pub(crate) fn flush_hs(&mut self) -> Result<(), Error> {
        let data = std::mem::take(&mut self.pending_hs);
        for chunk in data.chunks(MAX_PLAINTEXT) {
            match &mut self.write {
                Some(p) => p.seal(content::HANDSHAKE, chunk, &mut self.out)?,
                None => {
                    let v = self.first_record_version.take().unwrap_or(0x0303);
                    self.plain_record(content::HANDSHAKE, v, chunk);
                }
            }
        }
        Ok(())
    }

    fn plain_record(&mut self, typ: u8, version: u16, data: &[u8]) {
        self.out.push(typ);
        self.out.extend_from_slice(&version.to_be_bytes());
        self.out
            .extend_from_slice(&(data.len() as u16).to_be_bytes());
        self.out.extend_from_slice(data);
    }

    /// The dummy change_cipher_spec of middlebox compatibility mode
    /// (RFC 8446 D.4).
    pub(crate) fn send_ccs(&mut self) -> Result<(), Error> {
        self.flush_hs()?;
        self.plain_record(content::CHANGE_CIPHER_SPEC, 0x0303, &[1]);
        Ok(())
    }

    pub(crate) fn set_write_handshake(&mut self, suite: Suite, secret: &[u8]) -> Result<(), Error> {
        self.flush_hs()?;
        self.write = Some(Protection::tls13(suite, secret));
        Ok(())
    }

    pub(crate) fn set_read_handshake(&mut self, suite: Suite, secret: &[u8]) -> Result<(), Error> {
        self.check_key_change()?;
        self.read = Some(Protection::tls13(suite, secret));
        Ok(())
    }

    pub(crate) fn set_write_app(&mut self, suite: Suite, secret: Secret) -> Result<(), Error> {
        self.flush_hs()?;
        self.write = Some(Protection::tls13(suite, secret.expose()));
        self.write_secret = Some(secret);
        self.write_is_app = true;
        let pending = std::mem::take(&mut self.plain_out);
        self.write_app(&pending)
    }

    pub(crate) fn set_read_app(&mut self, suite: Suite, secret: Secret) -> Result<(), Error> {
        self.check_key_change()?;
        self.read = Some(Protection::tls13(suite, secret.expose()));
        self.read_secret = Some(secret);
        self.read_is_app = true;
        self.ccs_allowed = false;
        Ok(())
    }

    /// RFC 8446 5.1: handshake messages must not span a key change.
    fn check_key_change(&self) -> Result<(), Error> {
        if self.joiner.is_mid_message() {
            return Err(Error::unexpected("handshake message spans a key change"));
        }
        Ok(())
    }

    /// The handshake messages that arrived in the same record as the
    /// message that changed keys are under the old keys. A peer that does
    /// this is broken or attacking.
    pub(crate) fn no_buffered_handshake(&self) -> Result<(), Error> {
        self.check_key_change()
    }

    fn write_app(&mut self, data: &[u8]) -> Result<(), Error> {
        if !self.write_is_app {
            self.plain_out.extend_from_slice(data);
            return Ok(());
        }
        for chunk in data.chunks(MAX_PLAINTEXT) {
            if self.write.as_ref().is_some_and(Protection::exhausted) {
                // TLS 1.2 has no KeyUpdate; the connection has to end.
                if self.tls12.is_some() {
                    return Err(Error::internal("record limit of the key reached"));
                }
                self.send_key_update(false)?;
            }
            let w = self
                .write
                .as_mut()
                .ok_or(Error::internal("no write keys"))?;
            w.seal(content::APPLICATION_DATA, chunk, &mut self.out)?;
        }
        Ok(())
    }

    /// Sends a KeyUpdate and switches the write key (RFC 8446 4.6.3).
    pub(crate) fn send_key_update(&mut self, request_peer: bool) -> Result<(), Error> {
        let suite = self.suite.ok_or(Error::internal("no suite"))?;
        let next = next_traffic_secret(
            suite.hash,
            self.write_secret
                .as_ref()
                .ok_or(Error::internal("no secret"))?
                .expose(),
        );
        self.send_hs(&Handshake::new(hs::KEY_UPDATE, vec![request_peer as u8]));
        self.flush_hs()?;
        self.write = Some(Protection::tls13(suite, next.expose()));
        self.write_secret = Some(next);
        Ok(())
    }

    /// Handles a received KeyUpdate in the connected state.
    pub(crate) fn receive_key_update(&mut self, body: &[u8]) -> Result<(), Error> {
        let request = match body {
            [0] => false,
            [1] => true,
            _ => return Err(Error::illegal("KeyUpdate")),
        };
        self.check_key_change()?;
        let suite = self.suite.ok_or(Error::internal("no suite"))?;
        let next = next_traffic_secret(
            suite.hash,
            self.read_secret
                .as_ref()
                .ok_or(Error::internal("no secret"))?
                .expose(),
        );
        self.read = Some(Protection::tls13(suite, next.expose()));
        self.read_secret = Some(next);
        if request && !self.sent_close {
            self.send_key_update(false)?;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn write_secret_for_test(&self) -> Vec<u8> {
        self.write_secret
            .as_ref()
            .map(|s| s.expose().to_vec())
            .unwrap_or_default()
    }

    fn send_alert(&mut self, desc: u8) {
        let level = if desc == alert::CLOSE_NOTIFY || desc == alert::USER_CANCELED {
            1
        } else {
            2
        };
        let _ = self.flush_hs();
        match &mut self.write {
            Some(p) => {
                let _ = p.seal(content::ALERT, &[level, desc], &mut self.out);
            }
            None => self.plain_record(content::ALERT, 0x0303, &[level, desc]),
        }
    }

    fn idle(&mut self) -> Result<(), Error> {
        self.idle_records += 1;
        if self.idle_records > MAX_IDLE_RECORDS {
            return Err(Error::unexpected("too many records without content"));
        }
        Ok(())
    }

    /// Processes every complete record that has arrived.
    fn process(&mut self, state: &mut Option<Box<dyn State>>) -> Result<(), Error> {
        while let Some(rec) = self.deframer.pop()? {
            if self.peer_closed {
                return Err(Error::unexpected("data after close_notify"));
            }
            if rec.typ == content::CHANGE_CIPHER_SPEC && self.tls12.is_some() {
                // In TLS 1.2 it switches the read keys, and only where the
                // handshake expects it.
                if rec.payload != [1] || self.joiner.is_mid_message() {
                    return Err(Error::unexpected("change_cipher_spec"));
                }
                let p = self
                    .pending_read
                    .take()
                    .ok_or(Error::unexpected("change_cipher_spec"))?;
                self.read = Some(p);
                continue;
            }
            if rec.typ == content::CHANGE_CIPHER_SPEC {
                // Only during the handshake, only the one-byte dummy, and
                // never protected (RFC 8446 5).
                if !self.ccs_allowed || rec.payload != [1] {
                    return Err(Error::unexpected("change_cipher_spec"));
                }
                self.idle()?;
                continue;
            }
            let (typ, data) = match &mut self.read {
                Some(p) => p.open(rec)?,
                None => {
                    if rec.typ == content::APPLICATION_DATA {
                        return Err(Error::unexpected("application data before keys"));
                    }
                    if rec.payload.len() > MAX_PLAINTEXT {
                        return Err(Error::new(alert::RECORD_OVERFLOW, "record too long"));
                    }
                    (rec.typ, rec.payload)
                }
            };
            match typ {
                content::HANDSHAKE => {
                    if data.is_empty() {
                        return Err(Error::unexpected("empty handshake record"));
                    }
                    self.idle_records = 0;
                    self.joiner.push(&data);
                    while let Some((msg, raw)) = self.joiner.pop()? {
                        let s = state.take().ok_or(Error::internal("no state"))?;
                        *state = Some(s.handle(self, msg, raw)?);
                    }
                }
                content::ALERT => {
                    let [_level, desc] = data[..] else {
                        return Err(Error::decode("alert"));
                    };
                    if self.joiner.is_mid_message() {
                        return Err(Error::unexpected("alert inside a handshake message"));
                    }
                    match desc {
                        alert::CLOSE_NOTIFY => {
                            self.peer_closed = true;
                        }
                        alert::USER_CANCELED => self.idle()?,
                        d => return Err(Error::Peer(d)),
                    }
                }
                content::APPLICATION_DATA => {
                    if !self.read_is_app || self.joiner.is_mid_message() {
                        return Err(Error::unexpected("application data during the handshake"));
                    }
                    if data.is_empty() {
                        self.idle()?;
                    } else {
                        self.idle_records = 0;
                        self.plain_in.extend_from_slice(&data);
                    }
                }
                _ => return Err(Error::unexpected("unknown content type")),
            }
        }
        Ok(())
    }
}

/// The part of a connection that does not depend on its side.
pub struct Connection {
    pub(crate) core: Core,
    pub(crate) state: Option<Box<dyn State>>,
}

impl Connection {
    pub(crate) fn new(core: Core, state: Box<dyn State>) -> Connection {
        Connection {
            core,
            state: Some(state),
        }
    }

    fn fail(&mut self, e: Error) -> Error {
        if let Error::Local { alert: a, .. } = &e {
            self.core.send_alert(*a);
        }
        self.core.failed = Some(e.clone());
        self.core.plain_out.clear();
        e
    }

    /// Hands bytes received from the peer to the connection. On an error
    /// the alert for the peer is already queued in `take_tls`, and every
    /// later call fails.
    pub fn read_tls(&mut self, data: &[u8]) -> Result<(), Error> {
        if let Some(e) = &self.core.failed {
            return Err(e.clone());
        }
        self.core.deframer.push(data);
        let mut state = self.state.take();
        let r = self.core.process(&mut state);
        self.state = state;
        if self.state.as_ref().is_some_and(|s| s.is_connected()) && self.core.tls12.is_none() {
            self.core.deframer.max_ciphertext = MAX_CIPHERTEXT_13;
        }
        r.map_err(|e| self.fail(e))
    }

    /// The bytes to send to the peer, removed from the connection.
    pub fn take_tls(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.core.out)
    }

    pub fn wants_write(&self) -> bool {
        !self.core.out.is_empty()
    }

    pub fn is_handshaking(&self) -> bool {
        self.core.failed.is_none() && !self.state.as_ref().is_some_and(|s| s.is_connected())
    }

    /// Queues application data. Before the handshake has finished it is
    /// held back and sent once the keys exist.
    pub fn write(&mut self, data: &[u8]) -> Result<(), Error> {
        if let Some(e) = &self.core.failed {
            return Err(e.clone());
        }
        if self.core.sent_close {
            return Err(Error::Closed);
        }
        self.core.write_app(data).map_err(|e| self.fail(e))
    }

    /// Moves received application data into `buf` and returns how much.
    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.core.plain_in.len());
        buf[..n].copy_from_slice(&self.core.plain_in[..n]);
        self.core.plain_in.drain(..n);
        n
    }

    pub fn take_plaintext(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.core.plain_in)
    }

    pub fn has_plaintext(&self) -> bool {
        !self.core.plain_in.is_empty()
    }

    /// Sends close_notify. Data the peer sends afterwards can still be
    /// read; TLS 1.3 closes each direction on its own.
    pub fn close(&mut self) {
        if !self.core.sent_close && self.core.failed.is_none() {
            self.core.send_alert(alert::CLOSE_NOTIFY);
            self.core.sent_close = true;
        }
    }

    /// True once the peer has sent close_notify: everything it wrote has
    /// arrived and nothing more will.
    pub fn is_peer_closed(&self) -> bool {
        self.core.peer_closed
    }

    pub fn alpn_protocol(&self) -> Option<&[u8]> {
        self.core.alpn.as_deref()
    }

    /// The peer's certificate chain as it sent it, leaf first, once
    /// verified.
    pub fn peer_certificates(&self) -> Option<&[Vec<u8>]> {
        self.core.peer_chain.as_deref()
    }

    pub fn cipher_suite(&self) -> Option<u16> {
        self.core
            .suite
            .map(|s| s.id)
            .or(self.core.tls12.map(|s| s.id))
    }

    /// 0x0304 for TLS 1.3, 0x0303 for TLS 1.2, once negotiated.
    pub fn protocol_version(&self) -> Option<u16> {
        if self.core.tls12.is_some() {
            Some(0x0303)
        } else {
            self.core.suite.map(|_| 0x0304)
        }
    }

    /// True if this connection was resumed from a session ticket.
    pub fn is_resumed(&self) -> bool {
        self.core.resumed
    }

    /// Keying material for the application (RFC 8446 7.5, RFC 5705).
    pub fn export_keying_material(
        &self,
        label: &[u8],
        context: &[u8],
        len: usize,
    ) -> Result<Vec<u8>, Error> {
        if let (Some(suite), Some((master, randoms))) = (self.core.tls12, &self.core.exporter12) {
            // RFC 5705 4, with a context: the randoms, its length, itself.
            if context.len() > u16::MAX as usize {
                return Err(Error::internal("exporter context too long"));
            }
            let mut seed = randoms.clone();
            seed.extend_from_slice(&(context.len() as u16).to_be_bytes());
            seed.extend_from_slice(context);
            return Ok(prf12(suite.hash, master.expose(), label, &seed, len)
                .expose()
                .to_vec());
        }
        let (Some(suite), Some(secret)) = (self.core.suite, &self.core.exporter) else {
            return Err(Error::Closed);
        };
        Ok(export(suite.hash, secret.expose(), label, context, len)
            .expose()
            .to_vec())
    }

    /// Replaces this side's write key and asks the peer to replace its
    /// own. Keys are also replaced on their own before AES-GCM reaches its
    /// record limit.
    pub fn update_keys(&mut self) -> Result<(), Error> {
        if self.core.tls12.is_some() {
            return Err(Error::unexpected("TLS 1.2 has no KeyUpdate"));
        }
        if self.is_handshaking() {
            return Err(Error::unexpected("key update during the handshake"));
        }
        self.core.send_key_update(true).map_err(|e| self.fail(e))
    }
}

/// The connected state, the same for both sides.
pub(crate) struct Connected<F: Fn(&mut Core, &Handshake) -> Result<(), Error> + Send> {
    pub(crate) on_ticket: F,
}

impl<F: Fn(&mut Core, &Handshake) -> Result<(), Error> + Send + 'static> State for Connected<F> {
    fn handle(
        self: Box<Self>,
        core: &mut Core,
        msg: Handshake,
        _raw: Vec<u8>,
    ) -> Result<Box<dyn State>, Error> {
        match msg.typ {
            hs::KEY_UPDATE => core.receive_key_update(&msg.body)?,
            hs::NEW_SESSION_TICKET => (self.on_ticket)(core, &msg)?,
            _ => return Err(Error::unexpected("handshake message after the handshake")),
        }
        Ok(self)
    }

    fn is_connected(&self) -> bool {
        true
    }
}
