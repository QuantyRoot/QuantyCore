//! HTTP/2 (RFC 9113) without I/O: bytes from the socket go
//! into [`Connection::recv`], which returns what happened, and whatever the
//! connection wants sent waits in [`Connection::take_output`]. Threads,
//! sockets and timeouts belong to the caller.
//!
//! Received data is acknowledged as soon as it arrives, so the peer is never
//! slowed down by this side. Callers that buffer requests must bound them
//! themselves; the gRPC layer does.

use crate::hpack;
use std::collections::{HashMap, VecDeque};

pub const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const FRAME_HEADER_LEN: usize = 9;
const DEFAULT_WINDOW: i64 = 65_535;
const MAX_WINDOW: i64 = (1 << 31) - 1;
const MIN_FRAME_SIZE: u32 = 16_384;
const MAX_FRAME_SIZE: u32 = (1 << 24) - 1;

const DATA: u8 = 0x0;
const HEADERS: u8 = 0x1;
const PRIORITY: u8 = 0x2;
const RST_STREAM: u8 = 0x3;
const SETTINGS: u8 = 0x4;
const PUSH_PROMISE: u8 = 0x5;
const PING: u8 = 0x6;
const GOAWAY: u8 = 0x7;
const WINDOW_UPDATE: u8 = 0x8;
const CONTINUATION: u8 = 0x9;

const END_STREAM: u8 = 0x1;
const ACK: u8 = 0x1;
const END_HEADERS: u8 = 0x4;
const PADDED: u8 = 0x8;
const PRIORITY_FLAG: u8 = 0x20;

pub mod code {
    pub const NO_ERROR: u32 = 0x0;
    pub const PROTOCOL_ERROR: u32 = 0x1;
    pub const INTERNAL_ERROR: u32 = 0x2;
    pub const FLOW_CONTROL_ERROR: u32 = 0x3;
    pub const STREAM_CLOSED: u32 = 0x5;
    pub const FRAME_SIZE_ERROR: u32 = 0x6;
    pub const REFUSED_STREAM: u32 = 0x7;
    pub const CANCEL: u32 = 0x8;
    pub const COMPRESSION_ERROR: u32 = 0x9;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Settings {
    pub header_table_size: u32,
    pub max_concurrent_streams: u32,
    pub initial_window_size: u32,
    pub max_frame_size: u32,
    pub max_header_list_size: u32,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            header_table_size: 4096,
            max_concurrent_streams: 1000,
            initial_window_size: 1 << 20,
            max_frame_size: MIN_FRAME_SIZE,
            max_header_list_size: 1 << 16,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Headers {
        stream: u32,
        headers: Vec<hpack::Header>,
        end_stream: bool,
    },
    Data {
        stream: u32,
        data: Vec<u8>,
        end_stream: bool,
    },
    /// The peer reset the stream, or this side had to.
    Reset {
        stream: u32,
        code: u32,
    },
    GoAway {
        last_stream: u32,
        code: u32,
    },
}

/// A connection error. A GOAWAY carrying `code` is already in the output;
/// the caller sends it and closes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    pub code: u32,
    pub reason: &'static str,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "http2 error {:#x}: {}", self.code, self.reason)
    }
}

impl std::error::Error for Error {}

enum Item {
    Headers(Vec<u8>, bool),
    Data(Vec<u8>, bool),
}

struct Stream {
    /// false only on a client stream whose response has not started
    headers_seen: bool,
    send_window: i64,
    queue: VecDeque<Item>,
    remote_closed: bool,
    local_closed: bool,
}

struct PendingHeaders {
    stream: u32,
    block: Vec<u8>,
    end_stream: bool,
}

pub struct Connection {
    local: Settings,
    peer: Settings,
    seen_preface: bool,
    seen_settings: bool,
    inbuf: Vec<u8>,
    out: Vec<u8>,
    decoder: hpack::Decoder,
    streams: HashMap<u32, Stream>,
    last_peer_stream: u32,
    send_window: i64,
    unacked_conn: i64,
    unacked: HashMap<u32, i64>,
    continuation: Option<PendingHeaders>,
    closed: bool,
    client: bool,
    next_stream: u32,
}

impl Connection {
    pub fn server(local: Settings) -> Self {
        Self::new(local, false)
    }

    /// The client side, for calls this process makes. Server push is
    /// refused, so the only streams are the ones [`Self::start_request`]
    /// opens.
    pub fn client(local: Settings) -> Self {
        Self::new(local, true)
    }

    fn new(local: Settings, client: bool) -> Self {
        let mut c = Connection {
            local,
            peer: Settings {
                header_table_size: 4096,
                max_concurrent_streams: u32::MAX,
                initial_window_size: DEFAULT_WINDOW as u32,
                max_frame_size: MIN_FRAME_SIZE,
                max_header_list_size: u32::MAX,
            },
            seen_preface: false,
            seen_settings: false,
            inbuf: Vec::new(),
            out: Vec::new(),
            decoder: hpack::Decoder::new(
                local.header_table_size as usize,
                local.max_header_list_size as usize,
            ),
            streams: HashMap::new(),
            last_peer_stream: 0,
            send_window: DEFAULT_WINDOW,
            unacked_conn: 0,
            unacked: HashMap::new(),
            continuation: None,
            closed: false,
            client,
            next_stream: 1,
        };
        if client {
            c.out.extend_from_slice(PREFACE);
            c.seen_preface = true;
        }
        let mut payload = Vec::new();
        for (id, v) in [
            (0x1, local.header_table_size),
            (0x2, 0),
            (0x3, local.max_concurrent_streams),
            (0x4, local.initial_window_size),
            (0x5, local.max_frame_size),
            (0x6, local.max_header_list_size),
        ] {
            payload.extend_from_slice(&(id as u16).to_be_bytes());
            payload.extend_from_slice(&v.to_be_bytes());
        }
        c.frame(SETTINGS, 0, 0, &payload);
        // the connection window is not a setting; it only grows by update
        let grow = i64::from(local.initial_window_size) - DEFAULT_WINDOW;
        if grow > 0 {
            c.frame(WINDOW_UPDATE, 0, 0, &(grow as u32).to_be_bytes());
        }
        c
    }

    pub fn take_output(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.out)
    }

    pub fn has_output(&self) -> bool {
        !self.out.is_empty()
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }

    /// Bytes queued for `stream` that flow control has not let out yet.
    pub fn queued(&self, stream: u32) -> usize {
        self.streams.get(&stream).map_or(0, |s| {
            s.queue
                .iter()
                .map(|i| match i {
                    Item::Data(d, _) => d.len(),
                    Item::Headers(..) => 0,
                })
                .sum()
        })
    }

    pub fn recv(&mut self, bytes: &[u8]) -> Result<Vec<Event>, Error> {
        if self.closed {
            return Ok(Vec::new());
        }
        self.inbuf.extend_from_slice(bytes);
        let mut events = Vec::new();
        match self.process(&mut events) {
            Ok(()) => Ok(events),
            Err(e) => {
                self.goaway(e.code);
                Err(e)
            }
        }
    }

    fn process(&mut self, events: &mut Vec<Event>) -> Result<(), Error> {
        let mut pos = 0;
        if !self.seen_preface {
            let n = self.inbuf.len().min(PREFACE.len());
            if self.inbuf[..n] != PREFACE[..n] {
                return Err(protocol("bad connection preface"));
            }
            if n < PREFACE.len() {
                return Ok(());
            }
            self.seen_preface = true;
            pos = PREFACE.len();
        }
        while self.inbuf.len() - pos >= FRAME_HEADER_LEN {
            let h = &self.inbuf[pos..pos + FRAME_HEADER_LEN];
            let len = u32::from_be_bytes([0, h[0], h[1], h[2]]);
            let (kind, flags) = (h[3], h[4]);
            let stream = u32::from_be_bytes([h[5], h[6], h[7], h[8]]) & 0x7fff_ffff;
            if len > self.local.max_frame_size {
                return Err(Error {
                    code: code::FRAME_SIZE_ERROR,
                    reason: "frame larger than SETTINGS_MAX_FRAME_SIZE",
                });
            }
            let end = pos + FRAME_HEADER_LEN + len as usize;
            if self.inbuf.len() < end {
                break;
            }
            let payload = self.inbuf[pos + FRAME_HEADER_LEN..end].to_vec();
            pos = end;
            self.frame_in(kind, flags, stream, &payload, events)?;
        }
        self.inbuf.drain(..pos);
        Ok(())
    }

    fn frame_in(
        &mut self,
        kind: u8,
        flags: u8,
        stream: u32,
        payload: &[u8],
        events: &mut Vec<Event>,
    ) -> Result<(), Error> {
        if !self.seen_settings && (kind != SETTINGS || flags & ACK != 0) {
            return Err(protocol("first frame must be SETTINGS"));
        }
        if let Some(p) = &self.continuation {
            if kind != CONTINUATION || stream != p.stream {
                return Err(protocol("header block interrupted"));
            }
        }
        match kind {
            DATA => self.data_in(flags, stream, payload, events),
            HEADERS => self.headers_in(flags, stream, payload, events),
            CONTINUATION => {
                let mut p = self
                    .continuation
                    .take()
                    .ok_or(protocol("CONTINUATION without HEADERS"))?;
                p.block.extend_from_slice(payload);
                if p.block.len() > self.local.max_header_list_size as usize * 2 {
                    return Err(protocol("header block too large"));
                }
                if flags & END_HEADERS != 0 {
                    self.headers_done(p, events)
                } else {
                    self.continuation = Some(p);
                    Ok(())
                }
            }
            PRIORITY => {
                if stream == 0 {
                    return Err(protocol("PRIORITY on stream 0"));
                }
                if payload.len() != 5 {
                    self.reset(stream, code::FRAME_SIZE_ERROR);
                }
                Ok(())
            }
            RST_STREAM => {
                if stream == 0 {
                    return Err(protocol("RST_STREAM on stream 0"));
                }
                if payload.len() != 4 {
                    return Err(frame_size("RST_STREAM length"));
                }
                if self.idle(stream) {
                    return Err(protocol("RST_STREAM on an idle stream"));
                }
                let code = u32::from_be_bytes(payload.try_into().unwrap());
                if self.streams.remove(&stream).is_some() {
                    self.unacked.remove(&stream);
                    events.push(Event::Reset { stream, code });
                }
                Ok(())
            }
            SETTINGS => self.settings_in(flags, stream, payload),
            PUSH_PROMISE => Err(protocol("a client must not push")),
            PING => {
                if stream != 0 {
                    return Err(protocol("PING on a stream"));
                }
                if payload.len() != 8 {
                    return Err(frame_size("PING length"));
                }
                if flags & ACK == 0 {
                    self.frame(PING, ACK, 0, payload);
                }
                Ok(())
            }
            GOAWAY => {
                if stream != 0 {
                    return Err(protocol("GOAWAY on a stream"));
                }
                if payload.len() < 8 {
                    return Err(frame_size("GOAWAY length"));
                }
                events.push(Event::GoAway {
                    last_stream: u32::from_be_bytes(payload[..4].try_into().unwrap()) & 0x7fff_ffff,
                    code: u32::from_be_bytes(payload[4..8].try_into().unwrap()),
                });
                Ok(())
            }
            WINDOW_UPDATE => self.window_update_in(stream, payload),
            // unknown frame types must be ignored
            _ => Ok(()),
        }
    }

    fn data_in(
        &mut self,
        flags: u8,
        stream: u32,
        payload: &[u8],
        events: &mut Vec<Event>,
    ) -> Result<(), Error> {
        if stream == 0 {
            return Err(protocol("DATA on stream 0"));
        }
        // padding counts against flow control like data does
        let len = payload.len() as i64;
        self.unacked_conn += len;
        let data = unpad(flags, payload)?;
        let open = matches!(self.streams.get(&stream), Some(s) if !s.remote_closed);
        if !open {
            if self.idle(stream) {
                return Err(protocol("DATA on an idle stream"));
            }
            self.reset(stream, code::STREAM_CLOSED);
        } else {
            *self.unacked.entry(stream).or_default() += len;
            let end_stream = flags & END_STREAM != 0;
            if end_stream {
                self.remote_end(stream);
            }
            events.push(Event::Data {
                stream,
                data: data.to_vec(),
                end_stream,
            });
        }
        self.ack_received(stream);
        Ok(())
    }

    fn ack_received(&mut self, stream: u32) {
        let threshold = i64::from(self.local.initial_window_size) / 2;
        if self.unacked_conn >= threshold {
            let n = std::mem::take(&mut self.unacked_conn);
            self.frame(WINDOW_UPDATE, 0, 0, &(n as u32).to_be_bytes());
        }
        if let Some(n) = self.unacked.get_mut(&stream) {
            if *n >= threshold {
                let n = std::mem::take(n);
                if self.streams.get(&stream).is_some_and(|s| !s.remote_closed) {
                    self.frame(WINDOW_UPDATE, 0, stream, &(n as u32).to_be_bytes());
                }
            }
        }
    }

    fn headers_in(
        &mut self,
        flags: u8,
        stream: u32,
        payload: &[u8],
        events: &mut Vec<Event>,
    ) -> Result<(), Error> {
        if stream == 0 {
            return Err(protocol("HEADERS on stream 0"));
        }
        let mut block = unpad(flags, payload)?;
        if flags & PRIORITY_FLAG != 0 {
            block = block.get(5..).ok_or(frame_size("HEADERS priority"))?;
        }
        let p = PendingHeaders {
            stream,
            block: block.to_vec(),
            end_stream: flags & END_STREAM != 0,
        };
        if flags & END_HEADERS != 0 {
            self.headers_done(p, events)
        } else {
            self.continuation = Some(p);
            Ok(())
        }
    }

    fn headers_done(&mut self, p: PendingHeaders, events: &mut Vec<Event>) -> Result<(), Error> {
        // decode first, even for a stream about to be refused: the HPACK
        // table must see every block or it falls out of step with the peer
        let headers = self.decoder.decode(&p.block).map_err(|_| Error {
            code: code::COMPRESSION_ERROR,
            reason: "header block does not decode",
        })?;
        let stream = p.stream;
        match self.streams.get_mut(&stream) {
            Some(s) if !s.remote_closed => {
                if !s.headers_seen {
                    s.headers_seen = true;
                } else if !p.end_stream {
                    return Err(protocol("trailers without END_STREAM"));
                }
            }
            Some(_) => {
                self.reset(stream, code::STREAM_CLOSED);
                return Ok(());
            }
            None if self.client => {
                return Err(protocol("HEADERS on a stream this client never opened"));
            }
            None => {
                if stream.is_multiple_of(2) || stream <= self.last_peer_stream {
                    return Err(protocol("stream id not new or not odd"));
                }
                self.last_peer_stream = stream;
                if self.streams.len() >= self.local.max_concurrent_streams as usize {
                    self.reset(stream, code::REFUSED_STREAM);
                    return Ok(());
                }
                self.streams.insert(
                    stream,
                    Stream {
                        headers_seen: true,
                        send_window: i64::from(self.peer.initial_window_size),
                        queue: VecDeque::new(),
                        remote_closed: false,
                        local_closed: false,
                    },
                );
            }
        }
        if p.end_stream {
            self.remote_end(stream);
        }
        events.push(Event::Headers {
            stream,
            headers,
            end_stream: p.end_stream,
        });
        Ok(())
    }

    fn settings_in(&mut self, flags: u8, stream: u32, payload: &[u8]) -> Result<(), Error> {
        if stream != 0 {
            return Err(protocol("SETTINGS on a stream"));
        }
        if flags & ACK != 0 {
            if !payload.is_empty() {
                return Err(frame_size("SETTINGS ACK with payload"));
            }
            return Ok(());
        }
        if !payload.len().is_multiple_of(6) {
            return Err(frame_size("SETTINGS length"));
        }
        self.seen_settings = true;
        for s in payload.chunks(6) {
            let id = u16::from_be_bytes([s[0], s[1]]);
            let v = u32::from_be_bytes([s[2], s[3], s[4], s[5]]);
            match id {
                0x1 => self.peer.header_table_size = v,
                0x2 if v > 1 => return Err(protocol("ENABLE_PUSH not 0 or 1")),
                0x3 => self.peer.max_concurrent_streams = v,
                0x4 => {
                    if i64::from(v) > MAX_WINDOW {
                        return Err(Error {
                            code: code::FLOW_CONTROL_ERROR,
                            reason: "INITIAL_WINDOW_SIZE above 2^31-1",
                        });
                    }
                    let delta = i64::from(v) - i64::from(self.peer.initial_window_size);
                    for s in self.streams.values_mut() {
                        s.send_window += delta;
                        if s.send_window > MAX_WINDOW {
                            return Err(Error {
                                code: code::FLOW_CONTROL_ERROR,
                                reason: "stream window above 2^31-1",
                            });
                        }
                    }
                    self.peer.initial_window_size = v;
                }
                0x5 => {
                    if !(MIN_FRAME_SIZE..=MAX_FRAME_SIZE).contains(&v) {
                        return Err(protocol("MAX_FRAME_SIZE out of range"));
                    }
                    self.peer.max_frame_size = v;
                }
                0x6 => self.peer.max_header_list_size = v,
                _ => {}
            }
        }
        self.frame(SETTINGS, ACK, 0, &[]);
        self.flush_all();
        Ok(())
    }

    fn window_update_in(&mut self, stream: u32, payload: &[u8]) -> Result<(), Error> {
        if payload.len() != 4 {
            return Err(frame_size("WINDOW_UPDATE length"));
        }
        let inc = i64::from(u32::from_be_bytes(payload.try_into().unwrap()) & 0x7fff_ffff);
        if stream == 0 {
            if inc == 0 {
                return Err(protocol("WINDOW_UPDATE of 0"));
            }
            self.send_window += inc;
            if self.send_window > MAX_WINDOW {
                return Err(Error {
                    code: code::FLOW_CONTROL_ERROR,
                    reason: "connection window above 2^31-1",
                });
            }
            self.flush_all();
            return Ok(());
        }
        if self.idle(stream) {
            return Err(protocol("WINDOW_UPDATE on an idle stream"));
        }
        let Some(s) = self.streams.get_mut(&stream) else {
            return Ok(());
        };
        if inc == 0 {
            self.reset(stream, code::PROTOCOL_ERROR);
            return Ok(());
        }
        s.send_window += inc;
        if s.send_window > MAX_WINDOW {
            self.reset(stream, code::FLOW_CONTROL_ERROR);
            return Ok(());
        }
        self.flush(stream);
        Ok(())
    }

    fn idle(&self, stream: u32) -> bool {
        if self.client {
            stream >= self.next_stream
        } else {
            stream > self.last_peer_stream && stream % 2 == 1
        }
    }

    /// Opens a stream with a request's header block. Client side only.
    pub fn start_request(&mut self, headers: &[(&[u8], &[u8], bool)], end_stream: bool) -> u32 {
        assert!(self.client, "only a client opens streams");
        let id = self.next_stream;
        self.next_stream += 2;
        self.streams.insert(
            id,
            Stream {
                headers_seen: false,
                send_window: i64::from(self.peer.initial_window_size),
                queue: VecDeque::new(),
                remote_closed: false,
                local_closed: false,
            },
        );
        self.send_headers(id, headers, end_stream);
        id
    }

    fn remote_end(&mut self, stream: u32) {
        if let Some(s) = self.streams.get_mut(&stream) {
            s.remote_closed = true;
        }
        self.unacked.remove(&stream);
        self.maybe_forget(stream);
    }

    fn maybe_forget(&mut self, stream: u32) {
        if self
            .streams
            .get(&stream)
            .is_some_and(|s| s.remote_closed && s.local_closed && s.queue.is_empty())
        {
            self.streams.remove(&stream);
        }
    }

    /// Queues a header block (response headers or trailers). Returns false
    /// if the stream is gone, for example reset by the peer.
    pub fn send_headers(
        &mut self,
        stream: u32,
        headers: &[(&[u8], &[u8], bool)],
        end_stream: bool,
    ) -> bool {
        let mut block = Vec::new();
        hpack::encode(headers, &mut block);
        self.enqueue(stream, Item::Headers(block, end_stream))
    }

    pub fn send_data(&mut self, stream: u32, data: &[u8], end_stream: bool) -> bool {
        self.enqueue(stream, Item::Data(data.to_vec(), end_stream))
    }

    fn enqueue(&mut self, stream: u32, item: Item) -> bool {
        match self.streams.get_mut(&stream) {
            Some(s) if !s.local_closed => {
                if matches!(item, Item::Headers(_, true) | Item::Data(_, true)) {
                    s.local_closed = true;
                }
                s.queue.push_back(item);
                self.flush(stream);
                true
            }
            _ => false,
        }
    }

    pub fn reset(&mut self, stream: u32, code: u32) {
        self.streams.remove(&stream);
        self.unacked.remove(&stream);
        self.frame(RST_STREAM, 0, stream, &code.to_be_bytes());
    }

    pub fn goaway(&mut self, code: u32) {
        if self.closed {
            return;
        }
        self.closed = true;
        let mut p = self.last_peer_stream.to_be_bytes().to_vec();
        p.extend_from_slice(&code.to_be_bytes());
        self.frame(GOAWAY, 0, 0, &p);
    }

    fn flush_all(&mut self) {
        let mut ids: Vec<u32> = self.streams.keys().copied().collect();
        ids.sort_unstable();
        for id in ids {
            self.flush(id);
        }
    }

    fn flush(&mut self, stream: u32) {
        let max_frame = self.peer.max_frame_size as usize;
        loop {
            let Some(s) = self.streams.get_mut(&stream) else {
                return;
            };
            match s.queue.pop_front() {
                None => break,
                Some(Item::Headers(block, end)) => {
                    let mut chunks = block.chunks(max_frame).peekable();
                    let first = chunks.next().unwrap_or(&[]);
                    let mut flags = if end { END_STREAM } else { 0 };
                    if chunks.peek().is_none() {
                        flags |= END_HEADERS;
                    }
                    let mut frames = vec![(HEADERS, flags, first.to_vec())];
                    while let Some(c) = chunks.next() {
                        let f = if chunks.peek().is_none() {
                            END_HEADERS
                        } else {
                            0
                        };
                        frames.push((CONTINUATION, f, c.to_vec()));
                    }
                    for (k, f, p) in frames {
                        self.frame(k, f, stream, &p);
                    }
                }
                Some(Item::Data(mut data, end)) => {
                    let room = s.send_window.min(self.send_window).max(0) as usize;
                    let n = data.len().min(room).min(max_frame);
                    if n < data.len() || (n == 0 && !data.is_empty()) {
                        let rest = data.split_off(n);
                        s.queue.push_front(Item::Data(rest, end));
                        s.send_window -= n as i64;
                        self.send_window -= n as i64;
                        if n > 0 {
                            self.frame(DATA, 0, stream, &data);
                            continue;
                        }
                        break;
                    }
                    s.send_window -= n as i64;
                    self.send_window -= n as i64;
                    self.frame(DATA, if end { END_STREAM } else { 0 }, stream, &data);
                }
            }
        }
        self.maybe_forget(stream);
    }

    fn frame(&mut self, kind: u8, flags: u8, stream: u32, payload: &[u8]) {
        let len = payload.len() as u32;
        self.out.extend_from_slice(&len.to_be_bytes()[1..]);
        self.out.push(kind);
        self.out.push(flags);
        self.out.extend_from_slice(&stream.to_be_bytes());
        self.out.extend_from_slice(payload);
    }
}

fn unpad(flags: u8, payload: &[u8]) -> Result<&[u8], Error> {
    if flags & PADDED == 0 {
        return Ok(payload);
    }
    let pad = *payload.first().ok_or(frame_size("missing pad length"))? as usize;
    if pad >= payload.len() {
        return Err(protocol("padding longer than the frame"));
    }
    Ok(&payload[1..payload.len() - pad])
}

fn protocol(reason: &'static str) -> Error {
    Error {
        code: code::PROTOCOL_ERROR,
        reason,
    }
}

fn frame_size(reason: &'static str) -> Error {
    Error {
        code: code::FRAME_SIZE_ERROR,
        reason,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Frame {
        kind: u8,
        flags: u8,
        stream: u32,
        payload: Vec<u8>,
    }

    fn frames(mut b: &[u8]) -> Vec<Frame> {
        let mut out = Vec::new();
        while !b.is_empty() {
            let len = u32::from_be_bytes([0, b[0], b[1], b[2]]) as usize;
            out.push(Frame {
                kind: b[3],
                flags: b[4],
                stream: u32::from_be_bytes([b[5], b[6], b[7], b[8]]),
                payload: b[9..9 + len].to_vec(),
            });
            b = &b[9 + len..];
        }
        out
    }

    fn raw(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let mut c = Connection::server(Settings::default());
        c.out.clear();
        c.frame(kind, flags, stream, payload);
        c.out
    }

    fn settings(pairs: &[(u16, u32)]) -> Vec<u8> {
        let mut p = Vec::new();
        for (id, v) in pairs {
            p.extend_from_slice(&id.to_be_bytes());
            p.extend_from_slice(&v.to_be_bytes());
        }
        raw(SETTINGS, 0, 0, &p)
    }

    fn request(stream: u32, end: bool) -> Vec<u8> {
        let mut block = Vec::new();
        hpack::encode(
            &[
                (b":method", b"POST", false),
                (b":path", b"/etcdserverpb.KV/Range", false),
            ],
            &mut block,
        );
        raw(
            HEADERS,
            END_HEADERS | if end { END_STREAM } else { 0 },
            stream,
            &block,
        )
    }

    fn open(peer: &[(u16, u32)]) -> Connection {
        let mut c = Connection::server(Settings::default());
        let mut input = PREFACE.to_vec();
        input.extend(settings(peer));
        c.recv(&input).unwrap();
        c.take_output();
        c
    }

    #[test]
    fn handshake_and_a_request() {
        let mut c = Connection::server(Settings::default());
        let mut input = PREFACE.to_vec();
        input.extend(settings(&[]));
        input.extend(request(1, false));
        input.extend(raw(DATA, PADDED | END_STREAM, 1, &[2, b'h', b'i', 0, 0]));
        // arrive in pieces, as a socket delivers them
        let mut events = Vec::new();
        for chunk in input.chunks(7) {
            events.extend(c.recv(chunk).unwrap());
        }
        let out = frames(&c.take_output());
        assert_eq!(out[0].kind, SETTINGS);
        assert!(out.iter().any(|f| f.kind == SETTINGS && f.flags == ACK));
        assert!(matches!(
            &events[0],
            Event::Headers {
                stream: 1,
                end_stream: false,
                ..
            }
        ));
        assert_eq!(
            events[1],
            Event::Data {
                stream: 1,
                data: b"hi".to_vec(),
                end_stream: true
            }
        );
    }

    #[test]
    fn data_waits_for_the_window_and_trailers_wait_for_data() {
        let mut c = open(&[(0x4, 10)]);
        c.recv(&request(1, true)).unwrap();
        c.send_headers(1, &[(b":status", b"200", false)], false);
        c.send_data(1, &[7; 25], false);
        c.send_headers(1, &[(b"grpc-status", b"0", false)], true);
        let out = frames(&c.take_output());
        assert_eq!(out.len(), 2);
        assert_eq!((out[1].kind, out[1].payload.len()), (DATA, 10));
        assert_eq!(c.queued(1), 15);

        c.recv(&raw(WINDOW_UPDATE, 0, 1, &100u32.to_be_bytes()))
            .unwrap();
        let out = frames(&c.take_output());
        assert_eq!((out[0].kind, out[0].payload.len()), (DATA, 15));
        assert_eq!(
            (out[1].kind, out[1].flags),
            (HEADERS, END_HEADERS | END_STREAM)
        );
        assert!(c.streams.is_empty(), "a finished stream is forgotten");
    }

    #[test]
    fn the_connection_window_limits_all_streams() {
        let mut c = open(&[(0x4, 1 << 20)]);
        c.recv(&request(1, true)).unwrap();
        c.send_data(1, &vec![0; 70_000], true);
        let sent: usize = frames(&c.take_output())
            .iter()
            .map(|f| f.payload.len())
            .sum();
        assert_eq!(sent, DEFAULT_WINDOW as usize);
        c.recv(&raw(WINDOW_UPDATE, 0, 0, &10_000u32.to_be_bytes()))
            .unwrap();
        let out = frames(&c.take_output());
        assert_eq!(
            out.iter().map(|f| f.payload.len()).sum::<usize>(),
            70_000 - 65_535
        );
        assert_eq!(out.last().unwrap().flags, END_STREAM);
    }

    #[test]
    fn large_header_blocks_use_continuation_both_ways() {
        let mut c = open(&[]);
        c.recv(&request(1, true)).unwrap();
        let big = vec![b'x'; 40_000];
        c.send_headers(1, &[(b"x-big", &big, false)], true);
        let out = frames(&c.take_output());
        assert_eq!(
            out.iter().map(|f| (f.kind, f.flags)).collect::<Vec<_>>(),
            [
                (HEADERS, END_STREAM),
                (CONTINUATION, 0),
                (CONTINUATION, END_HEADERS)
            ]
        );
        let block: Vec<u8> = out.iter().flat_map(|f| f.payload.clone()).collect();
        let h = hpack::Decoder::new(4096, 1 << 20).decode(&block).unwrap();
        assert_eq!(h[0].value, big);

        let mut req = request(3, true);
        let (head, tail) = req.split_at_mut(9 + 2);
        let tail = tail.to_vec();
        head[2] = 2;
        head[4] = END_STREAM;
        let mut input = head.to_vec();
        input.extend(raw(CONTINUATION, END_HEADERS, 3, &tail));
        let ev = c.recv(&input).unwrap();
        assert!(
            matches!(&ev[0], Event::Headers { stream: 3, end_stream: true, headers } if headers.len() == 2)
        );

        let mut c = open(&[]);
        let mut input = head.to_vec();
        input.extend(raw(PING, 0, 0, &[0; 8]));
        assert_eq!(
            c.recv(&input).unwrap_err().reason,
            "header block interrupted"
        );
    }

    #[test]
    fn ping_is_answered() {
        let mut c = open(&[]);
        c.recv(&raw(PING, 0, 0, b"12345678")).unwrap();
        let out = frames(&c.take_output());
        assert_eq!(
            (out[0].kind, out[0].flags, &out[0].payload[..]),
            (PING, ACK, &b"12345678"[..])
        );
    }

    #[test]
    fn protocol_violations_end_the_connection() {
        let cases: Vec<(Vec<u8>, u32)> = vec![
            (raw(PING, 0, 0, &[0; 8]), code::PROTOCOL_ERROR),
            (request(2, true), code::PROTOCOL_ERROR),
            (raw(DATA, 0, 0, b"x"), code::PROTOCOL_ERROR),
            (raw(DATA, 0, 0, &vec![0; 20_000]), code::FRAME_SIZE_ERROR),
            (
                raw(WINDOW_UPDATE, 0, 0, &0u32.to_be_bytes()),
                code::PROTOCOL_ERROR,
            ),
            (
                raw(PUSH_PROMISE, END_HEADERS, 1, &[0, 0, 0, 2]),
                code::PROTOCOL_ERROR,
            ),
            (settings(&[(0x4, 1 << 31)]), code::FLOW_CONTROL_ERROR),
            (
                raw(HEADERS, END_HEADERS, 1, &[0x80]),
                code::COMPRESSION_ERROR,
            ),
        ];
        for (i, (frame, want)) in cases.into_iter().enumerate() {
            let mut c = Connection::server(Settings::default());
            let mut input = PREFACE.to_vec();
            // the first case checks that SETTINGS must come first
            if i > 0 {
                input.extend(settings(&[]));
            }
            input.extend(frame);
            let err = c.recv(&input).unwrap_err();
            assert_eq!(err.code, want, "case {i}: {}", err.reason);
            let goaway = frames(&c.take_output()).pop().unwrap();
            assert_eq!(goaway.kind, GOAWAY, "case {i}");
            assert!(c.is_closed());
        }
        let mut c = Connection::server(Settings::default());
        assert!(c.recv(b"GET / HTTP/1.1\r\n").is_err());
    }

    #[test]
    fn streams_beyond_the_limit_are_refused() {
        let mut c = Connection::server(Settings {
            max_concurrent_streams: 1,
            ..Settings::default()
        });
        let mut input = PREFACE.to_vec();
        input.extend(settings(&[]));
        input.extend(request(1, false));
        input.extend(request(3, false));
        let ev = c.recv(&input).unwrap();
        assert_eq!(ev.len(), 1);
        let rst = frames(&c.take_output()).pop().unwrap();
        assert_eq!((rst.kind, rst.stream), (RST_STREAM, 3));
        assert_eq!(rst.payload, code::REFUSED_STREAM.to_be_bytes());
    }
}
