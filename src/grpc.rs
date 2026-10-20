//! gRPC over [`crate::h2`], server side, on blocking sockets.
//!
//! One thread reads each connection. Unary calls run on a shared pool of
//! workers; each streaming call gets a thread of its own, since streams
//! such as watches live for hours and would otherwise starve the pool.

use crate::h2::{self, Connection, Event, Settings};
use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::Shutdown;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

pub mod code {
    pub const OK: u32 = 0;
    pub const CANCELLED: u32 = 1;
    pub const UNKNOWN: u32 = 2;
    pub const INVALID_ARGUMENT: u32 = 3;
    pub const NOT_FOUND: u32 = 5;
    pub const FAILED_PRECONDITION: u32 = 9;
    pub const OUT_OF_RANGE: u32 = 11;
    pub const UNIMPLEMENTED: u32 = 12;
    pub const INTERNAL: u32 = 13;
    pub const UNAVAILABLE: u32 = 14;
    pub const RESOURCE_EXHAUSTED: u32 = 8;
}

/// Largest request message accepted. etcd's own default is 1.5 MiB; this
/// leaves room without letting one call claim unbounded memory.
pub const MAX_MESSAGE: usize = 16 << 20;

/// Threads for unary calls on one server. Unary calls mostly wait on the
/// disk, not the CPU, and a group commit can only be as large as the
/// number of writes in flight.
pub const UNARY_THREADS: usize = 64;

/// A streaming sender blocks once this much is waiting on flow control, so
/// a client that stops reading cannot make the server buffer forever.
const MAX_QUEUED: usize = 4 << 20;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    pub code: u32,
    pub message: String,
}

impl Status {
    pub fn new(code: u32, message: impl Into<String>) -> Self {
        Status {
            code,
            message: message.into(),
        }
    }
}

pub trait Service: Send + Sync + 'static {
    fn is_streaming(&self, method: &str) -> bool;

    /// `method` is the full path, such as `/etcdserverpb.KV/Range`.
    fn unary(&self, method: &str, request: &[u8]) -> Result<Vec<u8>, Status>;

    /// Runs on its own thread for the life of the call. Returning without
    /// calling [`Responder::finish`] finishes with OK.
    fn stream(&self, method: &str, requests: Receiver<Vec<u8>>, responder: Responder);
}

pub trait Socket: Read + Write + Send + 'static {
    fn try_clone(&self) -> std::io::Result<Self>
    where
        Self: Sized;
    fn set_read_timeout(&self, t: Option<Duration>) -> std::io::Result<()>;
    fn set_write_timeout(&self, t: Option<Duration>) -> std::io::Result<()>;
    fn shutdown(&self, how: Shutdown) -> std::io::Result<()>;
}

macro_rules! socket {
    ($t:ty) => {
        impl Socket for $t {
            fn try_clone(&self) -> std::io::Result<Self> {
                <$t>::try_clone(self)
            }
            fn set_read_timeout(&self, t: Option<Duration>) -> std::io::Result<()> {
                <$t>::set_read_timeout(self, t)
            }
            fn set_write_timeout(&self, t: Option<Duration>) -> std::io::Result<()> {
                <$t>::set_write_timeout(self, t)
            }
            fn shutdown(&self, how: Shutdown) -> std::io::Result<()> {
                <$t>::shutdown(self, how)
            }
        }
    };
}

socket!(std::os::unix::net::UnixStream);
socket!(std::net::TcpStream);

/// What one server allows its peers.
#[derive(Debug, Clone)]
pub struct Options {
    /// Time to send the preface and SETTINGS before the connection closes.
    pub handshake_timeout: Duration,
    /// A connection with no open stream that sends nothing for this long
    /// gets GOAWAY NO_ERROR.
    pub idle_timeout: Duration,
    /// A peer that takes longer than this to accept a write has stopped
    /// reading, and its connection is dropped.
    pub write_timeout: Duration,
    /// Streaming calls each hold a thread, so they are capped on each
    /// connection.
    pub max_streaming_per_connection: usize,
    /// And across the server. A call beyond either cap ends at once with
    /// RESOURCE_EXHAUSTED.
    pub max_streaming: usize,
    pub unary_threads: usize,
    pub limits: h2::Limits,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            handshake_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(300),
            write_timeout: Duration::from_secs(30),
            max_streaming_per_connection: 256,
            max_streaming: 1024,
            unary_threads: UNARY_THREADS,
            limits: h2::Limits::default(),
        }
    }
}

struct Shared<S> {
    conn: Connection,
    writer: S,
    alive: bool,
    /// When the last open stream ended, if none is open now.
    idle_since: Option<Instant>,
}

struct Link<S> {
    shared: Mutex<Shared<S>>,
    drained: Condvar,
}

impl<S: Socket> Link<S> {
    /// Applies `f` to the connection and writes whatever it produced.
    fn with<R>(&self, f: impl FnOnce(&mut Connection) -> R) -> R {
        let mut g = self.lock();
        let r = f(&mut g.conn);
        let out = g.conn.take_output();
        if !out.is_empty() && g.alive && g.writer.write_all(&out).is_err() {
            g.alive = false;
        }
        if g.conn.open_streams() > 0 {
            g.idle_since = None;
        } else if g.idle_since.is_none() {
            g.idle_since = Some(Instant::now());
        }
        r
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Shared<S>> {
        self.shared.lock().unwrap_or_else(|e| e.into_inner())
    }
}

trait Sink: Send + Sync {
    fn is_open(&self, stream: u32) -> bool;
    fn send(&self, stream: u32, msg: &[u8], started: bool) -> bool;
    fn finish(&self, stream: u32, status: &Status, started: bool);
}

impl<S: Socket> Sink for Link<S> {
    fn is_open(&self, stream: u32) -> bool {
        let g = self.lock();
        g.alive && g.conn.is_open(stream)
    }

    fn send(&self, stream: u32, msg: &[u8], started: bool) -> bool {
        {
            let mut g = self.lock();
            while g.alive && g.conn.queued(stream) > MAX_QUEUED {
                g = self.drained.wait(g).unwrap_or_else(|e| e.into_inner());
            }
            if !g.alive {
                return false;
            }
        }
        self.with(|c| {
            if !started && !c.send_headers(stream, &response_headers(), false) {
                return false;
            }
            c.send_data(stream, &frame_message(msg), false)
        })
    }

    fn finish(&self, stream: u32, status: &Status, started: bool) {
        let code = status.code.to_string();
        let message = percent_encode(&status.message);
        let mut h: Vec<(&[u8], &[u8], bool)> = Vec::new();
        if !started {
            h.extend(response_headers());
        }
        h.push((b"grpc-status", code.as_bytes(), false));
        if !message.is_empty() {
            h.push((b"grpc-message", message.as_bytes(), false));
        }
        self.with(|c| c.send_headers(stream, &h, true));
    }
}

/// Sends the responses of one streaming call.
pub struct Responder {
    sink: Arc<dyn Sink>,
    stream: u32,
    started: bool,
    finished: bool,
    slot: Option<Slot>,
}

impl Responder {
    /// Returns false once the call is gone: reset by the client or the
    /// connection closed. The caller should stop then.
    pub fn send(&mut self, msg: &[u8]) -> bool {
        if self.finished {
            return false;
        }
        let ok = self.sink.send(self.stream, msg, self.started);
        self.started = true;
        ok
    }

    pub fn finish(mut self, status: Status) {
        self.end(&status);
    }

    fn end(&mut self, status: &Status) {
        if self.finished {
            return;
        }
        self.finished = true;
        // freed before the trailers go out, so a client that has seen the
        // call end can start another at once
        self.slot = None;
        self.sink.finish(self.stream, status, self.started);
    }
}

impl Drop for Responder {
    fn drop(&mut self) {
        self.end(&Status::new(code::OK, ""));
    }
}

/// One streaming call, counted against its connection's cap and the
/// server's.
struct Slot([Arc<AtomicUsize>; 2]);

impl Slot {
    fn take(caps: [(&Arc<AtomicUsize>, usize); 2]) -> Option<Slot> {
        for (i, (n, max)) in caps.iter().enumerate() {
            if n.fetch_add(1, Ordering::AcqRel) >= *max {
                for (n, _) in &caps[..=i] {
                    n.fetch_sub(1, Ordering::AcqRel);
                }
                return None;
            }
        }
        Some(Slot(caps.map(|(n, _)| n.clone())))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        for n in &self.0 {
            n.fetch_sub(1, Ordering::AcqRel);
        }
    }
}

fn response_headers() -> [(&'static [u8], &'static [u8], bool); 2] {
    [
        (b":status", b"200", false),
        (b"content-type", b"application/grpc", false),
    ]
}

pub fn frame_message(msg: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + msg.len());
    out.push(0);
    out.extend_from_slice(&(msg.len() as u32).to_be_bytes());
    out.extend_from_slice(msg);
    out
}

/// grpc-message is percent encoded (gRPC over HTTP/2, "Responses").
fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if (0x20..0x7f).contains(&b) && b != b'%' {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Splits length-prefixed messages out of a byte stream.
#[derive(Default)]
pub struct Deframer {
    buf: Vec<u8>,
}

impl Deframer {
    pub fn push(&mut self, data: &[u8]) -> Result<Vec<Vec<u8>>, Status> {
        self.buf.extend_from_slice(data);
        let mut msgs = Vec::new();
        let mut pos = 0;
        while self.buf.len() - pos >= 5 {
            if self.buf[pos] != 0 {
                return Err(Status::new(code::UNIMPLEMENTED, "compressed messages"));
            }
            let len = u32::from_be_bytes(self.buf[pos + 1..pos + 5].try_into().unwrap()) as usize;
            if len > MAX_MESSAGE {
                return Err(Status::new(code::RESOURCE_EXHAUSTED, "message too large"));
            }
            if self.buf.len() - pos - 5 < len {
                break;
            }
            msgs.push(self.buf[pos + 5..pos + 5 + len].to_vec());
            pos += 5 + len;
        }
        self.buf.drain(..pos);
        Ok(msgs)
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

type Job = Box<dyn FnOnce() + Send>;

/// A fixed set of threads for unary calls.
struct Pool {
    jobs: Mutex<Sender<Job>>,
}

impl Pool {
    fn new(threads: usize) -> Arc<Pool> {
        let (tx, rx) = mpsc::channel::<Job>();
        let rx = Arc::new(Mutex::new(rx));
        for _ in 0..threads.max(1) {
            let rx = rx.clone();
            std::thread::spawn(move || loop {
                let job = rx.lock().unwrap_or_else(|e| e.into_inner()).recv();
                match job {
                    Ok(job) => job(),
                    Err(_) => return,
                }
            });
        }
        Arc::new(Pool {
            jobs: Mutex::new(tx),
        })
    }

    fn run(&self, job: Job) {
        let _ = self
            .jobs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .send(job);
    }
}

enum Call {
    Unary {
        method: String,
        body: Deframer,
        msgs: Vec<Vec<u8>>,
    },
    Streaming {
        body: Deframer,
        tx: Sender<Vec<u8>>,
    },
}

/// One [`Service`] with its pool of unary threads, and the streaming calls
/// it has running across all its connections.
pub struct Server {
    service: Arc<dyn Service>,
    pool: Arc<Pool>,
    options: Options,
    streaming: Arc<AtomicUsize>,
}

impl Server {
    pub fn new(service: Arc<dyn Service>, options: Options) -> Arc<Server> {
        Arc::new(Server {
            service,
            pool: Pool::new(options.unary_threads),
            options,
            streaming: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// Accepts connections forever, one thread each.
    pub fn serve_unix(
        self: Arc<Self>,
        listener: std::os::unix::net::UnixListener,
    ) -> std::io::Result<()> {
        for socket in listener.incoming() {
            let socket = socket?;
            let server = self.clone();
            std::thread::spawn(move || server.serve_connection(socket));
        }
        Ok(())
    }

    /// Serves one connection until the peer goes away or breaks a limit in
    /// [`Options`]. Blocks the calling thread.
    pub fn serve_connection<S: Socket>(&self, socket: S) {
        let o = &self.options;
        let Ok(writer) = socket.try_clone() else {
            return;
        };
        let _ = writer.set_write_timeout(Some(o.write_timeout));
        let mut reader = socket;
        let link = Arc::new(Link {
            shared: Mutex::new(Shared {
                conn: Connection::server(Settings::default()).with_limits(o.limits),
                writer,
                alive: true,
                idle_since: None,
            }),
            drained: Condvar::new(),
        });
        link.with(|_| ());
        let start = Instant::now();
        let mut last_read = start;
        let streaming = Arc::new(AtomicUsize::new(0));
        let mut calls: HashMap<u32, Call> = HashMap::new();
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let deadline = {
                let g = link.lock();
                if !g.alive || g.conn.is_closed() {
                    break;
                }
                if g.conn.is_established() {
                    let since = g.idle_since.map(|t| t.max(last_read));
                    since.and_then(|t| t.checked_add(o.idle_timeout))
                } else {
                    start.checked_add(o.handshake_timeout)
                }
            };
            let wait = match deadline {
                Some(d) => match d.checked_duration_since(Instant::now()) {
                    Some(w) if !w.is_zero() => w,
                    _ => {
                        link.with(|c| {
                            if c.is_established() {
                                c.goaway(h2::code::NO_ERROR);
                            }
                        });
                        break;
                    }
                },
                // streams are open, or the timeout never ends: look again
                // later in case they have all ended
                None => o.idle_timeout,
            };
            let _ = reader.set_read_timeout(Some(wait));
            let n = match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e)
                    if matches!(
                        e.kind(),
                        ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                    ) =>
                {
                    continue
                }
                Err(_) => break,
            };
            last_read = Instant::now();
            let events = link.with(|c| c.recv(&buf[..n]));
            link.drained.notify_all();
            let Ok(events) = events else { break };
            for ev in events {
                self.handle(ev, &mut calls, &link, &streaming);
            }
        }
        link.lock().alive = false;
        link.drained.notify_all();
        // streaming handlers may still hold a clone of the socket, and the
        // peer must see the end now rather than when the last one returns
        let _ = reader.shutdown(Shutdown::Both);
    }

    fn handle<S: Socket>(
        &self,
        ev: Event,
        calls: &mut HashMap<u32, Call>,
        link: &Arc<Link<S>>,
        streaming: &Arc<AtomicUsize>,
    ) {
        let sink: Arc<dyn Sink> = link.clone();
        match ev {
            Event::Headers {
                stream,
                headers,
                end_stream,
            } => {
                if calls.contains_key(&stream) {
                    // trailers from the client carry nothing gRPC uses
                    if end_stream {
                        self.end_of_requests(stream, calls, sink);
                    }
                    return;
                }
                let path = headers
                    .iter()
                    .find(|h| h.name == b":path")
                    .and_then(|h| String::from_utf8(h.value.clone()).ok());
                let grpc = headers
                    .iter()
                    .any(|h| h.name == b"content-type" && h.value.starts_with(b"application/grpc"));
                let Some(method) = path.filter(|_| grpc) else {
                    link.with(|c| {
                        c.send_headers(stream, &[(b":status", b"415", false)], true);
                    });
                    return;
                };
                let call = if self.service.is_streaming(&method) {
                    let o = &self.options;
                    let Some(slot) = Slot::take([
                        (streaming, o.max_streaming_per_connection),
                        (&self.streaming, o.max_streaming),
                    ]) else {
                        let status =
                            Status::new(code::RESOURCE_EXHAUSTED, "too many streaming calls");
                        sink.finish(stream, &status, false);
                        if !end_stream {
                            link.with(|c| c.reset(stream, h2::code::NO_ERROR));
                        }
                        return;
                    };
                    let (tx, rx) = mpsc::channel();
                    let responder = Responder {
                        sink,
                        stream,
                        started: false,
                        finished: false,
                        slot: Some(slot),
                    };
                    let service = self.service.clone();
                    std::thread::spawn(move || service.stream(&method, rx, responder));
                    Call::Streaming {
                        body: Deframer::default(),
                        tx,
                    }
                } else {
                    Call::Unary {
                        method,
                        body: Deframer::default(),
                        msgs: Vec::new(),
                    }
                };
                calls.insert(stream, call);
                if end_stream {
                    self.end_of_requests(stream, calls, link.clone());
                }
            }
            Event::Data {
                stream,
                data,
                end_stream,
            } => {
                let Some(call) = calls.get_mut(&stream) else {
                    return;
                };
                let pushed = match call {
                    Call::Unary { body, msgs, .. } => body.push(&data).map(|m| msgs.extend(m)),
                    Call::Streaming { body, tx } => body.push(&data).map(|m| {
                        for msg in m {
                            let _ = tx.send(msg);
                        }
                    }),
                };
                if let Err(status) = pushed {
                    calls.remove(&stream);
                    sink.finish(stream, &status, false);
                    link.with(|c| c.reset(stream, h2::code::CANCEL));
                    return;
                }
                if end_stream {
                    self.end_of_requests(stream, calls, sink);
                }
            }
            Event::Reset { stream, .. } => {
                calls.remove(&stream);
            }
            Event::GoAway { .. } => {}
        }
    }

    fn end_of_requests(&self, stream: u32, calls: &mut HashMap<u32, Call>, sink: Arc<dyn Sink>) {
        match calls.remove(&stream) {
            Some(Call::Unary { method, msgs, .. }) => {
                let service = self.service.clone();
                self.pool.run(Box::new(move || {
                    // a call reset while it waited for a thread is not run,
                    // or opening and resetting calls would queue unbounded
                    // work (CVE-2023-44487)
                    if !sink.is_open(stream) {
                        return;
                    }
                    let result = match msgs.as_slice() {
                        [one] => std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                            service.unary(&method, one)
                        }))
                        .unwrap_or_else(|_| Err(Status::new(code::INTERNAL, "handler panicked"))),
                        _ => Err(Status::new(
                            code::INTERNAL,
                            "a unary call needs exactly one request message",
                        )),
                    };
                    match result {
                        Ok(resp) => {
                            if sink.send(stream, &resp, false) {
                                sink.finish(stream, &Status::new(code::OK, ""), true);
                            }
                        }
                        Err(status) => sink.finish(stream, &status, false),
                    }
                }));
            }
            // dropping the sender ends the handler's request iterator
            Some(Call::Streaming { .. }) | None => {}
        }
    }
}

/// One unary call on a connection of its own. Meant for command line
/// tools, which make a call or two and exit.
pub fn call<S: Read + Write>(mut sock: S, method: &str, request: &[u8]) -> Result<Vec<u8>, Status> {
    let io = |e: std::io::Error| Status::new(code::UNAVAILABLE, e.to_string());
    let mut conn = Connection::client(Settings::default());
    let id = conn.start_request(
        &[
            (b":method", b"POST", false),
            (b":scheme", b"http", false),
            (b":path", method.as_bytes(), false),
            (b":authority", b"localhost", false),
            (b"content-type", b"application/grpc", false),
            (b"te", b"trailers", false),
        ],
        false,
    );
    conn.send_data(id, &frame_message(request), true);
    let mut body = Deframer::default();
    let mut msgs = Vec::new();
    let (mut status, mut message) = (None, String::new());
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        sock.write_all(&conn.take_output()).map_err(io)?;
        let n = sock.read(&mut buf).map_err(io)?;
        if n == 0 {
            return Err(Status::new(code::UNAVAILABLE, "connection closed mid call"));
        }
        let events = conn
            .recv(&buf[..n])
            .map_err(|e| Status::new(code::INTERNAL, e.to_string()))?;
        for ev in events {
            let end = match ev {
                Event::Headers {
                    stream,
                    headers,
                    end_stream,
                } if stream == id => {
                    for h in headers {
                        match h.name.as_slice() {
                            b"grpc-status" => {
                                status = std::str::from_utf8(&h.value)
                                    .ok()
                                    .and_then(|v| v.parse().ok())
                            }
                            b"grpc-message" => message = String::from_utf8_lossy(&h.value).into(),
                            _ => {}
                        }
                    }
                    end_stream
                }
                Event::Data {
                    stream,
                    data,
                    end_stream,
                } if stream == id => {
                    msgs.extend(body.push(&data)?);
                    end_stream
                }
                Event::Reset { stream, code } if stream == id => {
                    return Err(Status::new(
                        code::UNAVAILABLE,
                        format!("stream reset ({code})"),
                    ))
                }
                _ => false,
            };
            if end {
                return match status {
                    Some(code::OK) => msgs
                        .pop()
                        .ok_or_else(|| Status::new(code::INTERNAL, "no response message")),
                    Some(c) => Err(Status::new(c, message)),
                    None => Err(Status::new(code::INTERNAL, "response without grpc-status")),
                };
            }
        }
    }
}

/// Accepts connections on a Unix socket forever, one thread each, with
/// the default [`Options`].
pub fn serve_unix(
    listener: std::os::unix::net::UnixListener,
    service: Arc<dyn Service>,
) -> std::io::Result<()> {
    Server::new(service, Options::default()).serve_unix(listener)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hpack;
    use std::os::unix::net::UnixStream;
    use std::sync::atomic::Ordering::SeqCst;

    struct Echo;

    impl Service for Echo {
        fn is_streaming(&self, method: &str) -> bool {
            method == "/test.Echo/Chat"
        }
        fn unary(&self, method: &str, req: &[u8]) -> Result<Vec<u8>, Status> {
            match method {
                "/test.Echo/Say" => Ok(req.to_vec()),
                "/test.Echo/Panic" => panic!("on purpose"),
                _ => Err(Status::new(code::UNIMPLEMENTED, "no such method: 100%")),
            }
        }
        fn stream(&self, _: &str, requests: Receiver<Vec<u8>>, mut out: Responder) {
            for r in requests {
                out.send(&r);
                out.send(&r);
            }
        }
    }

    /// Unary calls that wait for the test to let them go, and count how
    /// many of them ran.
    struct Gate {
        hold: Mutex<Receiver<()>>,
        runs: AtomicUsize,
    }

    impl Service for Gate {
        fn is_streaming(&self, _: &str) -> bool {
            false
        }
        fn unary(&self, method: &str, _: &[u8]) -> Result<Vec<u8>, Status> {
            if method == "/test.Gate/Hold" {
                let _ = self.hold.lock().unwrap().recv();
            } else {
                self.runs.fetch_add(1, SeqCst);
            }
            Ok(Vec::new())
        }
        fn stream(&self, _: &str, _: Receiver<Vec<u8>>, _: Responder) {}
    }

    fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = (payload.len() as u32).to_be_bytes()[1..].to_vec();
        out.extend([kind, flags]);
        out.extend(stream.to_be_bytes());
        out.extend(payload);
        out
    }

    fn call(stream: u32, path: &str, body: &[u8]) -> Vec<u8> {
        let mut out = open_call(stream, path);
        out.extend(frame(0, 0x1, stream, body));
        out
    }

    fn open_call(stream: u32, path: &str) -> Vec<u8> {
        let mut block = Vec::new();
        hpack::encode(
            &[
                (b":method", b"POST", false),
                (b":scheme", b"http", false),
                (b":path", path.as_bytes(), false),
                (b"content-type", b"application/grpc", false),
            ],
            &mut block,
        );
        frame(1, 0x4, stream, &block)
    }

    fn next_frame(sock: &mut UnixStream) -> (u8, u8, u32, Vec<u8>) {
        let mut h = [0u8; 9];
        sock.read_exact(&mut h).unwrap();
        let len = u32::from_be_bytes([0, h[0], h[1], h[2]]) as usize;
        let mut p = vec![0; len];
        sock.read_exact(&mut p).unwrap();
        (h[3], h[4], u32::from_be_bytes([h[5], h[6], h[7], h[8]]), p)
    }

    /// Skips frames up to the first of `kind` and returns its stream and
    /// payload.
    fn until(sock: &mut UnixStream, kind: u8) -> (u32, Vec<u8>) {
        loop {
            let (k, _, id, p) = next_frame(sock);
            if k == kind {
                return (id, p);
            }
        }
    }

    /// Reads until `stream` ends. Returns the response messages and the
    /// headers seen, trailers last.
    fn response(sock: &mut UnixStream, stream: u32) -> (Vec<Vec<u8>>, Vec<(String, String)>) {
        let mut dec = hpack::Decoder::new(4096, 1 << 20);
        let mut body = Deframer::default();
        let (mut msgs, mut headers) = (Vec::new(), Vec::new());
        loop {
            let (kind, flags, id, p) = next_frame(sock);
            match kind {
                1 => {
                    for x in dec.decode(&p).unwrap() {
                        headers.push((
                            String::from_utf8(x.name).unwrap(),
                            String::from_utf8(x.value).unwrap(),
                        ));
                    }
                }
                0 if id == stream => msgs.extend(body.push(&p).unwrap()),
                _ => {}
            }
            if id == stream && flags & 0x1 != 0 {
                return (msgs, headers);
            }
        }
    }

    fn grpc_status(headers: &[(String, String)]) -> &str {
        let last = headers.iter().rev().find(|(n, _)| n == "grpc-status");
        &last.unwrap().1
    }

    /// A connection to `server` that has not said anything yet.
    fn attach(server: &Arc<Server>) -> UnixStream {
        let (client, sock) = UnixStream::pair().unwrap();
        let server = server.clone();
        std::thread::spawn(move || server.serve_connection(sock));
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        client
    }

    fn connect_to(server: &Arc<Server>) -> UnixStream {
        let mut client = attach(server);
        let mut hello = h2::PREFACE.to_vec();
        hello.extend(frame(4, 0, 0, &[]));
        client.write_all(&hello).unwrap();
        client
    }

    fn connect() -> UnixStream {
        connect_to(&Server::new(Arc::new(Echo), Options::default()))
    }

    /// Opens a Chat call without ending it, and waits for its first echo.
    fn chat(sock: &mut UnixStream, stream: u32) {
        let mut out = open_call(stream, "/test.Echo/Chat");
        out.extend(frame(0, 0, stream, &frame_message(b"hi")));
        sock.write_all(&out).unwrap();
        while until(sock, 0).0 != stream {}
    }

    #[test]
    fn unary_calls_and_errors() {
        let mut c = connect();
        c.write_all(&call(1, "/test.Echo/Say", &frame_message(b"hello")))
            .unwrap();
        let (msgs, headers) = response(&mut c, 1);
        assert_eq!(msgs, [b"hello".to_vec()]);
        assert_eq!(headers.last().unwrap(), &("grpc-status".into(), "0".into()));

        c.write_all(&call(3, "/test.Echo/Nope", &frame_message(b"")))
            .unwrap();
        let (msgs, headers) = response(&mut c, 3);
        assert!(msgs.is_empty());
        let get = |k: &str| {
            headers
                .iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(get("grpc-status"), Some("12"));
        assert_eq!(get("grpc-message"), Some("no such method: 100%25"));
        assert_eq!(get(":status"), Some("200"));
    }

    #[test]
    fn the_client_side_talks_to_the_server_side() {
        let server = Server::new(
            Arc::new(Echo),
            Options {
                unary_threads: 1,
                ..Options::default()
            },
        );
        let big = vec![7u8; 200_000];
        assert_eq!(
            super::call(attach(&server), "/test.Echo/Say", &big),
            Ok(big)
        );
        let err = super::call(attach(&server), "/test.Echo/Nope", b"").unwrap_err();
        assert_eq!(err.code, code::UNIMPLEMENTED);
        let panicked = super::call(attach(&server), "/test.Echo/Panic", b"").unwrap_err();
        assert_eq!(panicked.code, code::INTERNAL);
        let after = super::call(attach(&server), "/test.Echo/Say", b"x");
        assert!(after.is_ok(), "the only pool thread survived the panic");
        assert_eq!(
            (err.code, err.message.as_str()),
            (code::UNIMPLEMENTED, "no such method: 100%25")
        );
    }

    #[test]
    fn a_stream_answers_until_the_client_half_closes() {
        let mut c = connect();
        let mut body = frame_message(b"a");
        body.extend(frame_message(b"bc"));
        c.write_all(&call(1, "/test.Echo/Chat", &body)).unwrap();
        let (msgs, headers) = response(&mut c, 1);
        assert_eq!(
            msgs,
            [b"a".to_vec(), b"a".to_vec(), b"bc".to_vec(), b"bc".to_vec()]
        );
        assert_eq!(headers.last().unwrap().0, "grpc-status");
    }

    #[test]
    fn deframing_across_arbitrary_splits() {
        let mut wire = frame_message(b"one");
        wire.extend(frame_message(b""));
        wire.extend(frame_message(&[9; 300]));
        let mut d = Deframer::default();
        let mut got = Vec::new();
        for chunk in wire.chunks(4) {
            got.extend(d.push(chunk).unwrap());
        }
        assert_eq!(got, [b"one".to_vec(), Vec::new(), vec![9; 300]]);
        assert!(d.push(&[1, 0, 0, 0, 0]).is_err());
    }

    #[test]
    fn reset_calls_do_not_run_and_too_many_resets_end_the_connection() {
        let (release, hold) = mpsc::channel();
        let gate = Arc::new(Gate {
            hold: Mutex::new(hold),
            runs: AtomicUsize::new(0),
        });
        let server = Server::new(
            gate.clone(),
            Options {
                unary_threads: 1,
                limits: h2::Limits {
                    reset_burst: 3,
                    reset_refill: Duration::from_secs(3600),
                    ..h2::Limits::default()
                },
                ..Options::default()
            },
        );
        let mut c = connect_to(&server);
        let count = |id| call(id, "/test.Gate/Count", &frame_message(b""));
        let cancel = |id| frame(3, 0, id, &h2::code::CANCEL.to_be_bytes());
        let mut burst = call(1, "/test.Gate/Hold", &frame_message(b""));
        for id in [3, 5] {
            burst.extend(count(id));
            burst.extend(cancel(id));
        }
        // a zero window increment makes the server reset the stream itself
        burst.extend(count(7));
        burst.extend(frame(8, 0, 7, &0u32.to_be_bytes()));
        burst.extend(frame(6, 0, 0, b"barrier!"));
        c.write_all(&burst).unwrap();
        until(&mut c, 6);
        release.send(()).unwrap();
        response(&mut c, 1);
        c.write_all(&count(9)).unwrap();
        response(&mut c, 9);
        assert_eq!(gate.runs.load(SeqCst), 1, "only the call nobody reset");

        let mut fourth = count(11);
        fourth.extend(cancel(11));
        c.write_all(&fourth).unwrap();
        let (_, goaway) = until(&mut c, 7);
        assert_eq!(goaway[4..8], h2::code::ENHANCE_YOUR_CALM.to_be_bytes());
        assert!(c.read_to_end(&mut Vec::new()).is_ok());
    }

    #[test]
    fn streaming_calls_are_capped_per_connection_and_per_server() {
        let server = Server::new(
            Arc::new(Echo),
            Options {
                max_streaming_per_connection: 1,
                max_streaming: 2,
                ..Options::default()
            },
        );
        let refused = |sock: &mut UnixStream, stream| {
            sock.write_all(&open_call(stream, "/test.Echo/Chat"))
                .unwrap();
            let (_, headers) = response(sock, stream);
            grpc_status(&headers) == code::RESOURCE_EXHAUSTED.to_string()
        };
        let (mut a, mut b, mut c) = (
            connect_to(&server),
            connect_to(&server),
            connect_to(&server),
        );
        chat(&mut a, 1);
        assert!(refused(&mut a, 3), "second call on one connection");
        chat(&mut b, 1);
        assert!(refused(&mut c, 1), "third call on the server");

        a.write_all(&frame(0, 0x1, 1, &[])).unwrap();
        response(&mut a, 1);
        chat(&mut c, 3);
    }

    #[test]
    fn silent_and_idle_connections_are_closed() {
        let server = Server::new(
            Arc::new(Echo),
            Options {
                handshake_timeout: Duration::from_millis(50),
                idle_timeout: Duration::from_millis(50),
                ..Options::default()
            },
        );
        let mut silent = attach(&server);
        assert!(silent.read_to_end(&mut Vec::new()).is_ok());

        let mut c = connect_to(&server);
        chat(&mut c, 1);
        std::thread::sleep(Duration::from_millis(150));
        c.write_all(&frame(0, 0x1, 1, &frame_message(b"x")))
            .unwrap();
        let (msgs, _) = response(&mut c, 1);
        assert!(msgs.contains(&b"x".to_vec()), "an open stream is not idle");
        let (_, goaway) = until(&mut c, 7);
        assert_eq!(goaway[4..8], h2::code::NO_ERROR.to_be_bytes());
        assert!(c.read_to_end(&mut Vec::new()).is_ok());
    }
}
