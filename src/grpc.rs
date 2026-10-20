//! gRPC over [`crate::h2`], server side, on blocking sockets.
//!
//! One thread reads each connection. Unary calls run on a shared pool of
//! workers; each streaming call gets a thread of its own, since streams
//! such as watches live for hours and would otherwise starve the pool.

use crate::h2::{self, Connection, Event, Settings};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Condvar, Mutex};

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
}

impl Socket for std::os::unix::net::UnixStream {
    fn try_clone(&self) -> std::io::Result<Self> {
        std::os::unix::net::UnixStream::try_clone(self)
    }
}

impl Socket for std::net::TcpStream {
    fn try_clone(&self) -> std::io::Result<Self> {
        std::net::TcpStream::try_clone(self)
    }
}

struct Shared<S> {
    conn: Connection,
    writer: S,
    alive: bool,
}

struct Link<S> {
    shared: Mutex<Shared<S>>,
    drained: Condvar,
}

impl<S: Socket> Link<S> {
    /// Applies `f` to the connection and writes whatever it produced.
    fn with<R>(&self, f: impl FnOnce(&mut Connection) -> R) -> R {
        let mut g = self.shared.lock().unwrap_or_else(|e| e.into_inner());
        let r = f(&mut g.conn);
        let out = g.conn.take_output();
        if !out.is_empty() && g.alive && g.writer.write_all(&out).is_err() {
            g.alive = false;
        }
        r
    }
}

trait Sink: Send + Sync {
    fn send(&self, stream: u32, msg: &[u8], started: bool) -> bool;
    fn finish(&self, stream: u32, status: &Status, started: bool);
}

impl<S: Socket> Sink for Link<S> {
    fn send(&self, stream: u32, msg: &[u8], started: bool) -> bool {
        {
            let mut g = self.shared.lock().unwrap_or_else(|e| e.into_inner());
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
        self.finished = true;
        self.sink.finish(self.stream, &status, self.started);
    }
}

impl Drop for Responder {
    fn drop(&mut self) {
        if !self.finished {
            self.sink
                .finish(self.stream, &Status::new(code::OK, ""), self.started);
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
pub struct Pool {
    jobs: Mutex<Sender<Job>>,
}

impl Pool {
    pub fn new(threads: usize) -> Arc<Pool> {
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

/// Serves one connection until the peer goes away. Blocks the calling
/// thread.
pub fn serve_connection<S: Socket>(socket: S, service: Arc<dyn Service>, pool: Arc<Pool>) {
    let Ok(writer) = socket.try_clone() else {
        return;
    };
    let mut reader = socket;
    let link = Arc::new(Link {
        shared: Mutex::new(Shared {
            conn: Connection::server(Settings::default()),
            writer,
            alive: true,
        }),
        drained: Condvar::new(),
    });
    link.with(|_| ());
    let mut calls: HashMap<u32, Call> = HashMap::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = match reader.read(&mut buf) {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let events = link.with(|c| c.recv(&buf[..n]));
        link.drained.notify_all();
        let Ok(events) = events else { break };
        for ev in events {
            handle(ev, &mut calls, &link, &service, &pool);
        }
        if link.with(|c| c.is_closed()) {
            break;
        }
    }
    let mut g = link.shared.lock().unwrap_or_else(|e| e.into_inner());
    g.alive = false;
    drop(g);
    link.drained.notify_all();
}

fn handle<S: Socket>(
    ev: Event,
    calls: &mut HashMap<u32, Call>,
    link: &Arc<Link<S>>,
    service: &Arc<dyn Service>,
    pool: &Arc<Pool>,
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
                    end_of_requests(stream, calls, sink, service, pool);
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
            let call = if service.is_streaming(&method) {
                let (tx, rx) = mpsc::channel();
                let responder = Responder {
                    sink,
                    stream,
                    started: false,
                    finished: false,
                };
                let service = service.clone();
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
                end_of_requests(stream, calls, link.clone(), service, pool);
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
                end_of_requests(stream, calls, sink, service, pool);
            }
        }
        Event::Reset { stream, .. } => {
            calls.remove(&stream);
        }
        Event::GoAway { .. } => {}
    }
}

fn end_of_requests(
    stream: u32,
    calls: &mut HashMap<u32, Call>,
    sink: Arc<dyn Sink>,
    service: &Arc<dyn Service>,
    pool: &Arc<Pool>,
) {
    match calls.remove(&stream) {
        Some(Call::Unary { method, msgs, .. }) => {
            let service = service.clone();
            pool.run(Box::new(move || {
                let result = match msgs.as_slice() {
                    [one] => service.unary(&method, one),
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

/// Accepts connections on a Unix socket forever, one thread each.
pub fn serve_unix(
    listener: std::os::unix::net::UnixListener,
    service: Arc<dyn Service>,
) -> std::io::Result<()> {
    let pool = Pool::new(std::thread::available_parallelism().map_or(4, |n| n.get() * 2));
    for socket in listener.incoming() {
        let socket = socket?;
        let (service, pool) = (service.clone(), pool.clone());
        std::thread::spawn(move || serve_connection(socket, service, pool));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hpack;
    use std::os::unix::net::UnixStream;

    struct Echo;

    impl Service for Echo {
        fn is_streaming(&self, method: &str) -> bool {
            method == "/test.Echo/Chat"
        }
        fn unary(&self, method: &str, req: &[u8]) -> Result<Vec<u8>, Status> {
            match method {
                "/test.Echo/Say" => Ok(req.to_vec()),
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

    fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = (payload.len() as u32).to_be_bytes()[1..].to_vec();
        out.extend([kind, flags]);
        out.extend(stream.to_be_bytes());
        out.extend(payload);
        out
    }

    fn call(stream: u32, path: &str, body: &[u8]) -> Vec<u8> {
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
        let mut out = frame(1, 0x4, stream, &block);
        out.extend(frame(0, 0x1, stream, body));
        out
    }

    /// Reads until `stream` ends. Returns the response messages and the
    /// headers seen, trailers last.
    fn response(sock: &mut UnixStream, stream: u32) -> (Vec<Vec<u8>>, Vec<(String, String)>) {
        let mut dec = hpack::Decoder::new(4096, 1 << 20);
        let mut body = Deframer::default();
        let (mut msgs, mut headers) = (Vec::new(), Vec::new());
        loop {
            let mut h = [0u8; 9];
            sock.read_exact(&mut h).unwrap();
            let len = u32::from_be_bytes([0, h[0], h[1], h[2]]) as usize;
            let mut p = vec![0; len];
            sock.read_exact(&mut p).unwrap();
            let id = u32::from_be_bytes([h[5], h[6], h[7], h[8]]);
            match h[3] {
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
            if id == stream && h[4] & 0x1 != 0 {
                return (msgs, headers);
            }
        }
    }

    fn connect() -> UnixStream {
        let (client, server) = UnixStream::pair().unwrap();
        let pool = Pool::new(2);
        std::thread::spawn(move || serve_connection(server, Arc::new(Echo), pool));
        let mut client = client;
        let mut hello = h2::PREFACE.to_vec();
        hello.extend(frame(4, 0, 0, &[]));
        client.write_all(&hello).unwrap();
        client
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
        let (client, server) = UnixStream::pair().unwrap();
        let pool = Pool::new(1);
        std::thread::spawn(move || serve_connection(server, Arc::new(Echo), pool));
        let big = vec![7u8; 200_000];
        assert_eq!(super::call(&client, "/test.Echo/Say", &big), Ok(big));
        let (client, server) = UnixStream::pair().unwrap();
        std::thread::spawn(move || serve_connection(server, Arc::new(Echo), Pool::new(1)));
        let err = super::call(&client, "/test.Echo/Nope", b"").unwrap_err();
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
}
