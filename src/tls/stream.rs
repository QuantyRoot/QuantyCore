//! A blocking TLS stream over anything that is `Read + Write`, such as a
//! `TcpStream`. It only moves bytes between the transport and the
//! connection; all TLS logic stays in the connection.

use super::conn::Connection;
use std::io::{self, Read, Write};
use std::ops::DerefMut;

pub struct Stream<C, T> {
    conn: C,
    io: T,
    eof: bool,
}

impl<C: DerefMut<Target = Connection>, T: Read + Write> Stream<C, T> {
    pub fn new(conn: C, io: T) -> Stream<C, T> {
        Stream {
            conn,
            io,
            eof: false,
        }
    }

    pub fn connection(&self) -> &C {
        &self.conn
    }

    pub fn get_ref(&self) -> &T {
        &self.io
    }

    fn flush_tls(&mut self) -> io::Result<()> {
        let out = self.conn.take_tls();
        if !out.is_empty() {
            self.io.write_all(&out)?;
            self.io.flush()?;
        }
        Ok(())
    }

    /// Reads from the transport once and feeds the connection. A
    /// transport that ends before close_notify is an error: without it, a
    /// truncation attack looks like a short message.
    fn read_tls_once(&mut self) -> io::Result<()> {
        let mut buf = [0u8; 16 * 1024 + 512];
        let n = self.io.read(&mut buf)?;
        if n == 0 {
            self.eof = true;
            if !self.conn.is_peer_closed() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "connection ended without close_notify",
                ));
            }
            return Ok(());
        }
        let r = self.conn.read_tls(&buf[..n]);
        // An alert queued by a failure still goes out.
        let _ = self.flush_tls();
        r.map_err(io::Error::from)
    }

    /// Runs the handshake to its end.
    pub fn handshake(&mut self) -> io::Result<()> {
        self.flush_tls()?;
        while self.conn.is_handshaking() {
            self.read_tls_once()?;
            self.flush_tls()?;
        }
        Ok(())
    }

    /// Sends close_notify. The transport stays open for the caller to
    /// shut down.
    pub fn close(&mut self) -> io::Result<()> {
        self.conn.close();
        self.flush_tls()
    }
}

impl<C: DerefMut<Target = Connection>, T: Read + Write> Read for Stream<C, T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.handshake()?;
        loop {
            let n = self.conn.read(buf);
            if n > 0 || buf.is_empty() {
                return Ok(n);
            }
            if self.conn.is_peer_closed() || self.eof {
                return Ok(0);
            }
            self.read_tls_once()?;
            self.flush_tls()?;
        }
    }
}

impl<C: DerefMut<Target = Connection>, T: Read + Write> Write for Stream<C, T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.handshake()?;
        self.conn.write(buf).map_err(io::Error::from)?;
        self.flush_tls()?;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.flush_tls()
    }
}
