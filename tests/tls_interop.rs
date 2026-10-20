//! Interoperability with OpenSSL (`s_client`, `s_server`) and Go's
//! `crypto/tls`, over real TCP connections, in both directions, with and
//! without client certificates.
//!
//! The certificates are issued by this crate for each run, so the peers
//! also check that what is issued here is acceptable to them. Needs the
//! `openssl` and, for the Go tests, `go` binaries; ignored by default and
//! run in their own CI job.

use quantycore::tls::x509::build::{issue, Issuer, Params, SanEntry};
use quantycore::tls::x509::{pem, PrivateKey, RootStore};
use quantycore::tls::{ClientConfig, ClientConnection, ServerConfig, ServerConnection, Stream};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct Pki {
    dir: PathBuf,
    root: Vec<u8>,
    server_chain: Vec<Vec<u8>>,
    server_key: PrivateKey,
    client_chain: Vec<Vec<u8>>,
    client_key: PrivateKey,
}

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

fn pki(tag: &str) -> Pki {
    let dir = std::env::temp_dir().join(format!("quanty-interop-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let t = now();
    let root_key = PrivateKey::generate_ed25519().unwrap();
    let root = issue(
        &Params::ca("Interop Root", t - 3600, t + 86400),
        &root_key.public_spki(),
        None,
        &root_key,
    )
    .unwrap();
    let issuer = Issuer::from_certificate(&root, &root_key).unwrap();
    let leaf = |cn: &str, key: &PrivateKey| {
        let p = Params::end_entity(
            cn,
            vec![
                SanEntry::Dns("localhost".into()),
                SanEntry::Ip("127.0.0.1".parse().unwrap()),
            ],
            t - 3600,
            t + 86400,
        );
        issue(&p, &key.public_spki(), Some(&issuer), &root_key).unwrap()
    };
    let server_key = PrivateKey::generate_ed25519().unwrap();
    let client_key = PrivateKey::generate_ed25519().unwrap();
    let server = leaf("server", &server_key);
    let client = leaf("client", &client_key);
    let write = |name: &str, s: String| std::fs::write(dir.join(name), s).unwrap();
    write("root.pem", pem::encode("CERTIFICATE", &root));
    write("server.pem", pem::encode("CERTIFICATE", &server));
    write("server.key", server_key.to_pem());
    write("client.pem", pem::encode("CERTIFICATE", &client));
    write("client.key", client_key.to_pem());
    Pki {
        dir,
        root,
        server_chain: vec![server],
        server_key,
        client_chain: vec![client],
        client_key,
    }
}

impl Pki {
    fn path(&self, f: &str) -> String {
        self.dir.join(f).to_str().unwrap().to_string()
    }
    fn roots(&self) -> RootStore {
        let mut r = RootStore::new();
        r.add_der(&self.root).unwrap();
        r
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Kills the child when dropped, so a failing test leaves nothing
/// running.
struct Guard(Child);

impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn connect_retry(port: u16) -> TcpStream {
    for _ in 0..100 {
        if let Ok(s) = TcpStream::connect(("127.0.0.1", port)) {
            s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
            return s;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("peer did not start listening on {port}");
}

/// Our client against `openssl s_server -www`, which answers an HTTP
/// request with a page describing the connection.
fn client_against_s_server(mtls: bool) {
    let p = pki(if mtls { "c-mtls" } else { "c" });
    let port = free_port();
    let mut cmd = Command::new("openssl");
    cmd.args([
        "s_server",
        "-quiet",
        "-www",
        "-tls1_3",
        "-accept",
        &port.to_string(),
    ])
    .args([
        "-cert",
        &p.path("server.pem"),
        "-key",
        &p.path("server.key"),
    ])
    .args(["-alpn", "h2"]);
    if mtls {
        cmd.args([
            "-Verify",
            "1",
            "-verify_return_error",
            "-CAfile",
            &p.path("root.pem"),
        ]);
    }
    let _server = Guard(
        cmd.stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("openssl"),
    );
    let tcp = connect_retry(port);

    let mut config = ClientConfig::new(p.roots());
    config.set_alpn(&[b"h2"]);
    if mtls {
        config.set_client_certificate(
            p.client_chain.clone(),
            PrivateKey::from_pem(&std::fs::read_to_string(p.path("client.key")).unwrap()).unwrap(),
        );
    }
    let conn = ClientConnection::new(Arc::new(config), "localhost").unwrap();
    let mut s = Stream::new(conn, tcp);
    s.handshake().unwrap();
    assert_eq!(s.connection().alpn_protocol(), Some(&b"h2"[..]));
    s.write_all(b"GET / HTTP/1.0\r\n\r\n").unwrap();
    let mut page = String::new();
    let _ = s.read_to_string(&mut page);
    assert!(page.starts_with("HTTP/1.0 200 ok"), "{page}");
    assert!(page.contains("TLSv1.3"), "{page}");
}

/// `openssl s_client` against our server, which echoes one line back
/// upper case and closes.
fn s_client_against_server(mtls: bool) {
    let p = pki(if mtls { "s-mtls" } else { "s" });
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut config = ServerConfig::new(
        p.server_chain.clone(),
        PrivateKey::from_pem(&p.server_key.to_pem()).unwrap(),
    )
    .unwrap();
    if mtls {
        config.require_client_certificates(p.roots());
    }
    let config = Arc::new(config);
    let server = std::thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut s = Stream::new(ServerConnection::new(config), tcp);
        s.handshake().unwrap();
        let peer = s.connection().peer_certificates().map(|c| c.len());
        let mut line = String::new();
        BufReader::new(&mut s).read_line(&mut line).unwrap();
        s.write_all(line.to_uppercase().as_bytes()).unwrap();
        s.close().unwrap();
        peer
    });
    let mut cmd = Command::new("openssl");
    cmd.args([
        "s_client",
        "-quiet",
        "-tls1_3",
        "-connect",
        &format!("127.0.0.1:{port}"),
    ])
    .args(["-servername", "localhost", "-verify_hostname", "localhost"])
    .args(["-CAfile", &p.path("root.pem"), "-verify_return_error"]);
    if mtls {
        cmd.args([
            "-cert",
            &p.path("client.pem"),
            "-key",
            &p.path("client.key"),
        ]);
    }
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("openssl");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"hello from openssl\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("HELLO FROM OPENSSL"),
        "stdout {stdout}\nstderr {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // s_client sends the root along with its certificate; the chain is
    // valid either way.
    let peer = server.join().unwrap();
    assert_eq!(peer.is_some_and(|n| n >= 1), mtls);
}

#[test]
#[ignore]
fn openssl_server() {
    client_against_s_server(false);
}

#[test]
#[ignore]
fn openssl_server_mtls() {
    client_against_s_server(true);
}

#[test]
#[ignore]
fn openssl_client() {
    s_client_against_server(false);
}

#[test]
#[ignore]
fn openssl_client_mtls() {
    s_client_against_server(true);
}

const GO_PEER: &str = r#"package main

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"
)

func main() {
	mode, addr, dir, mtls := os.Args[1], os.Args[2], os.Args[3], os.Args[4] == "1"
	pool := x509.NewCertPool()
	root, _ := os.ReadFile(dir + "/root.pem")
	pool.AppendCertsFromPEM(root)
	if mode == "client" {
		cfg := &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS13}
		if mtls {
			c, err := tls.LoadX509KeyPair(dir+"/client.pem", dir+"/client.key")
			if err != nil { panic(err) }
			cfg.Certificates = []tls.Certificate{c}
		}
		conn, err := tls.Dial("tcp", addr, cfg)
		if err != nil { panic(err) }
		fmt.Fprintf(conn, "hello from go\n")
		line, err := bufio.NewReader(conn).ReadString('\n')
		if err != nil { panic(err) }
		fmt.Print(line)
		return
	}
	c, err := tls.LoadX509KeyPair(dir+"/server.pem", dir+"/server.key")
	if err != nil { panic(err) }
	cfg := &tls.Config{Certificates: []tls.Certificate{c}, MinVersion: tls.VersionTLS13, NextProtos: []string{"h2"}}
	if mtls {
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
		cfg.ClientCAs = pool
	}
	ln, err := tls.Listen("tcp", addr, cfg)
	if err != nil { panic(err) }
	fmt.Println("ready")
	conn, err := ln.Accept()
	if err != nil { panic(err) }
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil { panic(err) }
	fmt.Fprint(conn, strings.ToUpper(line))
	conn.Close()
}
"#;

fn go_program(p: &Pki) -> Option<PathBuf> {
    if Command::new("go").arg("version").output().is_err() {
        eprintln!("go not installed, Go interop not run");
        return None;
    }
    let src = p.dir.join("peer.go");
    std::fs::write(&src, GO_PEER).unwrap();
    let bin = p.dir.join("peer");
    let st = Command::new("go")
        .args(["build", "-o"])
        .arg(&bin)
        .arg(&src)
        .status()
        .unwrap();
    assert!(st.success(), "go build failed");
    Some(bin)
}

fn go_both_ways(mtls: bool) {
    let p = pki(if mtls { "go-mtls" } else { "go" });
    let Some(bin) = go_program(&p) else {
        return;
    };
    let m = if mtls { "1" } else { "0" };

    // Go server, our client.
    let port = free_port();
    let mut child = Command::new(&bin)
        .args([
            "server",
            &format!("127.0.0.1:{port}"),
            p.dir.to_str().unwrap(),
            m,
        ])
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut ready = String::new();
    BufReader::new(child.stdout.as_mut().unwrap())
        .read_line(&mut ready)
        .unwrap();
    let _g = Guard(child);
    let mut config = ClientConfig::new(p.roots());
    config.set_alpn(&[b"h2"]);
    if mtls {
        config.set_client_certificate(
            p.client_chain.clone(),
            PrivateKey::from_pem(&p.client_key.to_pem()).unwrap(),
        );
    }
    let mut s = Stream::new(
        ClientConnection::new(Arc::new(config), "localhost").unwrap(),
        connect_retry(port),
    );
    s.write_all(b"hello from quanty\n").unwrap();
    let mut back = String::new();
    BufReader::new(&mut s).read_line(&mut back).unwrap();
    assert_eq!(back, "HELLO FROM QUANTY\n");
    assert_eq!(s.connection().alpn_protocol(), Some(&b"h2"[..]));

    // Our server, Go client.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut config = ServerConfig::new(
        p.server_chain.clone(),
        PrivateKey::from_pem(&p.server_key.to_pem()).unwrap(),
    )
    .unwrap();
    if mtls {
        config.require_client_certificates(p.roots());
    }
    let config = Arc::new(config);
    let server = std::thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let mut s = Stream::new(ServerConnection::new(config), tcp);
        let mut line = String::new();
        BufReader::new(&mut s).read_line(&mut line).unwrap();
        s.write_all(line.to_uppercase().as_bytes()).unwrap();
        s.close().unwrap();
    });
    let out = Command::new(&bin)
        .args([
            "client",
            &format!("127.0.0.1:{port}"),
            p.dir.to_str().unwrap(),
            m,
        ])
        .output()
        .unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "HELLO FROM GO\n",
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    server.join().unwrap();
}

#[test]
#[ignore]
fn go_crypto_tls() {
    go_both_ways(false);
}

#[test]
#[ignore]
fn go_crypto_tls_mtls() {
    go_both_ways(true);
}
