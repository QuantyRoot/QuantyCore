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

#[derive(Clone, Copy)]
enum Kind {
    Ed25519,
    P256,
    Rsa,
}

/// A key of `kind`. RSA keys come from OpenSSL, since this crate does not
/// generate them; that also checks that OpenSSL's PKCS#8 loads here.
fn new_key(kind: Kind, dir: &std::path::Path) -> PrivateKey {
    match kind {
        Kind::Ed25519 => PrivateKey::generate_ed25519().unwrap(),
        Kind::P256 => PrivateKey::generate_ec(quantycore::tls::crypto::ec::Curve::P256).unwrap(),
        Kind::Rsa => {
            let path = dir.join("rsa-gen.key");
            let st = Command::new("openssl")
                .args([
                    "genpkey",
                    "-algorithm",
                    "RSA",
                    "-pkeyopt",
                    "rsa_keygen_bits:2048",
                    "-out",
                ])
                .arg(&path)
                .stderr(Stdio::null())
                .status()
                .unwrap();
            assert!(st.success());
            PrivateKey::from_pem(&std::fs::read_to_string(&path).unwrap()).unwrap()
        }
    }
}

fn pki_of(tag: &str, kind: Kind) -> Pki {
    let dir = std::env::temp_dir().join(format!("quanty-interop-{tag}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let t = now();
    let root_key = new_key(kind, &dir);
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
    let server_key = new_key(kind, &dir);
    let client_key = new_key(kind, &dir);
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
    client_against_s_server_with(mtls, Kind::Ed25519, false);
}

fn version_flag(tls12: bool) -> &'static str {
    if tls12 {
        "-tls1_2"
    } else {
        "-tls1_3"
    }
}

fn client_against_s_server_with(mtls: bool, kind: Kind, tls12: bool) {
    client_against_s_server_cipher(mtls, kind, tls12, None);
}

/// With `cipher`, s_server is limited to that one TLS 1.2 suite, given
/// by its OpenSSL name and its number.
fn client_against_s_server_cipher(
    mtls: bool,
    kind: Kind,
    tls12: bool,
    cipher: Option<(&str, u16)>,
) {
    let p = pki_of(if mtls { "c-mtls" } else { "c" }, kind);
    let port = free_port();
    let mut cmd = Command::new("openssl");
    cmd.args([
        "s_server",
        "-quiet",
        "-www",
        version_flag(tls12),
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
    if let Some((name, _)) = cipher {
        cmd.args(["-cipher", name]);
    }
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
    if tls12 {
        config.enable_tls12();
    }
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
    let (name, v) = if tls12 {
        ("TLSv1.2", 0x0303)
    } else {
        ("TLSv1.3", 0x0304)
    };
    assert!(page.contains(name), "{page}");
    assert_eq!(s.connection().protocol_version(), Some(v));
    // OpenSSL before 3.5 has no ML-KEM and takes the X25519 share.
    let g = s.connection().key_exchange_group().unwrap();
    assert!(g == 0x001d || (g == 0x11ec && !tls12), "group {g:#x}");
    if let Some((_, id)) = cipher {
        assert_eq!(s.connection().cipher_suite(), Some(id));
    }
}

/// `openssl s_client` against our server, which echoes one line back
/// upper case and closes.
fn s_client_against_server(mtls: bool) {
    s_client_against_server_with(mtls, Kind::Ed25519, false);
}

fn s_client_against_server_with(mtls: bool, kind: Kind, tls12: bool) {
    let p = pki_of(if mtls { "s-mtls" } else { "s" }, kind);
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
    if tls12 {
        config.enable_tls12();
    }
    let config = Arc::new(config);
    let server = std::thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        tcp.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        let mut s = Stream::new(ServerConnection::new(config), tcp);
        s.handshake().unwrap();
        let peer = s.connection().peer_certificates().map(|c| c.len());
        let version = s.connection().protocol_version();
        let mut line = String::new();
        BufReader::new(&mut s).read_line(&mut line).unwrap();
        s.write_all(line.to_uppercase().as_bytes()).unwrap();
        s.close().unwrap();
        (peer, version)
    });
    let mut cmd = Command::new("openssl");
    cmd.args([
        "s_client",
        "-quiet",
        version_flag(tls12),
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
    let (peer, version) = server.join().unwrap();
    assert_eq!(peer.is_some_and(|n| n >= 1), mtls);
    assert_eq!(version, Some(if tls12 { 0x0303 } else { 0x0304 }));
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
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

func export(c *tls.Conn) string {
	st := c.ConnectionState()
	k, err := st.ExportKeyingMaterial("EXPORTER-test", []byte("ctx"), 32)
	if err != nil { panic(err) }
	return hex.EncodeToString(k)
}

func main() {
	mode, addr, dir, mtls := os.Args[1], os.Args[2], os.Args[3], os.Args[4] == "1"
	var version uint16 = tls.VersionTLS13
	if os.Args[5] == "12" {
		version = tls.VersionTLS12
	}
	pool := x509.NewCertPool()
	root, _ := os.ReadFile(dir + "/root.pem")
	pool.AppendCertsFromPEM(root)
	if mode == "client" {
		cfg := &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: version, MaxVersion: version}
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
		fmt.Println(export(conn))
		return
	}
	c, err := tls.LoadX509KeyPair(dir+"/server.pem", dir+"/server.key")
	if err != nil { panic(err) }
	cfg := &tls.Config{Certificates: []tls.Certificate{c}, MinVersion: version, MaxVersion: version, NextProtos: []string{"h2"}}
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
	fmt.Fprintln(conn, export(conn.(*tls.Conn)))
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

fn exported(c: &quantycore::tls::Connection) -> String {
    c.export_keying_material(b"EXPORTER-test", b"ctx", 32)
        .unwrap()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn go_both_ways(mtls: bool) {
    go_both_ways_with(mtls, Kind::Ed25519, false);
}

fn go_both_ways_with(mtls: bool, kind: Kind, tls12: bool) {
    let p = pki_of(if mtls { "go-mtls" } else { "go" }, kind);
    let Some(bin) = go_program(&p) else {
        return;
    };
    let m = if mtls { "1" } else { "0" };
    let v = if tls12 { "12" } else { "13" };

    // Go server, our client.
    let port = free_port();
    let mut child = Command::new(&bin)
        .args([
            "server",
            &format!("127.0.0.1:{port}"),
            p.dir.to_str().unwrap(),
            m,
            v,
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
    if tls12 {
        config.enable_tls12();
    }
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
    let mut r = BufReader::new(&mut s);
    r.read_line(&mut back).unwrap();
    assert_eq!(back, "HELLO FROM QUANTY\n");
    // Both sides export the same keying material (RFC 5705, RFC 8446
    // 7.5).
    let mut theirs = String::new();
    r.read_line(&mut theirs).unwrap();
    assert_eq!(theirs.trim(), exported(s.connection()));
    assert_eq!(s.connection().alpn_protocol(), Some(&b"h2"[..]));
    assert_eq!(
        s.connection().protocol_version(),
        Some(if tls12 { 0x0303 } else { 0x0304 })
    );
    // Go has X25519MLKEM768 on by default since 1.24; TLS 1.2 falls back
    // to X25519.
    let group = if tls12 { 0x001d } else { 0x11ec };
    assert_eq!(s.connection().key_exchange_group(), Some(group));

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
    if tls12 {
        config.enable_tls12();
    }
    let config = Arc::new(config);
    let server = std::thread::spawn(move || {
        let (tcp, _) = listener.accept().unwrap();
        let mut s = Stream::new(ServerConnection::new(config), tcp);
        let mut line = String::new();
        BufReader::new(&mut s).read_line(&mut line).unwrap();
        s.write_all(line.to_uppercase().as_bytes()).unwrap();
        s.close().unwrap();
        assert_eq!(s.connection().key_exchange_group(), Some(group));
        exported(s.connection())
    });
    let out = Command::new(&bin)
        .args([
            "client",
            &format!("127.0.0.1:{port}"),
            p.dir.to_str().unwrap(),
            m,
            v,
        ])
        .output()
        .unwrap();
    let ours = server.join().unwrap();
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        format!("HELLO FROM GO\n{ours}\n"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
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

#[test]
#[ignore]
fn openssl_with_p256_and_rsa() {
    for kind in [Kind::P256, Kind::Rsa] {
        client_against_s_server_with(true, kind, false);
        s_client_against_server_with(true, kind, false);
    }
}

#[test]
#[ignore]
fn openssl_tls12() {
    for kind in [Kind::Ed25519, Kind::P256, Kind::Rsa] {
        for mtls in [false, true] {
            client_against_s_server_with(mtls, kind, true);
            s_client_against_server_with(mtls, kind, true);
        }
    }
    let suites = [
        (Kind::P256, "ECDHE-ECDSA-CHACHA20-POLY1305", 0xcca9),
        (Kind::P256, "ECDHE-ECDSA-AES128-GCM-SHA256", 0xc02b),
        (Kind::P256, "ECDHE-ECDSA-AES256-GCM-SHA384", 0xc02c),
        (Kind::Rsa, "ECDHE-RSA-CHACHA20-POLY1305", 0xcca8),
        (Kind::Rsa, "ECDHE-RSA-AES128-GCM-SHA256", 0xc02f),
        (Kind::Rsa, "ECDHE-RSA-AES256-GCM-SHA384", 0xc030),
    ];
    for (kind, name, id) in suites {
        client_against_s_server_cipher(false, kind, true, Some((name, id)));
    }
}

#[test]
#[ignore]
fn go_tls12() {
    for kind in [Kind::P256, Kind::Rsa] {
        for mtls in [false, true] {
            go_both_ways_with(mtls, kind, true);
        }
    }
}

#[test]
#[ignore]
fn go_with_p256_and_rsa() {
    for kind in [Kind::P256, Kind::Rsa] {
        go_both_ways_with(true, kind, false);
    }
}
