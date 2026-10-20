//! Decodes a real gzip file and compares the result and the time taken
//! with `gzip -dc`. Run it in release mode with QUANTY_GZIP_CORPUS naming
//! a .gz file, e.g. a 50 MB mix of text and binaries packed with `gzip -6`:
//!
//! ```text
//! QUANTY_GZIP_CORPUS=/tmp/mix.gz cargo test --release --test inflate_corpus -- --nocapture
//! ```

use quantycore::inflate::GzipReader;
use std::io::{self, Read};
use std::process::{Command, Stdio};
use std::time::Instant;

#[test]
fn a_large_file_decodes_like_gzip_does() {
    let Ok(path) = std::env::var("QUANTY_GZIP_CORPUS") else {
        eprintln!("QUANTY_GZIP_CORPUS not set, corpus not run");
        return;
    };
    let compressed = std::fs::read(&path).unwrap();

    let start = Instant::now();
    let mut ours = GzipReader::new(&compressed[..]);
    let size = io::copy(&mut ours, &mut io::sink()).unwrap();
    let ours_secs = start.elapsed().as_secs_f64();

    let start = Instant::now();
    let status = Command::new("gzip")
        .arg("-dc")
        .arg(&path)
        .stdout(Stdio::null())
        .status()
        .unwrap();
    let gzip_secs = start.elapsed().as_secs_f64();
    assert!(status.success());

    let mut child = Command::new("gzip")
        .arg("-dc")
        .arg(&path)
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut theirs = child.stdout.take().unwrap();
    let mut ours = GzipReader::new(&compressed[..]);
    let (mut a, mut b) = (vec![0; 1 << 16], vec![0; 1 << 16]);
    let mut at = 0u64;
    loop {
        let n = ours.read(&mut a).unwrap();
        theirs.read_exact(&mut b[..n]).unwrap();
        assert!(a[..n] == b[..n], "output differs near byte {at}");
        at += n as u64;
        if n == 0 {
            assert_eq!(theirs.read(&mut b).unwrap(), 0, "gzip produced more");
            break;
        }
    }
    assert!(child.wait().unwrap().success());

    let mb = size as f64 / 1e6;
    eprintln!(
        "{mb:.1} MB out of {:.1} MB: {:.0} MB/s here, {:.0} MB/s gzip -dc",
        compressed.len() as f64 / 1e6,
        mb / ours_secs,
        mb / gzip_secs
    );
}
