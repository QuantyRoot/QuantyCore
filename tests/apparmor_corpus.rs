//! Real profiles: what Ubuntu 24.04 and Debian 13 ship in their apparmor
//! and apparmor-profiles packages, upstream's own profiles, and the
//! default profiles of Docker, containerd and CRI-O as those render them.
//! `tests/apparmor_fetch_corpus.sh` builds the tree at pinned versions and
//! CI points `QUANTY_APPARMOR_CORPUS` at it.
//!
//! Upstream's `apparmor_parser` accepts every one of these files, so every
//! one must pass here, with its includes resolved from its own tree.

use std::path::{Path, PathBuf};

use quantycore::apparmor::{check, FsResolver, Options};

/// Ubuntu 115, Debian 116, upstream 198, containers 6 at the pinned
/// versions.
const MIN_FILES: usize = 430;

const ROOTS: &[&str] = &["ubuntu-24.04", "debian-13", "upstream", "containers"];

fn profiles(dir: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_file())
        .collect();
    out.sort();
    out
}

#[test]
fn corpus() {
    let Some(corpus) = std::env::var_os("QUANTY_APPARMOR_CORPUS") else {
        if std::env::var_os("QUANTY_VECTORS_REQUIRED").is_some() {
            panic!("QUANTY_APPARMOR_CORPUS not set but QUANTY_VECTORS_REQUIRED is");
        }
        eprintln!("QUANTY_APPARMOR_CORPUS not set, skipping");
        return;
    };
    let corpus = PathBuf::from(corpus);
    let mut checked = 0;
    let mut failed = Vec::new();
    let opts = Options::default();
    for root in ROOTS {
        let base = corpus.join(root).join("etc/apparmor.d");
        for path in profiles(&base) {
            let text = std::fs::read(&path).unwrap();
            let mut resolver = FsResolver::new(vec![base.clone()], base.clone());
            let name = path
                .strip_prefix(&corpus)
                .unwrap()
                .to_string_lossy()
                .into_owned();
            if let Err(e) = check(&mut resolver, &name, text, &opts) {
                failed.push(format!("{e}"));
            }
            checked += 1;
        }
    }
    eprintln!("{checked} profiles checked, {} refused", failed.len());
    for f in &failed {
        eprintln!("refused: {f}");
    }
    assert!(
        checked >= MIN_FILES,
        "only {checked} profiles found under {}",
        corpus.display()
    );
    assert!(failed.is_empty(), "{} real profiles refused", failed.len());
}
