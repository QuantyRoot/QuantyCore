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

/// The built-in RuntimeDefault is byte for byte what containerd renders,
/// on a host with the profile directory and on one without; the profiles
/// containerd renders are in the corpus and compared with upstream's
/// automata by apparmor_diff.
#[test]
fn runtime_default_is_containerds() {
    use quantycore::apparmor::runtime_default::{RuntimeDefault, NAME};
    let Some(corpus) = std::env::var_os("QUANTY_APPARMOR_CORPUS") else {
        if std::env::var_os("QUANTY_VECTORS_REQUIRED").is_some() {
            panic!("QUANTY_APPARMOR_CORPUS not set but QUANTY_VECTORS_REQUIRED is");
        }
        eprintln!("QUANTY_APPARMOR_CORPUS not set, skipping");
        return;
    };
    let base = PathBuf::from(corpus).join("containers/etc/apparmor.d");
    let mut resolver = FsResolver::new(vec![base.clone()], base.clone());
    let host = RuntimeDefault::for_host(&mut resolver, NAME, None);
    let want = std::fs::read_to_string(base.join(NAME)).unwrap();
    assert_eq!(host.render(), want);
    let want = std::fs::read_to_string(base.join("containerd-bare")).unwrap();
    assert_eq!(RuntimeDefault::bare("containerd-bare").render(), want);
    let p = host.compile(&mut resolver, &Options::default()).unwrap();
    assert_eq!(p.profiles.len(), 1);
    eprintln!("2 renderings equal to containerd's");
}
