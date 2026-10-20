//! The compiler against `apparmor_parser`: every case of upstream's
//! simple_tests that both accept is compiled by both, and each automaton
//! is compared with upstream's by walking the two together over every
//! input byte and the out of band symbol. Where the walk reaches a pair
//! of states, both must grant the same permissions; so the automata match
//! the same paths with the same permissions, however their states are
//! numbered or their tables packed.
//!
//! `QUANTY_APPARMOR_PARSER` names a reference parser built from upstream
//! at the pinned commit (`tests/apparmor_fetch.sh <dir> build`), and
//! `QUANTY_APPARMOR_TST` its `parser/tst`, as for the simple_tests.

mod apparmor_common;

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use apparmor_common::{profiles, read_case, walk, BinProfile, Tables};
use quantycore::apparmor::compile::dfa::Dfa;
use quantycore::apparmor::model::Profile;
use quantycore::apparmor::{compile, Features, FsResolver, Options};

/// Cases both accept at the pinned commit are about sixty thousand;
/// fewer means the reference or the suite did not run.
const MIN_COMPARED: usize = 50_000;

fn reference(parser: &Path, tst: &Path, include: &Path, body: &[u8]) -> Option<Vec<u8>> {
    let mut child = Command::new(parser)
        .current_dir(tst)
        .args([
            "--config-file=./parser.conf",
            "-M",
            "features_files/features.all",
            "-S",
        ])
        .arg("-I")
        .arg(include)
        .arg("--base")
        .arg(include)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("reference parser runs");
    let mut stdin = child.stdin.take().unwrap();
    let body = body.to_vec();
    let feeder = std::thread::spawn(move || {
        let _ = stdin.write_all(&body);
    });
    let out = child.wait_with_output().unwrap();
    feeder.join().unwrap();
    out.status.success().then_some(out.stdout)
}

/// The kernel's view of one of our states.
fn accept(d: &Dfa, s: u32) -> (u32, u32) {
    d.perms[s as usize].accept_pair()
}

/// Walks both automata together. Returns the first difference.
fn compare(ours: &Dfa, theirs: &Tables, what: &str) -> Result<(), String> {
    let mut seen: HashSet<(u32, u32)> = HashSet::new();
    let mut queue = VecDeque::from([(1u32, 1u32, Vec::<u8>::new())]);
    seen.insert((1, 1));
    while let Some((a, b, path)) = queue.pop_front() {
        let ta = (
            theirs.accept.get(b as usize).copied().unwrap_or(0),
            theirs.accept2.get(b as usize).copied().unwrap_or(0),
        );
        if accept(ours, a) != ta {
            return Err(format!(
                "{what}: after {:?} ours {:x?}, upstream {:x?}",
                String::from_utf8_lossy(&path),
                accept(ours, a),
                ta
            ));
        }
        let mut step = |na: u32, nb: u32, sym: Option<u8>| {
            if seen.insert((na, nb)) {
                let mut p = path.clone();
                match sym {
                    Some(c) => p.push(c),
                    None => p.extend_from_slice(b"<oob>"),
                }
                queue.push_back((na, nb, p));
            }
        };
        for c in 0..=255u8 {
            let nb = theirs.next(b, c).map_err(|e| format!("{what}: {e}"))?;
            step(ours.next(a, c), nb, Some(c));
        }
        let nb = theirs.next_oob(b).map_err(|e| format!("{what}: {e}"))?;
        step(ours.next_oob(a), nb, None);
    }
    Ok(())
}

fn compare_opt(ours: Option<&Dfa>, theirs: Option<&Tables>, what: &str) -> Result<(), String> {
    match (ours, theirs) {
        (None, None) => Ok(()),
        (Some(o), Some(t)) => compare(o, t, what),
        (o, t) => Err(format!(
            "{what}: ours {}, upstream {}",
            if o.is_some() { "present" } else { "absent" },
            if t.is_some() { "present" } else { "absent" }
        )),
    }
}

/// upstream writes a namespaced exec target with the separator after the
/// namespace turned into NUL.
fn xtable_entry(name: &[u8]) -> Vec<u8> {
    let mut v = name.to_vec();
    if v.first() == Some(&b':') {
        if let Some(p) = v[1..].iter().position(|&c| c == b':') {
            v[p + 1] = 0;
        }
    }
    v.push(0);
    v
}

fn flatten<'a>(p: &'a Profile, prefix: &[u8], out: &mut Vec<(Vec<u8>, &'a Profile)>) {
    let mut name = prefix.to_vec();
    if !name.is_empty() {
        name.extend_from_slice(b"//");
    }
    name.extend_from_slice(&p.name);
    for h in p.hats.values() {
        flatten(h, &name, out);
    }
    out.push((name, p));
}

fn compare_policy(
    ours: &quantycore::apparmor::model::Policy,
    theirs: &[BinProfile],
) -> Result<usize, String> {
    let mut mine = Vec::new();
    for p in ours.profiles.values() {
        flatten(p, b"", &mut mine);
    }
    let by_name: HashMap<(Option<Vec<u8>>, Vec<u8>), &BinProfile> = theirs
        .iter()
        .map(|t| ((t.namespace.clone(), t.name.clone()), t))
        .collect();
    if by_name.len() != mine.len() {
        return Err(format!(
            "{} profiles here, {} upstream",
            mine.len(),
            by_name.len()
        ));
    }
    let mut compared = 0;
    for (name, p) in &mine {
        let shown = String::from_utf8_lossy(name);
        let t = by_name
            .get(&(p.ns.clone(), name.clone()))
            .ok_or_else(|| format!("profile {shown} missing upstream"))?;
        compare_opt(
            p.file_dfa.as_ref(),
            t.file.as_ref(),
            &format!("{shown} file"),
        )?;
        compare_opt(
            p.xmatch.as_ref().map(|x| &x.0),
            t.xmatch.as_ref().map(|x| &x.0),
            &format!("{shown} attachment"),
        )?;
        if let (Some(o), Some(u)) = (&p.xmatch, &t.xmatch) {
            if o.1 as u32 != u.1 {
                return Err(format!(
                    "{shown}: attachment length {} here, {} upstream",
                    o.1, u.1
                ));
            }
        }
        if p.file_dfa.is_some() && p.exec_table[4].is_some() {
            let xt: Vec<Vec<u8>> = p.exec_table[4..]
                .iter()
                .flatten()
                .map(|n| xtable_entry(n))
                .collect();
            if xt != t.xtable {
                return Err(format!(
                    "{shown}: exec table {xt:?} here, {:?} upstream",
                    t.xtable
                ));
            }
        }
        compared += 1;
    }
    Ok(compared)
}

#[test]
fn automata_match_upstream() {
    let (Some(parser), Some(tst)) = (
        std::env::var_os("QUANTY_APPARMOR_PARSER"),
        std::env::var_os("QUANTY_APPARMOR_TST"),
    ) else {
        if std::env::var_os("QUANTY_VECTORS_REQUIRED").is_some() {
            panic!("QUANTY_APPARMOR_PARSER or QUANTY_APPARMOR_TST not set but QUANTY_VECTORS_REQUIRED is");
        }
        eprintln!("QUANTY_APPARMOR_PARSER or QUANTY_APPARMOR_TST not set, skipping");
        return;
    };
    let parser = PathBuf::from(parser);
    let tst = PathBuf::from(tst);
    let root = tst.join("simple_tests");
    let mut paths = Vec::new();
    walk(&root, &mut paths);
    paths.sort();
    let feats = std::fs::read(tst.join("features_files/features.all")).unwrap();
    let feats = Features::from_text(&feats).unwrap();
    let opts = Options {
        kernel_features: feats.clone(),
        policy_features: Some(feats),
        ..Options::default()
    };

    let next = AtomicUsize::new(0);
    let compared = AtomicUsize::new(0);
    let profiles_compared = AtomicUsize::new(0);
    let different: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some(path) = paths.get(i) else { break };
                let case = read_case(path);
                if case.disabled {
                    continue;
                }
                let mut resolver = FsResolver::new(vec![root.clone()], tst.clone());
                let Ok(ours) = compile(&mut resolver, "stdin", case.body.clone(), &opts) else {
                    continue;
                };
                let Some(bin) = reference(&parser, &tst, &root, &case.body) else {
                    continue;
                };
                let rel = path.strip_prefix(&tst).unwrap().display().to_string();
                let result = profiles(&bin).and_then(|t| compare_policy(&ours, &t));
                match result {
                    Ok(n) => {
                        compared.fetch_add(1, Ordering::Relaxed);
                        profiles_compared.fetch_add(n, Ordering::Relaxed);
                    }
                    Err(e) => different.lock().unwrap().push(format!("{rel}: {e}")),
                }
            });
        }
    });
    let mut different = different.into_inner().unwrap();
    different.sort();
    let compared = compared.into_inner();
    eprintln!(
        "{compared} cases with {} profiles match upstream, {} differ",
        profiles_compared.into_inner(),
        different.len()
    );
    for d in different.iter().take(40) {
        eprintln!("differs: {d}");
    }
    if let Ok(out) = std::env::var("QUANTY_APPARMOR_DIFF_OUT") {
        std::fs::write(out, different.join("\n")).unwrap();
    }
    assert!(compared >= MIN_COMPARED, "only {compared} cases compared");
    assert!(
        different.is_empty(),
        "{} cases differ from upstream",
        different.len()
    );
}

/// The corpus of real profiles, compiled by both with upstream's test
/// features, each profile resolving includes from its own tree.
#[test]
fn corpus_automata_match_upstream() {
    let (Some(parser), Some(tst), Some(corpus)) = (
        std::env::var_os("QUANTY_APPARMOR_PARSER"),
        std::env::var_os("QUANTY_APPARMOR_TST"),
        std::env::var_os("QUANTY_APPARMOR_CORPUS"),
    ) else {
        if std::env::var_os("QUANTY_VECTORS_REQUIRED").is_some() {
            panic!("reference parser, tst or corpus not set but QUANTY_VECTORS_REQUIRED is");
        }
        eprintln!("reference parser, tst or corpus not set, skipping");
        return;
    };
    let (parser, tst, corpus) = (
        PathBuf::from(parser),
        PathBuf::from(tst),
        PathBuf::from(corpus),
    );
    let feats = std::fs::read(tst.join("features_files/features.all")).unwrap();
    let feats = Features::from_text(&feats).unwrap();
    let opts = Options {
        kernel_features: feats.clone(),
        policy_features: Some(feats),
        ..Options::default()
    };
    let mut files = Vec::new();
    for root in ["ubuntu-24.04", "debian-13", "upstream", "containers"] {
        let base = corpus.join(root).join("etc/apparmor.d");
        for e in std::fs::read_dir(&base).unwrap() {
            let p = e.unwrap().path();
            if p.is_file() {
                files.push((base.clone(), p));
            }
        }
    }
    files.sort();
    let next = AtomicUsize::new(0);
    let compared = AtomicUsize::new(0);
    let different: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some((base, path)) = files.get(i) else {
                    break;
                };
                let text = std::fs::read(path).unwrap();
                let rel = path.strip_prefix(&corpus).unwrap().display().to_string();
                let mut resolver = FsResolver::new(vec![base.clone()], base.clone());
                let ours = match compile(&mut resolver, &rel, text.clone(), &opts) {
                    Ok(p) => p,
                    Err(e) => {
                        different
                            .lock()
                            .unwrap()
                            .push(format!("{rel}: refused here: {e}"));
                        continue;
                    }
                };
                let Some(bin) = reference(&parser, &tst, base, &text) else {
                    different
                        .lock()
                        .unwrap()
                        .push(format!("{rel}: refused upstream"));
                    continue;
                };
                match profiles(&bin).and_then(|t| compare_policy(&ours, &t)) {
                    Ok(_) => {
                        compared.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(e) => different.lock().unwrap().push(format!("{rel}: {e}")),
                }
            });
        }
    });
    let mut different = different.into_inner().unwrap();
    different.sort();
    let compared = compared.into_inner();
    eprintln!(
        "{compared} corpus profiles match upstream, {} differ",
        different.len()
    );
    for d in &different {
        eprintln!("differs: {d}");
    }
    assert!(
        compared + different.len() >= 430,
        "only {} corpus files",
        compared + different.len()
    );
    assert!(
        different.is_empty(),
        "{} corpus profiles differ from upstream",
        different.len()
    );
}
