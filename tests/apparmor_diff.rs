//! The compiler against `apparmor_parser`: every case of upstream's
//! simple_tests that both accept, and every corpus profile, is compiled
//! by both, and each automaton is compared with upstream's by walking the
//! two together over every input byte and the out of band symbol. Where
//! the walk reaches a pair of states, both must give the kernel the same
//! permissions; so the automata match the same paths with the same
//! permissions, however their states are numbered or their tables packed.
//!
//! Each comparison runs against three kernels: upstream's test feature
//! set, which takes permissions in the accept tables and has no fine
//! grained networking, and its `abi/5.0` and `abi/5.0-interface` feature
//! sets, which take a permissions table and mediate inet sockets, message
//! queues, io_uring and user namespaces.
//!
//! `QUANTY_APPARMOR_PARSER` names a reference parser built from upstream
//! at the pinned commit (`tests/apparmor_fetch.sh <dir> build`),
//! `QUANTY_APPARMOR_TST` its `parser/tst`, and `QUANTY_APPARMOR_CORPUS`
//! the corpus of real profiles.

mod apparmor_common;

use std::collections::{HashMap, HashSet, VecDeque};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use apparmor_common::{profiles, read_case, skeleton, walk, BinProfile, Tables};
use quantycore::apparmor::compile::dfa::{Dfa, Perms, DEAD, START};
use quantycore::apparmor::compile::kperms::AaPerms;
use quantycore::apparmor::model::Profile;
use quantycore::apparmor::{compile, Features, FsResolver, Options};

/// Cases both accept at the pinned commit, per feature set, are about
/// fifty thousand; fewer means the reference or the suite did not run.
const MIN_COMPARED: usize = 45_000;
const MIN_CORPUS: usize = 430;

struct Env {
    parser: PathBuf,
    tst: PathBuf,
}

/// The feature sets compared against, by name and path below the
/// upstream checkout's parser/tst.
const FEATURE_SETS: &[(&str, &str)] = &[
    ("features.all", "features_files/features.all"),
    ("abi 5.0", "../../profiles/apparmor.d/abi/5.0"),
    (
        "abi 5.0-interface",
        "../../profiles/apparmor.d/abi/5.0-interface",
    ),
];

fn env() -> Option<Env> {
    match (
        std::env::var_os("QUANTY_APPARMOR_PARSER"),
        std::env::var_os("QUANTY_APPARMOR_TST"),
    ) {
        (Some(p), Some(t)) => Some(Env {
            parser: PathBuf::from(p),
            tst: PathBuf::from(t),
        }),
        _ => {
            if std::env::var_os("QUANTY_VECTORS_REQUIRED").is_some() {
                panic!("QUANTY_APPARMOR_PARSER or QUANTY_APPARMOR_TST not set but QUANTY_VECTORS_REQUIRED is");
            }
            eprintln!("QUANTY_APPARMOR_PARSER or QUANTY_APPARMOR_TST not set, skipping");
            None
        }
    }
}

fn reference(e: &Env, features: &Path, include: &Path, body: &[u8]) -> Option<Vec<u8>> {
    let mut child = Command::new(&e.parser)
        .current_dir(&e.tst)
        .arg("--config-file=./parser.conf")
        .arg("--zstd-compress-level=none")
        .arg("-M")
        .arg(features)
        .arg("-S")
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

/// What the kernel reads for one state: the accept entries, or with a
/// permissions table, the owner flag and the entries it indexes.
#[derive(Debug, PartialEq, Eq)]
enum Seen {
    Accept(u32, u32),
    Table(u32, Vec<AaPerms>),
}

fn table_entry(raw: &[u32; 14]) -> AaPerms {
    AaPerms {
        allow: raw[1],
        deny: raw[2],
        subtree: raw[3],
        cond: raw[4],
        kill: raw[5],
        complain: raw[6],
        prompt: raw[7],
        audit: raw[8],
        quiet: raw[9],
        hide: raw[10],
        xindex: raw[11],
        tag: raw[12],
        label: raw[13],
    }
}

fn theirs_seen(t: &Tables, s: u32, file: bool) -> Result<Seen, String> {
    let a1 = t.accept.get(s as usize).copied().unwrap_or(0);
    let a2 = t.accept2.get(s as usize).copied().unwrap_or(0);
    match &t.permstable {
        None => Ok(Seen::Accept(a1, a2)),
        Some(table) => {
            let n = if file { 2 } else { 1 };
            let mut v = Vec::new();
            for k in 0..n {
                let e = table
                    .get(a1 as usize + k)
                    .ok_or_else(|| format!("accept index {a1} outside the permissions table"))?;
                v.push(table_entry(e));
            }
            Ok(Seen::Table(a2, v))
        }
    }
}

/// Ours, as upstream would encode it for the same kernel. With a
/// permissions table the start state indexes the first entry whatever
/// its permissions, and only states other than the start and the dead
/// one carry the owner flag.
fn ours_seen(d: &Dfa, s: u32, file: bool, table: bool, owner_flag: bool) -> Seen {
    let p = d.perms[s as usize];
    if !table {
        let (a1, a2) = p.accept_pair();
        return Seen::Accept(a1, a2);
    }
    let p = if s == START { Perms::default() } else { p };
    let flag = u32::from(owner_flag && s != START && s != DEAD);
    if file {
        Seen::Table(flag, p.file_entries().to_vec())
    } else {
        Seen::Table(0, vec![p.policy_entry()])
    }
}

/// Walks two decoded automata together, ours as written by the
/// serializer and upstream's. Returns the first difference.
fn compare_tables(ours: &Tables, theirs: &Tables, file: bool, what: &str) -> Result<(), String> {
    let mut seen: HashSet<(u32, u32)> = HashSet::new();
    let mut queue = VecDeque::from([(1u32, 1u32, Vec::<u8>::new())]);
    seen.insert((1, 1));
    while let Some((a, b, path)) = queue.pop_front() {
        let t = theirs_seen(theirs, b, file).map_err(|e| format!("{what}: {e}"))?;
        let o = theirs_seen(ours, a, file).map_err(|e| format!("{what}: ours: {e}"))?;
        if o != t {
            return Err(format!(
                "{what}: written, after {:?} ours {o:x?}, upstream {t:x?}",
                String::from_utf8_lossy(&path)
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
            let na = ours.next(a, c).map_err(|e| format!("{what}: ours: {e}"))?;
            let nb = theirs.next(b, c).map_err(|e| format!("{what}: {e}"))?;
            step(na, nb, Some(c));
        }
        let na = ours.next_oob(a).map_err(|e| format!("{what}: ours: {e}"))?;
        let nb = theirs.next_oob(b).map_err(|e| format!("{what}: {e}"))?;
        step(na, nb, None);
    }
    Ok(())
}

fn compare_tables_opt(
    ours: Option<&Tables>,
    theirs: Option<&Tables>,
    file: bool,
    what: &str,
) -> Result<(), String> {
    match (ours, theirs) {
        (None, None) => Ok(()),
        (Some(o), Some(t)) => compare_tables(o, t, file, what),
        _ => Err(format!("{what}: written, present on one side only")),
    }
}

/// Our policy as the serializer writes it, against upstream's bytes:
/// every value outside the automata equal and in the same order, every
/// automaton matching state for state.
fn compare_written(
    ours: &quantycore::apparmor::model::Policy,
    theirs_bin: &[u8],
) -> Result<(), String> {
    let units = quantycore::apparmor::binary::serialize(ours, &ours.support)?;
    let mut ours_bin = Vec::new();
    for u in &units {
        ours_bin.extend_from_slice(&u.data);
    }
    let key = |sk: &Vec<apparmor_common::Tlv>| format!("{sk:?}");
    let mut a: Vec<_> = skeleton(&ours_bin)?.iter().map(key).collect();
    let mut b: Vec<_> = skeleton(theirs_bin)?.iter().map(key).collect();
    a.sort();
    b.sort();
    if a != b {
        let first = a.iter().zip(&b).find(|(x, y)| x != y);
        return Err(format!(
            "written values differ: ours {first:?}, {} units vs {}",
            a.len(),
            b.len()
        ));
    }
    let mine = profiles(&ours_bin)?;
    let theirs = profiles(theirs_bin)?;
    let by_name: HashMap<(Option<Vec<u8>>, Vec<u8>), &BinProfile> = theirs
        .iter()
        .map(|t| ((t.namespace.clone(), t.name.clone()), t))
        .collect();
    for m in &mine {
        let shown = String::from_utf8_lossy(&m.name).into_owned();
        let t = by_name
            .get(&(m.namespace.clone(), m.name.clone()))
            .ok_or_else(|| format!("written profile {shown} missing upstream"))?;
        compare_tables_opt(
            m.file.as_ref(),
            t.file.as_ref(),
            true,
            &format!("{shown} file"),
        )?;
        compare_tables_opt(
            m.xmatch.as_ref().map(|x| &x.0),
            t.xmatch.as_ref().map(|x| &x.0),
            false,
            &format!("{shown} attachment"),
        )?;
        compare_tables_opt(
            m.policydb.as_ref(),
            t.policydb.as_ref(),
            false,
            &format!("{shown} policy"),
        )?;
    }
    Ok(())
}

/// Walks both automata together. Returns the first difference.
fn compare(ours: &Dfa, theirs: &Tables, file: bool, what: &str) -> Result<(), String> {
    let table = theirs.permstable.is_some();
    let owner_flag = file && !theirs.accept2.is_empty();
    let mut seen: HashSet<(u32, u32)> = HashSet::new();
    let mut queue = VecDeque::from([(START, 1u32, Vec::<u8>::new())]);
    seen.insert((START, 1));
    while let Some((a, b, path)) = queue.pop_front() {
        let t = theirs_seen(theirs, b, file).map_err(|e| format!("{what}: {e}"))?;
        let o = ours_seen(ours, a, file, table, owner_flag);
        if o != t {
            return Err(format!(
                "{what}: after {:?} ours {o:x?}, upstream {t:x?}",
                String::from_utf8_lossy(&path)
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

fn compare_opt(
    ours: Option<&Dfa>,
    theirs: Option<&Tables>,
    file: bool,
    what: &str,
) -> Result<(), String> {
    match (ours, theirs) {
        (None, None) => Ok(()),
        (Some(o), Some(t)) => compare(o, t, file, what),
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
            true,
            &format!("{shown} file"),
        )?;
        compare_opt(
            p.xmatch.as_ref().map(|x| &x.0),
            t.xmatch.as_ref().map(|x| &x.0),
            false,
            &format!("{shown} attachment"),
        )?;
        compare_opt(
            p.policydb.as_ref(),
            t.policydb.as_ref(),
            false,
            &format!("{shown} policy"),
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

/// Runs `jobs` across threads; each yields `Ok(n)` with n profiles
/// compared, `Err` for a difference, or None when skipped.
fn run<T: Sync>(
    jobs: &[T],
    f: impl Fn(&T) -> Option<Result<usize, String>> + Sync,
) -> (usize, usize, Vec<String>) {
    let next = AtomicUsize::new(0);
    let cases = AtomicUsize::new(0);
    let profiles_compared = AtomicUsize::new(0);
    let different: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| loop {
                let i = next.fetch_add(1, Ordering::Relaxed);
                let Some(job) = jobs.get(i) else { break };
                match f(job) {
                    None => {}
                    Some(Ok(n)) => {
                        cases.fetch_add(1, Ordering::Relaxed);
                        profiles_compared.fetch_add(n, Ordering::Relaxed);
                    }
                    Some(Err(e)) => different.lock().unwrap().push(e),
                }
            });
        }
    });
    let mut different = different.into_inner().unwrap();
    different.sort();
    (
        cases.into_inner(),
        profiles_compared.into_inner(),
        different,
    )
}

fn options(features: &Path) -> Options {
    let feats = Features::from_text(&std::fs::read(features).unwrap()).unwrap();
    Options {
        kernel_features: feats.clone(),
        policy_features: Some(feats),
        ..Options::default()
    }
}

fn report(what: &str, cases: usize, profiles: usize, different: &[String]) {
    eprintln!(
        "{what}: {cases} with {profiles} profiles match upstream, {} differ",
        different.len()
    );
    for d in different.iter().take(40) {
        eprintln!("differs: {d}");
    }
}

#[test]
fn automata_match_upstream() {
    let Some(e) = env() else { return };
    let root = e.tst.join("simple_tests");
    let mut paths = Vec::new();
    walk(&root, &mut paths);
    paths.sort();
    let mut all_different = Vec::new();
    for (name, rel) in FEATURE_SETS {
        let features = e.tst.join(rel);
        let opts = options(&features);
        let (cases, profiles_n, different) = run(&paths, |path| {
            let case = read_case(path);
            if case.disabled {
                return None;
            }
            let mut resolver = FsResolver::new(vec![root.clone()], e.tst.clone());
            let ours = compile(&mut resolver, "stdin", case.body.clone(), &opts).ok()?;
            let bin = reference(&e, &features, &root, &case.body)?;
            let rel = path.strip_prefix(&e.tst).unwrap().display().to_string();
            Some(
                profiles(&bin)
                    .and_then(|t| compare_policy(&ours, &t))
                    .and_then(|n| compare_written(&ours, &bin).map(|()| n))
                    .map_err(|m| format!("{name}: {rel}: {m}")),
            )
        });
        report(name, cases, profiles_n, &different);
        assert!(cases >= MIN_COMPARED, "{name}: only {cases} cases compared");
        all_different.extend(different);
    }
    if let Ok(out) = std::env::var("QUANTY_APPARMOR_DIFF_OUT") {
        std::fs::write(out, all_different.join("\n")).unwrap();
    }
    assert!(
        all_different.is_empty(),
        "{} cases differ from upstream",
        all_different.len()
    );
}

/// The corpus of real profiles, each resolving includes from its own
/// tree. A profile either side refuses counts as a difference: upstream
/// accepts all of them.
#[test]
fn corpus_automata_match_upstream() {
    let Some(e) = env() else { return };
    let Some(corpus) = std::env::var_os("QUANTY_APPARMOR_CORPUS") else {
        if std::env::var_os("QUANTY_VECTORS_REQUIRED").is_some() {
            panic!("QUANTY_APPARMOR_CORPUS not set but QUANTY_VECTORS_REQUIRED is");
        }
        eprintln!("QUANTY_APPARMOR_CORPUS not set, skipping");
        return;
    };
    let corpus = PathBuf::from(corpus);
    let mut files = Vec::new();
    for root in ["ubuntu-24.04", "debian-13", "upstream", "containers"] {
        let base = corpus.join(root).join("etc/apparmor.d");
        for d in std::fs::read_dir(&base).unwrap() {
            let p = d.unwrap().path();
            if p.is_file() {
                files.push((base.clone(), p));
            }
        }
    }
    files.sort();
    let mut all_different = Vec::new();
    for (name, rel) in FEATURE_SETS {
        let features = e.tst.join(rel);
        let opts = options(&features);
        let (cases, profiles_n, different) = run(&files, |(base, path)| {
            let text = std::fs::read(path).unwrap();
            let rel = path.strip_prefix(&corpus).unwrap().display().to_string();
            let mut resolver = FsResolver::new(vec![base.clone()], base.clone());
            let ours = match compile(&mut resolver, &rel, text.clone(), &opts) {
                Ok(p) => p,
                Err(m) => return Some(Err(format!("{name}: {rel}: refused here: {m}"))),
            };
            let Some(bin) = reference(&e, &features, base, &text) else {
                return Some(Err(format!("{name}: {rel}: refused upstream")));
            };
            Some(
                profiles(&bin)
                    .and_then(|t| compare_policy(&ours, &t))
                    .and_then(|n| compare_written(&ours, &bin).map(|()| n))
                    .map_err(|m| format!("{name}: {rel}: {m}")),
            )
        });
        report(&format!("{name} corpus"), cases, profiles_n, &different);
        assert!(
            cases + different.len() >= MIN_CORPUS,
            "{name}: only {} corpus files",
            cases + different.len()
        );
        all_different.extend(different);
    }
    assert!(
        all_different.is_empty(),
        "{} corpus profiles differ from upstream",
        all_different.len()
    );
}
