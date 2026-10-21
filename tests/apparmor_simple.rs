//! Upstream's parser test suite (`parser/tst/simple_tests` in
//! gitlab.com/apparmor/apparmor, GPL-2.0, read as data and never copied
//! here): about seventy thousand profile snippets, each marked with
//! whether `apparmor_parser` must accept or refuse it. CI checks the
//! suite out at a pinned commit, generates the cases upstream generates,
//! and points `QUANTY_APPARMOR_TST` at `parser/tst`.
//!
//! Upstream runs each case through the whole parser and compiler, so a
//! case can be refused at any stage; `check` runs the same stages here.
//! Every case must be decided as upstream decides it.

mod apparmor_common;

use std::path::PathBuf;

use apparmor_common::{read_case, walk};
use quantycore::apparmor::{check, Features, FsResolver, Options};

/// Cases marked TODO are ones upstream knows it gets wrong. The reference
/// is what upstream does, not what it would like to do, so for those the
/// expectation is inverted. Matched by path.
const TODO_INVERTED: bool = true;

/// Cases this crate deliberately decides differently. Path, reason.
const DIFFERS_ON_PURPOSE: &[(&str, &str)] = &[];

/// The suite at the pinned commit has 73737 cases; fewer means the
/// checkout or the generation step went wrong.
const MIN_CASES: usize = 73_000;

#[test]
fn simple_tests() {
    let Some(tst) = std::env::var_os("QUANTY_APPARMOR_TST") else {
        if std::env::var_os("QUANTY_VECTORS_REQUIRED").is_some() {
            panic!("QUANTY_APPARMOR_TST not set but QUANTY_VECTORS_REQUIRED is");
        }
        eprintln!("QUANTY_APPARMOR_TST not set, skipping");
        return;
    };
    let tst = PathBuf::from(tst);
    let root = tst.join("simple_tests");
    // Upstream's harness passes -M features_files/features.all, which
    // sets the kernel's features and pins the policy's.
    let feats = std::fs::read(tst.join("features_files/features.all")).unwrap();
    let feats = Features::from_text(&feats).unwrap();
    let opts = Options {
        kernel_features: feats.clone(),
        policy_features: Some(feats),
        ..Options::default()
    };
    let mut paths = Vec::new();
    walk(&root, &mut paths);
    paths.sort();

    let (mut checked, mut disabled, mut wrongly_accepted) = (0, 0, Vec::new());
    let mut wrongly_refused = Vec::new();
    let mut on_purpose_seen = 0;
    for path in &paths {
        let case = read_case(path);
        if case.disabled {
            disabled += 1;
            continue;
        }
        let rel = path
            .strip_prefix(&tst)
            .unwrap()
            .to_string_lossy()
            .into_owned();
        let expect_pass = if case.todo && TODO_INVERTED {
            !case.expect_pass
        } else {
            case.expect_pass
        };
        let mut resolver = FsResolver::new(vec![root.clone()], tst.clone());
        let result = check(&mut resolver, "stdin", case.body, &opts);
        checked += 1;
        if DIFFERS_ON_PURPOSE.iter().any(|(p, _)| *p == rel) {
            on_purpose_seen += 1;
            continue;
        }
        match (expect_pass, result) {
            (true, Ok(())) | (false, Err(_)) => {}
            (true, Err(e)) => wrongly_refused.push(format!("{rel}: {e}")),
            (false, Ok(())) => wrongly_accepted.push(rel),
        }
    }

    eprintln!(
        "{checked} cases checked, {disabled} disabled upstream, {} wrongly refused, {} wrongly accepted",
        wrongly_refused.len(),
        wrongly_accepted.len()
    );
    assert!(
        checked + disabled >= MIN_CASES,
        "only {} cases found under {}",
        checked + disabled,
        root.display()
    );
    assert_eq!(
        on_purpose_seen,
        DIFFERS_ON_PURPOSE.len(),
        "a listed case no longer exists"
    );
    for w in wrongly_refused.iter().take(50) {
        eprintln!("refused: {w}");
    }
    assert!(
        wrongly_refused.is_empty(),
        "{} cases wrongly refused",
        wrongly_refused.len()
    );
    if let Ok(out) = std::env::var("QUANTY_APPARMOR_ACCEPTED_OUT") {
        std::fs::write(out, wrongly_accepted.join("\n")).unwrap();
    }
    for p in wrongly_accepted.iter().take(50) {
        eprintln!("accepted: {p}");
    }
    assert!(
        wrongly_accepted.is_empty(),
        "{} cases wrongly accepted",
        wrongly_accepted.len()
    );
}
