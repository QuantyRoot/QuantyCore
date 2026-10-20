//! JSONTestSuite (github.com/nst/JSONTestSuite, MIT): about 300 small
//! documents, each named for whether RFC 8259 requires a parser to accept
//! it (y_), reject it (n_), or leaves the choice open (i_). Runs when
//! QUANTY_JSON_SUITE points at its test_parsing directory; checked at
//! commit 1ef36fa01286573e846ac449e8683f8833c5b26a.
//!
//! ```text
//! QUANTY_JSON_SUITE=/path/to/JSONTestSuite/test_parsing cargo test --test json_suite -- --nocapture
//! ```

use quantycore::json::{parse_bytes, ErrorKind};

// The RFC allows duplicate keys; this parser refuses them on purpose.
const REFUSED_BY_DESIGN: [&str; 2] = [
    "y_object_duplicated_key.json",
    "y_object_duplicated_key_and_value.json",
];

#[test]
fn every_case_in_the_suite() {
    let Ok(root) = std::env::var("QUANTY_JSON_SUITE") else {
        eprintln!("QUANTY_JSON_SUITE not set, suite not run");
        return;
    };
    let mut files: Vec<_> = std::fs::read_dir(&root)
        .expect("QUANTY_JSON_SUITE must be a directory")
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    let (mut yes, mut no, mut open, mut open_accepted) = (0, 0, 0, 0);
    let mut failures = Vec::new();
    for path in files {
        let name = path.file_name().unwrap().to_str().unwrap().to_string();
        let result = parse_bytes(&std::fs::read(&path).unwrap());
        match &name[..2] {
            "y_" if REFUSED_BY_DESIGN.contains(&name.as_str()) => {
                yes += 1;
                if !matches!(&result, Err(e) if e.kind == ErrorKind::DuplicateKey) {
                    failures.push(format!("{name}: expected a duplicate key error"));
                }
            }
            "y_" => {
                yes += 1;
                if let Err(e) = result {
                    failures.push(format!("{name}: rejected, {e}"));
                }
            }
            "n_" => {
                no += 1;
                if let Ok(v) = result {
                    failures.push(format!("{name}: accepted as {v}"));
                }
            }
            "i_" => {
                open += 1;
                let verdict = match &result {
                    Ok(_) => "accepted".to_string(),
                    Err(e) => format!("rejected, {e}"),
                };
                if result.is_ok() {
                    open_accepted += 1;
                }
                eprintln!("{name}: {verdict}");
            }
            _ => {}
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    eprintln!(
        "y_: {} of {yes} accepted, {} refused by design; n_: {no} of {no} rejected; \
         i_: {open_accepted} of {open} accepted",
        yes - REFUSED_BY_DESIGN.len(),
        REFUSED_BY_DESIGN.len()
    );
    assert!(yes > 90 && no > 180 && open > 30, "suite looks incomplete");
}
