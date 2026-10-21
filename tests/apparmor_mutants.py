#!/usr/bin/env python3
"""Breaks the AppArmor code on purpose and checks that the named test fails.

Each mutant is one plausible bug, in the parser, the compiler, the
writer, the kernel interface or the built-in profile, and the one test
that must catch it. A mutant that survives fails the run, and so does one
whose text is not found exactly once, so the list cannot rot silently.

Mutants whose test needs upstream's tests, the reference parser or the
corpus are skipped when the variable is unset, unless
QUANTY_VECTORS_REQUIRED is set, as in CI. The differential test also
needs LD_LIBRARY_PATH to find the reference parser's libapparmor.

Usage: tests/apparmor_mutants.py [substring of a mutant name]
"""

import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

UNIT = ["--lib"]
SIMPLE = ["--release", "--test", "apparmor_simple"]
DIFF = ["--release", "--test", "apparmor_diff"]
CORPUS = ["--release", "--test", "apparmor_corpus"]
FUZZ = ["--release", "--test", "apparmor_fuzz"]

TST = "QUANTY_APPARMOR_TST"
REF = ["QUANTY_APPARMOR_PARSER", "QUANTY_APPARMOR_TST", "QUANTY_APPARMOR_CORPUS"]
CORP = ["QUANTY_APPARMOR_CORPUS"]

# name, file, text to find (exactly once), replacement, cargo test args,
# test filter, environment the test needs
MUTANTS = [
    (
        "parser: priority one above the maximum accepted",
        "src/apparmor/build.rs",
        "if v > MAX_POLICY_PRIORITY as i64 {",
        "if v > MAX_POLICY_PRIORITY as i64 + 1 {",
        SIMPLE, "simple_tests", [TST],
    ),
    (
        "parser: expression depth unbounded",
        "src/apparmor/parser.rs",
        "if self.depth > MAX_EXPR_NESTING {",
        "if false {",
        UNIT, "nesting_is_bounded_by_the_heap_not_the_stack", [],
    ),
    (
        "variables: recursion not noticed",
        "src/apparmor/eval.rs",
        "Some(v) if v.expanding => {",
        "Some(v) if v.expanding && false => {",
        UNIT, "recursion_and_explosion_are_errors", [],
    ),
    (
        "signal: rtmin+32 refused",
        "src/apparmor/class/signal.rs",
        "(n <= MAXRT)",
        "(n < MAXRT)",
        UNIT, "realtime_signals_follow_upstreams_mapping", [],
    ),
    (
        "glob: ** stops at a slash",
        "src/apparmor/compile/aare.rs",
        'Glob::Default => (&b"[^/\\\\x00]"[..], &b"[^/\\\\x00]*"[..], &b"[^\\\\x00]*"[..]),',
        'Glob::Default => (&b"[^/\\\\x00]"[..], &b"[^/\\\\x00]*"[..], &b"[^/\\\\x00]*"[..]),',
        DIFF, "corpus_automata_match_upstream", REF,
    ),
    (
        "dfa: allow wins over deny at equal priority",
        "src/apparmor/compile/dfa.rs",
        "        Kind::Deny => 3,",
        "        Kind::Deny => 0,",
        UNIT, "deny_wins_at_equal_priority_and_priority_wins_over_deny", [],
    ),
    (
        "dfa: conflicting x modifiers of allow rules merged",
        "src/apparmor/compile/dfa.rs",
        "        Kind::Allow => {\n            if conflicts(p) {",
        "        Kind::Allow => {\n            if false && conflicts(p) {",
        UNIT, "different_exec_modifiers_on_overlapping_paths_conflict", [],
    ),
    (
        "dfa: conflicting x modifiers of exact rules merged",
        "src/apparmor/compile/dfa.rs",
        "        Kind::Exact => {\n            if conflicts(p) {",
        "        Kind::Exact => {\n            if false && conflicts(p) {",
        UNIT, "different_exec_modifiers_on_overlapping_paths_conflict", [],
    ),
    (
        "dfa: ix no longer implies m",
        "src/apparmor/compile/dfa.rs",
        "            p.allow |= OLD_EXEC_MMAP;\n            priority[6] = priority[0];",
        "            priority[6] = priority[0];",
        DIFF, "corpus_automata_match_upstream", REF,
    ),
    (
        "dfa: deny left in tables that carry no deny mask",
        "src/apparmor/compile/dfa.rs",
        "                if filter_deny {\n                    p = p.apply_deny();",
        "                if false {\n                    p = p.apply_deny();",
        DIFF, "corpus_automata_match_upstream", REF,
    ),
    (
        "dfa: state limit not enforced",
        "src/apparmor/compile/dfa.rs",
        "if states.len() >= limits.max_states {",
        "if false {",
        UNIT, "explosion_is_an_error_not_an_abort", [],
    ),
    (
        "dfa: minimization refines only from the first block",
        "src/apparmor/compile/dfa.rs",
        "    for b in 0..nblocks {",
        "    for b in 0..1 {",
        DIFF, "corpus_automata_match_upstream", REF,
    ),
    (
        "parser: not chains keep the wrong parity",
        "src/apparmor/parser.rs",
        "Ok(if nots % 2 == 1 {",
        "Ok(if nots % 2 == 0 {",
        UNIT, "conditionals_nest_and_chain", [],
    ),
    (
        "network: allowed families written as audited",
        "src/apparmor/class/network.rs",
        "                    e[0] |= bits;\n                    if audit {",
        "                    e[1] |= bits;\n                    if audit {",
        DIFF, "corpus_automata_match_upstream", REF,
    ),
    (
        "binary: no room for the kernel's read ahead",
        "src/apparmor/binary.rs",
        "let len = (max_base + 256).max(next.len());",
        "let len = next.len();",
        FUZZ, "fuzz_profile_text", [TST],
    ),
    (
        "binary: check entries all point at the start state",
        "src/apparmor/binary.rs",
        "            check[p] = s as u32;",
        "            check[p] = 0;",
        DIFF, "corpus_automata_match_upstream", REF,
    ),
    (
        "binary: byte classes shifted",
        "src/apparmor/binary.rs",
        "d.class.iter().map(|&c| c as u32)",
        "d.class.iter().map(|&c| c as u32 ^ 1)",
        DIFF, "corpus_automata_match_upstream", REF,
    ),
    (
        "binary: policy version left out",
        "src/apparmor/binary.rs",
        "        v |= (POLICY_VERSION & 0xff) << 20;",
        "",
        DIFF, "corpus_automata_match_upstream", REF,
    ),
    (
        "exec attribute: shared file used when the module says disabled",
        "src/apparmor/kernel.rs",
        "    let fallback = if base != Base::Old && enabled != Param::No {",
        "    let fallback = if base != Base::Old {",
        UNIT, "attribute_choice_follows_libapparmor", [],
    ),
    (
        "exec attribute: an unreadable parameter counts as disabled",
        "src/apparmor/kernel.rs",
        "            Param::Unread(Probe::Denied) => {}\n",
        "",
        UNIT, "attribute_choice_follows_libapparmor", [],
    ),
    (
        "exec attribute: command without the space",
        "src/apparmor/kernel.rs",
        'command.extend_from_slice(b"exec ");',
        'command.extend_from_slice(b"exec");',
        UNIT, "exec_command_is_refused_when_empty_or_with_nul", [],
    ),
    (
        "securityfs: profile names split at the first parenthesis",
        "src/apparmor/kernel.rs",
        '.rposition(|w| w == b" (")',
        '.position(|w| w == b" (")',
        UNIT, "profiles_file_is_read_by_its_last_parenthesis", [],
    ),
    (
        "RuntimeDefault: powercap left writable",
        "src/apparmor/runtime_default.rs",
        "  deny /sys/devices/virtual/powercap/** rwklx,\n",
        "",
        CORPUS, "runtime_default_is_containerds", CORP,
    ),
    (
        "RuntimeDefault: one blank line too few",
        "src/apparmor/runtime_default.rs",
        '"\\n\\nprofile {name} flags',
        '"\\nprofile {name} flags',
        CORPUS, "runtime_default_is_containerds", CORP,
    ),
]


def run(cmd, env):
    return subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True, timeout=1500)


def main():
    only = sys.argv[1] if len(sys.argv) > 1 else ""
    required = "QUANTY_VECTORS_REQUIRED" in os.environ
    env = dict(os.environ)
    env["CARGO_TERM_COLOR"] = "never"
    survived, skipped, killed = [], [], 0
    for name, path, find, repl, args, test, needs in MUTANTS:
        if only not in name:
            continue
        missing = [v for v in needs if v not in os.environ]
        if missing:
            if required:
                print(f"FAIL  {name}: {', '.join(missing)} not set")
                survived.append(name)
            else:
                print(f"skip  {name}: needs {', '.join(missing)}")
                skipped.append(name)
            continue
        full = os.path.join(ROOT, path)
        original = open(full).read()
        if original.count(find) != 1:
            print(f"FAIL  {name}: text found {original.count(find)} times")
            survived.append(name)
            continue
        open(full, "w").write(original.replace(find, repl))
        try:
            start = time.time()
            try:
                r = run(["cargo", "test", *args, test, "--", "--test-threads", "1"], env)
            except subprocess.TimeoutExpired:
                killed += 1
                print(f"ok    {name}: {test} did not finish in time")
                continue
            out = r.stdout + r.stderr
            if r.returncode == 0:
                print(f"FAIL  {name}: {test} stayed green")
                survived.append(name)
            elif "error[E" in out or "could not compile" in out:
                print(f"FAIL  {name}: mutant does not compile")
                survived.append(name)
            elif f"{test} ... FAILED" not in out:
                print(f"FAIL  {name}: {test} did not fail, cargo said:\n{out[-2000:]}")
                survived.append(name)
            else:
                killed += 1
                print(f"ok    {name}: {test} failed ({time.time() - start:.0f}s)")
        finally:
            open(full, "w").write(original)
    print(f"{killed} killed, {len(survived)} survived or broken, {len(skipped)} skipped")
    if survived or killed == 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
