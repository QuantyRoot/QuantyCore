#!/usr/bin/env python3
"""Breaks the TLS code on purpose and checks that the named test fails.

A vector test that stays green against a wrong implementation is not a
test. Each mutant below is one plausible bug, the test that must catch it,
and nothing else. A mutant that survives fails the run.

Mutants whose test needs a vector suite are skipped when the suite's
variable is unset, unless QUANTY_VECTORS_REQUIRED is set, as in CI.

Usage: tests/tls_mutants.py [substring of a mutant name]
"""

import os
import subprocess
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

UNIT = ["--lib"]
VECTORS = ["--release", "--test", "tls_vectors"]

# name, file, text to find (exactly once), replacement, cargo test args,
# test filter, environment the test needs
MUTANTS = [
    (
        "sha2: padding fits one byte short",
        "src/tls/crypto/sha2.rs",
        "if self.used > B - len_bytes {",
        "if self.used >= B - len_bytes {",
        VECTORS, "acvp_sha2_aft_and_mct", ["QUANTY_ACVP"],
    ),
    (
        "sha2: bit length counter of 32 bits",
        "src/tls/crypto/sha2.rs",
        "let bits = self.total.wrapping_mul(8);",
        "let bits = self.total.wrapping_mul(8) as u32 as u128;",
        VECTORS, "acvp_sha2_large_messages", ["QUANTY_ACVP", "QUANTY_ACVP_LDT"],
    ),
    (
        "sha2: partial block not advanced",
        "src/tls/crypto/sha2.rs",
        "self.used += take;",
        "self.used += 0 * take;",
        UNIT, "million_a_fed_in_odd_pieces", [],
    ),
    (
        "sha256: wrong rotation in Sigma0",
        "src/tls/crypto/sha2.rs",
        "a.rotate_right(13) ^ a.rotate_right(22)",
        "a.rotate_right(13) ^ a.rotate_right(21)",
        UNIT, "fips_180_4_examples", [],
    ),
    (
        "sha384: wrong initial value",
        "src/tls/crypto/sha2.rs",
        "0xcbbb9d5dc1059ed8",
        "0xcbbb9d5dc1059ed9",
        UNIT, "fips_180_4_examples", [],
    ),
    (
        "hmac: key of exactly one block hashed",
        "src/tls/crypto/hmac.rs",
        "if key.len() > block {",
        "if key.len() >= block {",
        VECTORS, "acvp_hmac", ["QUANTY_ACVP"],
    ),
    (
        "hmac: wrong outer pad",
        "src/tls/crypto/hmac.rs",
        "0x36 ^ 0x5c",
        "0x36 ^ 0x5d",
        UNIT, "rfc_4231", [],
    ),
    (
        "hmac: verify accepts anything",
        "src/tls/crypto/hmac.rs",
        "let ok = ct::eq(&got, tag);",
        "let ok = ct::eq(&got, &got);",
        UNIT, "verify_rejects_a_flipped_last_bit", [],
    ),
    (
        "hkdf: counter starts at zero",
        "src/tls/crypto/hkdf.rs",
        "h.update(&[i as u8 + 1]);",
        "h.update(&[i as u8]);",
        UNIT, "rfc_5869", [],
    ),
    (
        "hkdf: blocks not chained",
        "src/tls/crypto/hkdf.rs",
        "prev = Some(t);",
        "drop(t);",
        UNIT, "rfc_5869", [],
    ),
    (
        "hkdf: limit one block too high",
        "src/tls/crypto/hkdf.rs",
        "if len > 255 * hash_len {",
        "if len > 256 * hash_len {",
        UNIT, "length_limit_is_255_blocks", [],
    ),
    (
        "hkdf: limit fixed at the SHA-256 size",
        "src/tls/crypto/hkdf.rs",
        "if len > 255 * hash_len {",
        "if len > 255 * 32 {",
        VECTORS, "wycheproof_hkdf", ["QUANTY_WYCHEPROOF"],
    ),
    (
        "ct: eq ignores the length",
        "src/tls/crypto/ct.rs",
        "    if a.len() != b.len() {\n        return false;\n    }\n    let mut acc",
        "    let mut acc",
        UNIT, "eq_sees_every_bit_position", [],
    ),
    (
        "ct: eq misses a bit",
        "src/tls/crypto/ct.rs",
        "acc |= x ^ y;",
        "acc |= (x ^ y) & 0x7f;",
        UNIT, "eq_sees_every_bit_position", [],
    ),
    (
        "ct: lt mask wrong for the top bit",
        "src/tls/crypto/ct.rs",
        "(d >> 32) as u32",
        "(d >> 31) as u32",
        UNIT, "masks_at_the_edges", [],
    ),
    (
        "ct: secret printed",
        "src/tls/crypto/ct.rs",
        'write!(f, "Secret({} bytes)", self.0.len())',
        'write!(f, "Secret({:?})", self.0)',
        UNIT, "secret_does_not_print_its_bytes", [],
    ),
]


def run(cmd, env):
    return subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True)


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
            if required and missing != ["QUANTY_ACVP_LDT"]:
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
            r = run(["cargo", "test", *args, test], env)
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
