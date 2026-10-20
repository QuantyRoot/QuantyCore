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
    (
        "aes: one gate of the S-box circuit wrong",
        "src/tls/crypto/aes.rs",
        "let t2 = y12 & y15;",
        "let t2 = y12 | y15;",
        UNIT, "sbox_circuit_matches_the_definition", [],
    ),
    (
        "aes: ShiftRows wraps the wrong way",
        "src/tls/crypto/aes.rs",
        "((t << (16 - 4 * r)) & m & !low)",
        "((t << (12 - 4 * r)) & m & !low)",
        UNIT, "fips_197_in_every_lane", [],
    ),
    (
        "aes: MixColumns without reduction in bit 3",
        "src/tls/crypto/aes.rs",
        "        s[3] ^ s[7],\n",
        "        s[3],\n",
        UNIT, "fips_197_in_every_lane", [],
    ),
    (
        "aes: AES-256 key schedule misses the middle SubWord",
        "src/tls/crypto/aes.rs",
        "} else if nk > 6 && i % nk == 4 {",
        "} else if nk > 8 && i % nk == 4 {",
        UNIT, "fips_197_in_every_lane", [],
    ),
    (
        "aes: round constant not reduced",
        "src/tls/crypto/aes.rs",
        "rcon = (rcon << 1) ^ (0x1b * (rcon >> 7));",
        "rcon <<= 1;",
        UNIT, "fips_197_in_every_lane", [],
    ),
    (
        "aes: lanes swapped going in",
        "src/tls/crypto/aes.rs",
        "*plane |= ((y >> (8 * b)) & 0xff) << (8 * g);",
        "*plane |= ((y >> (8 * b)) & 0xff) << (8 * (g ^ 2));",
        UNIT, "fips_197_in_every_lane", [],
    ),
    (
        "gcm: counter starts at J0",
        "src/tls/crypto/gcm.rs",
        "let ctr = (2 + 4 * i + lane) as u32;",
        "let ctr = (1 + 4 * i + lane) as u32;",
        UNIT, "gcm_spec_cases_4_and_16", [],
    ),
    (
        "gcm: counter repeats after the first four blocks",
        "src/tls/crypto/gcm.rs",
        "let ctr = (2 + 4 * i + lane) as u32;",
        "let ctr = (2 + 3 * i + lane) as u32;",
        VECTORS, "wycheproof_aes_gcm", ["QUANTY_WYCHEPROOF"],
    ),
    (
        "gcm: wrong reduction in GHASH",
        "src/tls/crypto/gcm.rs",
        "v2 ^= v0 ^ (v0 >> 1) ^ (v0 >> 2) ^ (v0 >> 7);",
        "v2 ^= v0 ^ (v0 >> 1) ^ (v0 >> 2) ^ (v0 >> 6);",
        UNIT, "gcm_spec_cases_4_and_16", [],
    ),
    (
        "gcm: carryless product loses a residue class",
        "src/tls/crypto/gcm.rs",
        "(z0 & M0) | (z1 & M1) | (z2 & M2) | (z3 & M3)",
        "(z0 & M0) | (z1 & M1) | (z2 & M2) | (z3 & M2)",
        UNIT, "gcm_spec_cases_4_and_16", [],
    ),
    (
        "gcm: lengths in bytes instead of bits",
        "src/tls/crypto/gcm.rs",
        "(aad.len() as u64 * 8)",
        "(aad.len() as u64)",
        UNIT, "gcm_spec_cases_4_and_16", [],
    ),
    (
        "gcm: an empty padding block for aligned input",
        "src/tls/crypto/gcm.rs",
        "        if !rest.is_empty() {\n            let mut b = [0u8; 16];",
        "        if true {\n            let mut b = [0u8; 16];",
        VECTORS, "cavp_aes_gcm", ["QUANTY_CAVP"],
    ),
    (
        "gcm: decrypts before the tag is checked",
        "src/tls/crypto/gcm.rs",
        "        if !ct::eq(&want, &buf[body..]) {\n            return Err(AeadError);",
        "        if !ct::eq(&want, &buf[body..]) {\n            self.ctr(nonce, &mut buf[..body]);\n            return Err(AeadError);",
        UNIT, "gcm::tests::open_rejects_and_leaves_no_plaintext", [],
    ),
    (
        "chacha20: wrong rotation",
        "src/tls/crypto/chacha20poly1305.rs",
        "s[b] = (s[b] ^ s[c]).rotate_left(12);",
        "s[b] = (s[b] ^ s[c]).rotate_left(13);",
        UNIT, "rfc_8439_chacha20", [],
    ),
    (
        "chacha20: block counter not advanced",
        "src/tls/crypto/chacha20poly1305.rs",
        "chacha20_block(&self.key, counter + i as u32, &self.nonce, &mut ks);",
        "chacha20_block(&self.key, counter + 0 * i as u32, &self.nonce, &mut ks);",
        UNIT, "rfc_8439_chacha20", [],
    ),
    (
        "poly1305: r not clamped",
        "src/tls/crypto/chacha20poly1305.rs",
        "(le32(&key[3..]) >> 2) & 0x3ff_ff03,",
        "(le32(&key[3..]) >> 2) & 0x3ff_ffff,",
        UNIT, "rfc_8439_poly1305", [],
    ),
    (
        "poly1305: last partial block gets the high bit",
        "src/tls/crypto/chacha20poly1305.rs",
        "self.block(&b, 0);",
        "self.block(&b, 1 << 24);",
        UNIT, "rfc_8439_poly1305", [],
    ),
    (
        "poly1305: no final subtraction of p",
        "src/tls/crypto/chacha20poly1305.rs",
        "let keep_g = (g[4] >> 31).wrapping_sub(1);",
        "let keep_g = 0u32;",
        UNIT, "poly1305_reduces_values_just_above_p", [],
    ),
    (
        "poly1305: carry lost adding s",
        "src/tls/crypto/chacha20poly1305.rs",
        "f = w[i] as u64 + self.pad[i] as u64 + (f >> 32);",
        "f = w[i] as u64 + self.pad[i] as u64;",
        UNIT, "poly1305_reduces_values_just_above_p", [],
    ),
    (
        "chacha20poly1305: a full padding block for aligned input",
        "src/tls/crypto/chacha20poly1305.rs",
        "p.update(&zeros[..(16 - aad.len() % 16) % 16]);",
        "p.update(&zeros[..16 - aad.len() % 16]);",
        VECTORS, "wycheproof_chacha20_poly1305", ["QUANTY_WYCHEPROOF"],
    ),
    (
        "chacha20poly1305: decrypts before the tag is checked",
        "src/tls/crypto/chacha20poly1305.rs",
        "        if !ct::eq(&want, &buf[body..]) {\n            return Err(AeadError);",
        "        if !ct::eq(&want, &buf[body..]) {\n            cipher.apply(1, &mut buf[..body]);\n            return Err(AeadError);",
        UNIT, "chacha20poly1305::tests::open_rejects_and_leaves_no_plaintext", [],
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
