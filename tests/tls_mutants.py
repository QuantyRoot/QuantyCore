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
    (
        "x25519: no clamping of the high bits",
        "src/tls/crypto/x25519.rs",
        "    k[31] &= 127;\n    k[31] |= 64;\n",
        "",
        UNIT, "rfc_7748_vectors", [],
    ),
    (
        "x25519: low bits not cleared",
        "src/tls/crypto/x25519.rs",
        "k[0] &= 248;",
        "k[0] &= 255;",
        UNIT, "rfc_7748_vectors", [],
    ),
    (
        "x25519: top bit of u not ignored",
        "src/tls/crypto/field25519.rs",
        "            (w(24) >> 12) & MASK,",
        "            w(24) >> 12,",
        UNIT, "rfc_7748_vectors", [],
    ),
    (
        "x25519: swap state not carried to the next bit",
        "src/tls/crypto/x25519.rs",
        "        swap = bit;\n",
        "        swap = 0;\n",
        UNIT, "rfc_7748_vectors", [],
    ),
    (
        "x25519: wrong a24",
        "src/tls/crypto/x25519.rs",
        "e.mul_small(121665)",
        "e.mul_small(121666)",
        UNIT, "rfc_7748_vectors", [],
    ),
    (
        "x25519: zero secret accepted",
        "src/tls/crypto/x25519.rs",
        "if ct::eq(s.expose(), &[0; 32]) {",
        "if ct::eq(s.expose(), &[1; 32]) {",
        UNIT, "small_order_point_is_refused", [],
    ),
    (
        "field25519: no final reduction",
        "src/tls/crypto/field25519.rs",
        "        l[0] += 19 * q;\n",
        "",
        UNIT, "values_at_and_above_p_reduce", [],
    ),
    (
        "field25519: subtraction bias of 2p",
        "src/tls/crypto/field25519.rs",
        "            0x1f_ffff_ffff_ffb4,",
        "            0x1f_ffff_ffff_ffb5,",
        UNIT, "rfc_7748_vectors", [],
    ),
    (
        "field25519: carry into the top limb dropped",
        "src/tls/crypto/field25519.rs",
        "        l[0] += c * 19;\n        self",
        "        self",
        VECTORS, "wycheproof_x25519", ["QUANTY_WYCHEPROOF"],
    ),
    (
        "field25519: inversion chain one square short",
        "src/tls/crypto/field25519.rs",
        "z_250_0.pow2k(5).mul(&z11)",
        "z_250_0.pow2k(4).mul(&z11)",
        UNIT, "field25519::tests::inverse", [],
    ),
    (
        "field25519: cswap ignores the flag",
        "src/tls/crypto/field25519.rs",
        "let mask = 0u64.wrapping_sub(std::hint::black_box(swap));",
        "let mask = 0u64.wrapping_sub(std::hint::black_box(swap)) & 0;",
        UNIT, "rfc_7748_vectors", [],
    ),
    (
        "key schedule: label without the tls13 prefix",
        "src/tls/key_schedule.rs",
        'let mut full = b"tls13 ".to_vec();',
        'let mut full = b"tls13".to_vec();',
        UNIT, "rfc_8448_early_and_derived", [],
    ),
    (
        "key schedule: derived secret over the wrong context",
        "src/tls/key_schedule.rs",
        'let derived = derive_secret(self.hash, self.current.expose(), b"derived", &empty);',
        'let derived = derive_secret(self.hash, self.current.expose(), b"derived", b"");',
        UNIT, "tls::rfc8448::simple_1rtt_handshake", ["QUANTY_RFC8448"],
    ),
    (
        "key schedule: Finished keyed with the traffic secret itself",
        "src/tls/key_schedule.rs",
        "let mut h = Hmac::new(hash, key.expose());",
        "let mut h = Hmac::new(hash, base_secret);",
        UNIT, "tls::rfc8448::simple_1rtt_handshake", ["QUANTY_RFC8448"],
    ),
    (
        "key schedule: ticket nonce ignored",
        "src/tls/key_schedule.rs",
        '        b"resumption",\n        nonce,\n',
        '        b"resumption",\n        b"",\n',
        UNIT, "tls::rfc8448::simple_1rtt_handshake", ["QUANTY_RFC8448"],
    ),
    (
        "record: sequence number xored into the wrong bytes",
        "src/tls/record.rs",
        "for (a, b) in n[4..].iter_mut().zip(self.seq.to_be_bytes()) {",
        "for (a, b) in n[3..].iter_mut().zip(self.seq.to_be_bytes()) {",
        UNIT, "tls::rfc8448::simple_1rtt_handshake", ["QUANTY_RFC8448"],
    ),
    (
        "record: additional data without the tag length",
        "src/tls/record.rs",
        "let len = inner.len() + 16;",
        "let len = inner.len();",
        UNIT, "tls::rfc8448::simple_1rtt_handshake", ["QUANTY_RFC8448"],
    ),
    (
        "record: sequence number not advanced on send",
        "src/tls/record.rs",
        "        self.cipher.seal(&nonce, &header, &mut inner);\n        self.seq += 1;",
        "        self.cipher.seal(&nonce, &header, &mut inner);",
        UNIT, "tls::rfc8448::simple_1rtt_handshake", ["QUANTY_RFC8448"],
    ),
    (
        "record: padding stripped from the front",
        "src/tls/record.rs",
        "let Some(end) = buf.iter().rposition(|&b| b != 0) else {",
        "let Some(end) = buf.iter().position(|&b| b != 0) else {",
        UNIT, "padding_is_removed_and_an_all_zero_record_refused", [],
    ),
    (
        "record: length limit off by one",
        "src/tls/record.rs",
        "        if len > self.max_ciphertext {",
        "        if len > self.max_ciphertext + 1 {",
        UNIT, "oversized_records_are_refused_from_the_header", [],
    ),
    (
        "msgs: duplicate extensions accepted",
        "src/tls/msgs.rs",
        "if out.iter().any(|e| e.typ == typ) {",
        "if out.iter().any(|e| e.typ == typ && false) {",
        UNIT, "duplicate_extensions_are_refused", [],
    ),
    (
        "codec: length prefix not checked against the rest",
        "src/tls/codec.rs",
        "        if n > self.buf.len() {\n            return None;\n        }",
        "        if n > self.buf.len() {\n            return Some(self.buf);\n        }",
        UNIT, "length_prefix_past_the_end_is_refused", [],
    ),
    (
        "client: session id echo not checked",
        "src/tls/client.rs",
        "if sh.session_id != s.offer.session_id {",
        "if false {",
        UNIT, "client_refuses_a_broken_server_hello", [],
    ),
    (
        "client: unsolicited extension accepted",
        "src/tls/client.rs",
        "            if !s.offer.extensions.contains(&e.typ) {",
        "            if false {",
        UNIT, "client_refuses_a_broken_server_hello", [],
    ),
    (
        "client: retry that changes nothing accepted",
        "src/tls/client.rs",
        "if group.is_none() && cookie.is_none() {",
        "if false {",
        UNIT, "client_refuses_a_broken_server_hello", [],
    ),
    (
        "client: server signature not checked",
        "src/tls/client.rs",
        "        self.key.verify(cv.scheme, &content, &cv.signature)?;",
        "        let _ = self.key.verify(cv.scheme, &content, &cv.signature);",
        UNIT, "wrong_name_or_key_fails_the_handshake", [],
    ),
    (
        "client: server Finished not checked",
        "src/tls/client.rs",
        "        if !verify_finished(&expected, &msg.body) {",
        "        if false {",
        UNIT, "client_refuses_a_forged_server_finished", ["QUANTY_RFC8448"],
    ),
    (
        "server: compression accepted",
        "src/tls/server.rs",
        "if ch.compression != [0] {",
        "if false {",
        UNIT, "server_refuses_a_broken_client_hello", [],
    ),
    (
        "server: pre_shared_key anywhere",
        "src/tls/server.rs",
        "if i != ch.extensions.len() - 1 {",
        "if false {",
        UNIT, "server_refuses_a_broken_client_hello", [],
    ),
    (
        "server: shares outside supported_groups",
        "src/tls/server.rs",
        "if shares.iter().any(|k| !groups.contains(&k.group)) {",
        "if false {",
        UNIT, "server_refuses_a_broken_client_hello", [],
    ),
    (
        "server: PSK binder not checked",
        "src/tls/server.rs",
        "if !verify_finished(&expected, &psks.binders[0]) {",
        "if false {",
        UNIT, "a_wrong_binder_fails_the_handshake", [],
    ),
    (
        "server: client certificate may be empty",
        "src/tls/server.rs",
        "        if cert.entries.is_empty() {",
        "        if false {",
        UNIT, "missing_client_certificate_is_refused", [],
    ),
    (
        "server: client Finished not checked",
        "src/tls/server.rs",
        "        if !verify_finished(&expected, &msg.body) {",
        "        if false {",
        UNIT, "server_refuses_a_finished_over_another_transcript", ["QUANTY_RFC8448"],
    ),
    (
        "conn: change_cipher_spec allowed forever",
        "src/tls/conn.rs",
        "        self.ccs_allowed = false;\n",
        "",
        UNIT, "change_cipher_spec_after_the_handshake_is_refused", [],
    ),
    (
        "conn: no limit on empty records",
        "src/tls/conn.rs",
        "if self.idle_records > MAX_IDLE_RECORDS {",
        "if false {",
        UNIT, "records_without_content_are_limited", [],
    ),
    (
        "conn: requested key update not answered",
        "src/tls/conn.rs",
        "if request && !self.sent_close {",
        "if false {",
        UNIT, "a_requested_key_update_is_answered", [],
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
