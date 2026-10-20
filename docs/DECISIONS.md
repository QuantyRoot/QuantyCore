# QuantyCore Design Decisions

Short ADRs. Newest at the bottom. If a decision gets reversed, strike it
through and add a new entry, never silently edit history.

## Index

- [ADR-001](#adr-001-nothing-outside-the-standard-library-and-quantyroot-is-not-outside) Nothing outside the standard library, and QuantyRoot is not outside
- [ADR-002](#adr-002-honesty-rule-for-public-claims) Honesty rule for public claims
- [ADR-003](#adr-003-tls-is-written-here) TLS is written here
- [ADR-004](#adr-004-the-wire-protocols-live-here-in-one-crate) The wire protocols live here, in one crate
- [ADR-005](#adr-005-apache-20) Apache 2.0

## ADR-001: Nothing outside the standard library, and QuantyRoot is not outside

QuantyCore depends on the Rust standard library and on nothing else. Any
Quanty project may depend on QuantyCore, and on any other crate written and
maintained in a QuantyRoot repository, without that counting against its
own rule of having no dependencies.

**Why the line is drawn at the author, not at Cargo.toml.** QuantyDB's
ADR-020 removed its last third-party crates, and the reasons it gave were
never about the line in the manifest. They were about what a foreign crate
brings with it: someone else's release schedule, someone else's minimum
supported Rust version, someone else's security surface, and the eleven
further crates two small ones had pulled in. A crate from this
organization brings none of that. Its schedule is ours, its MSRV is ours,
and when it is wrong the person who fixes it is the person who noticed.
Copying the code into every project instead would keep the manifest empty
and create several copies that drift apart the first week nobody looks.

**What this costs, and the rules that keep it honest.**

1. The exemption only holds if an in-house crate meets the same bar as the
   project using it: the same gates in CI, tests that are shown to fail
   when the code is broken, ADRs for decisions, the same MSRV promise.
   Otherwise "no dependencies" turns into "no dependencies we admit to",
   and the rule is evaded by relabeling.
2. A breaking change in QuantyCore is a coordinated change across every
   repository that uses it. Until QuantyCore is on crates.io, consumers
   pin it by git revision, and moving the pin is a deliberate commit.
3. Public text says what is true: "depends only on the standard library
   and on other QuantyRoot crates", not "zero dependencies". Anyone who
   runs `cargo tree` will see the QuantyRoot crates, and the claim has to
   survive that (ADR-002).
4. A crate published to crates.io can only depend on other crates that are
   published there. A project that wants a crates.io release therefore
   waits for the QuantyCore release it needs.

What does not count as a dependency: test data taken from published
standards and test suites (RFC examples, NIST vectors), which is data with
its source and license noted beside it, not code that runs; and the tools
CI uses to run the build.

`unsafe` is forbidden in this crate. When something here needs a syscall
the standard library does not wrap, it goes behind one small boundary
crate, the way `quantydb-sys` does it in QuantyDB (ADR-023 there), and gets
its own record.

## ADR-002: Honesty rule for public claims

Carried over from QuantyDB's ADR-009 unchanged. No benchmark numbers,
compatibility claims, security claims or feature checkmarks in public text
unless they are reproducible from the repository. Built things are
described as built and planned things as planned.

For this crate the rule matters most for ADR-003: nothing here is called
secure, hardened or production ready until the conditions listed there are
met.

## ADR-003: TLS is written here

QuantyCore will contain its own implementation of TLS 1.3, including the
cryptographic primitives under it, written in this repository like
everything else.

**This reverses a judgment QuantyDB made twice**, when it declined to write
its own TLS client. The reason given there was that TLS means five to
fifteen thousand lines of cryptography, and that cryptography is the one
kind of code where wrong and clever looks exactly like right: a bug does
not crash, it leaks. That description of the cost is still accurate and is
kept here on purpose. What changed is which side of it the project stands
on, for three reasons:

1. **The consumers multiplied.** QuantyDB wanted TLS for one thing.
   QuantyKube needs it in at least three places: the etcd endpoint when it
   is reachable over a network (Kubernetes hardening guides expect TLS with
   client certificates between the API server and its store), the image
   puller talking to registries over HTTPS, and eventually the QuantyDB
   server. One implementation in one place serves all of them.
2. **No dependencies is the identity of these projects**, not a detail of
   one of them. A TLS crate from outside would be the largest and most
   security critical dependency in every product, which is the exact
   opposite of what the rule is for.
3. **It sits under the protocols that live here anyway** (ADR-004). TLS is
   the bottom of the same stack.

**Scope.** Narrow on purpose, and widened only by a real peer that needs
more.

- TLS 1.3 only (RFC 8446). TLS 1.2 is not built unless a peer we must talk
  to refuses 1.3. The registries the image puller targets are checked for
  that before the client ships, rather than assumed.
- Cipher suite: TLS_AES_128_GCM_SHA256, which RFC 8446 makes mandatory.
  Others when there is a reason.
- Key exchange: X25519 first, because Go's `crypto/tls`, which is what the
  Kubernetes API server uses, offers it. secp256r1, which the RFC makes
  mandatory, before the implementation claims to follow the RFC.
- Signatures: verification of RSA PKCS#1 v1.5 and ECDSA P-256 for
  certificate chains, RSA-PSS and ECDSA P-256 for CertificateVerify, and
  signing with whichever key type the deployment's certificates use.
  Kubernetes tooling commonly issues RSA keys, so RSA cannot be skipped.
- Certificates: a DER parser and the subset of X.509 path validation that
  a private cluster needs: chain to a configured CA, validity period,
  subject alternative name match, key usage. No CRL, no OCSP, no system
  trust store at first.
- Client certificates, both requesting and presenting them, because the
  etcd use is mutual TLS.
- Not built: 0-RTT, session resumption, and anything else whose only
  purpose is speed, until a measurement asks for it.
- Randomness comes from `/dev/urandom` through `std::fs`, which needs no
  unsafe code.

**Rules for writing it.** Secret data never decides a branch, a loop bound
or a memory index. AES is written without lookup tables, because table
based AES leaks its key through cache timing; that makes it slower than
hardware AES, and hardware AES is added later behind a measurement and its
own record, the way QuantyDB's ADR-020 handled the CRC instruction. The
compiler promises nothing about constant time, so this is checked by
measurement, not assumed from the source.

**The measuring instruments come before the code they measure.**

- Every primitive is tested against published vectors: FIPS 180-4 for
  SHA-256, RFC 4231 for HMAC, RFC 5869 for HKDF, NIST examples for AES-GCM,
  RFC 7748 for X25519, and the Project Wycheproof suites for the edge cases
  the RFC examples do not reach. Each vector test is shown to fail when the
  primitive is deliberately broken; a vector test that stays green against
  a wrong implementation is not a test.
- The handshake is checked byte for byte against the example traces in RFC
  8448.
- Interoperability is tested against Go's `crypto/tls` and against OpenSSL,
  in both directions, on a real machine.
- The parsers (records, handshake messages, DER) are fuzzed.
- The secret handling primitives get a statistical timing test in the
  style of dudect, written here.

**When it may be called secure.** Not before all of the above runs in CI,
and not before someone who did not write it has reviewed it. Until then,
any product that uses it says in its own README that its TLS is
unreviewed.

**What it costs.** Probably eight to fifteen thousand lines including the
tests, and months, not weeks. A class of bug this organization has not had
to defend against before: one that passes every functional test and still
leaks a key. And a maintenance duty that does not end, because TLS
implementations are attacked for as long as they exist.

**What it does not block.** QuantyKube's first demonstration talks to the
Kubernetes API server over a Unix socket without TLS, the way k3s runs
kine, so this work is not on that path and is scheduled after the
protocols that are (ADR-004).

## ADR-004: The wire protocols live here, in one crate

The protobuf wire format, HPACK, HTTP/2 framing and gRPC are built in
QuantyCore, not inside QuantyKube.

QuantyKube alone has two separate uses for the same stack. The etcd API is
gRPC, with QuantyKube as the server. The Container Runtime Interface, which
the kubelet uses to talk to the container runtime on every node, is also
gRPC, again with the runtime as the server. TLS (ADR-003) sits underneath
it whenever a connection leaves the machine. Building the stack once,
below both, is the reason this repository exists.

It is one crate with one module per layer. It gets split when there is a
reason, such as an unsafe boundary (ADR-001) or compile times that a
measurement shows to matter, and not before.

**The cost:** the code on QuantyKube's critical path lives in a second
repository. During development QuantyKube may point at a local checkout,
but every commit it makes pins QuantyCore by revision, so a protocol fix
is two commits in two repositories. That is accepted because the
alternative, building the stack inside QuantyKube and moving it out once
the runtime needs it, means moving it in the middle of the busiest weeks.

## ADR-005: Apache 2.0

QuantyCore is licensed under the Apache License 2.0, the same as
QuantyKube; that project's ADR-007 gives the full reasoning. For a library
the deciding point is simpler: it is meant to be used by Quanty projects
and by anyone else, and Apache 2.0 is compatible with both the MIT license
QuantyDB uses and the Apache 2.0 that QuantyKube uses.
