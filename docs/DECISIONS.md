# QuantyCore Design Decisions

Short ADRs. Newest at the bottom. If a decision gets reversed, strike it
through and add a new entry, never silently edit history.

## Index

- [ADR-001](#adr-001-nothing-outside-the-standard-library-and-quantyroot-is-not-outside) Nothing outside the standard library, and QuantyRoot is not outside
- [ADR-002](#adr-002-honesty-rule-for-public-claims) Honesty rule for public claims
- [ADR-003](#adr-003-tls-is-written-here) TLS is written here
- [ADR-004](#adr-004-the-wire-protocols-live-here-in-one-crate) The wire protocols live here, in one crate
- [ADR-005](#adr-005-apache-20) Apache 2.0
- [ADR-006](#adr-006-http2-and-grpc-on-blocking-threads-hardened-for-local-peers-first) HTTP/2 and gRPC on blocking threads, hardened for local peers first
- [ADR-007](#adr-007-gzip-and-tar-stream-with-fixed-memory-and-accept-what-zlib-accepts) gzip and tar stream with fixed memory, and accept what zlib accepts
- [ADR-008](#adr-008-json-is-strict-and-one-document-has-one-meaning) JSON is strict, and one document has one meaning
- [ADR-009](#adr-009-http11-for-registries-with-one-reading-of-every-response) HTTP/1.1 for registries, with one reading of every response
- [ADR-020](#adr-020-tls-scope-widened-to-a-complete-implementation) TLS scope widened to a complete implementation
- [ADR-021](#adr-021-aead-built-for-constant-time-not-speed) AEAD built for constant time, not speed
- [ADR-022](#adr-022-the-tls-13-handshake-sans-io-compatibility-mode-stateless-tickets) The TLS 1.3 handshake: sans I/O, compatibility mode, stateless tickets
- [ADR-023](#adr-023-constant-time-is-measured-not-assumed) Constant time is measured, not assumed
- [ADR-024](#adr-024-x509-validation-like-webpki-not-like-a-browser) X.509 validation like webpki, not like a browser
- [ADR-025](#adr-025-x509-measured-against-x509-limbo-and-expired-roots-refused) X.509 measured against x509-limbo, and expired roots refused
- [ADR-026](#adr-026-rsa-without-crt-and-without-key-generation) RSA without CRT and without key generation
- [ADR-027](#adr-027-a-fuzzer-of-our-own-structure-aware-and-checked-by-mutants) A fuzzer of our own, structure aware and checked by mutants
- [ADR-032](#adr-032-apparmor-is-written-here) AppArmor is written here
- [ADR-033](#adr-033-the-profile-language-is-read-the-way-flex-and-bison-read-it) The profile language is read the way flex and bison read it

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


## ADR-006: HTTP/2 and gRPC on blocking threads, hardened for local peers first

The HTTP/2 connection is a state machine without I/O (`h2.rs`), so it can
run under any loop: QuantyDB's reactor, a TLS layer, or a plain thread.
The gRPC server on top (`grpc.rs`) uses the plainest of those: a thread
reads each connection, unary calls run on a fixed pool, and every
streaming call gets its own thread. Watches live for hours, and a pool
would let a few hundred of them starve every unary call.

That shape was chosen because the first consumer, QuantyKube, serves one
API server over a Unix socket: a few connections, a few hundred streams,
a trusted peer. It was checked against curl's nghttp2 in both directions
and against etcd's Go client.

What it already refuses: frames above the advertised size, header blocks
above twice the advertised list size (which also ends the CONTINUATION
flood), windows past 2^31-1, streams beyond the advertised limit, request
messages above 16 MiB, and streaming responses beyond 4 MiB waiting on
flow control, after which the sender blocks.

What a peer on a network could do beyond that, and what now stops it:

- Opening and resetting streams as fast as it can (the 2023 rapid reset
  attack, CVE-2023-44487), or making this side reset them with stream
  errors (CVE-2025-8671). A unary call reset before a pool thread picks it
  up is dropped without running. Every reset, sent or provoked, spends
  from a budget of 1000 that refills at 33 a second, nghttp2's numbers;
  an empty budget ends the connection with GOAWAY ENHANCE_YOUR_CALM.
- Flooding PINGs or SETTINGS and never reading the replies. More than
  1000 replies from one read of the socket end the connection the same
  way, and so do 1000 frames in a row that give nothing to act on:
  PRIORITY, empty DATA or CONTINUATION, stray acks, SETTINGS, unknown
  types. A write the peer does not take within 30 seconds drops the
  connection, since the thread that reads a connection also writes its
  replies.
- Opening the maximum number of streaming calls, each a thread. They are
  capped at 256 per connection and 1024 per server, and a call beyond
  either cap ends at once with RESOURCE_EXHAUSTED. The advertised
  MAX_CONCURRENT_STREAMS stays at 1000.
- Idle connections. A connection has 10 seconds to send its preface and
  SETTINGS, and one with no open stream that sends nothing for 5 minutes
  gets GOAWAY NO_ERROR.

Every number is a field of `grpc::Options` or `h2::Limits`, and
`serve_unix` takes the defaults. Not bounded here: the number of
connections, each a reading thread. A listener that accepts connections
from another machine (ADR-003) caps those itself.

**The cost:** a client that cancels more than 33 calls a second for long,
holds more than 256 streaming calls on one connection, or stops reading
for 30 seconds now loses its call or its connection, where before it was
served.

## ADR-007: gzip and tar stream with fixed memory, and accept what zlib accepts

QuantyKube's node runtime unpacks OCI image layers, which are gzip
compressed tar archives from a registry nobody here controls. Both
readers are written here (`inflate.rs`, `tar.rs`), streaming, so a layer
is unpacked as it arrives and never held whole.

**Memory is fixed per reader,** a 64 KiB ring, a 32 KiB input buffer and
the Huffman tables for gzip, and capped long names and PAX records for
tar. A hostile layer can cost time in proportion to its size and nothing
else. Errors poison the gzip reader, so a caller cannot read on past
corruption by accident.

**Where to be strict.** Every check that protects the unpacker is
strict: CRC and length trailers, header checksums, truncation anywhere,
over-subscribed codes, distances before the start. Where RFC 1951 is
stricter than the decoders the ecosystem uses, this follows them: a
literal code with a single one bit symbol is accepted, as zlib and Go
accept it, because refusing a layer that containerd unpacks without
complaint protects nothing. Bytes after the last gzip member are an
error, as they are for Go's reader, which containerd uses.

**What the caller must do,** and the runtime will: read the gzip stream
to its end even after tar reports the last entry, since the trailer is
checked only there; handle OCI whiteout files; and reject entry paths
with `safe_relative`, since a `..` in a layer path is the oldest
container escape there is.

**Measured:** about 195 MB/s decompressing, against 130 to 170 MB/s for
`gzip -dc` on the same machine. Tests compare against Python's zlib,
the gzip command and GNU tar in all three formats, and each was shown to
fail when the code was broken on purpose.

## ADR-008: JSON is strict, and one document has one meaning

Image manifests, image configs, registry token responses and CNI
configuration are JSON from outside, and some of it is hashed: an image
is named by the digest of its manifest's bytes. `json.rs` parses RFC
8259 strictly and refuses what would let one document mean two things:

- duplicate keys in an object, compared after unescaping, because which
  duplicate wins differs between parsers, and a manifest that one tool
  reads one way and another tool the other is how verification is
  bypassed;
- a byte order mark, which RFC 8259 forbids senders to add and which
  would give one value two encodings with different digests;
- lone surrogates, control characters in strings and every relaxation
  (trailing commas, comments, leading zeros, NaN).

Numbers keep their source text. An integer is read only if it fits, and
`1e400` is kept as written rather than becoming infinity, so nothing is
silently rounded on the way through. Nesting stops at 128 levels and the
parser uses no recursion, so input cannot overflow the stack.

**Checked against:** JSONTestSuite, all 188 documents that must be
rejected are rejected and 93 of the 95 that must be accepted are; the two
others contain duplicate keys and are listed as refused on purpose. The
writer's output matches Python's `json.dumps` byte for byte.

**The cost:** a document with duplicate keys that other tools accept is
refused here. If a real registry ever serves one, this record is where
that gets decided again.

## ADR-009: HTTP/1.1 for registries, with one reading of every response

QuantyKube's image puller fetches manifests and blobs from OCI
registries. Every registry speaks HTTP/1.1, and HTTP/2 to them would need
TLS with ALPN first. `http1.rs` is a blocking client: GET and HEAD
without a body, over any `Read + Write` stream, so TLS goes under it
later without changes here. A connection is reused only when the
response ended exactly where its framing said.

**Framing has one reading or none.** The responses come from servers
nobody here controls, often through a CDN, and the known HTTP/1.1
attacks are two parsers disagreeing about where a message ends. So, as
RFC 9112 requires or allows: Content-Length together with
Transfer-Encoding is refused; Transfer-Encoding must be exactly
`chunked`; Content-Length must be digits, and repeats must agree; folded
lines, whitespace before a colon, control bytes in fields, lines not
ended by CRLF and chunk sizes past 64 bits are refused. Requests are
checked the same way, so no caller value can add a line.

**Memory is fixed,** as in ADR-007: the head, 1xx responses included,
is held up to 64 KiB and 100 fields, trailers get the same and are
dropped, a chunk-size line may be 4 KiB, and the body streams through a
16 KiB buffer.

**Redirects and credentials are the caller's.** Registries send blob
downloads to storage on another host. `resolve` says where a Location
points (RFC 3986 section 5.2, checked against every example there);
whether to go, and keeping the registry token away from the storage
host, is decided in QuantyKube. URLs with user info are refused.
`parse_www_authenticate` reads the Bearer challenge, and refuses one that
names a parameter twice, for the reason in ADR-008.

Tested on in-memory streams and over a local TCP socket; each check was
shown to fail its test when broken on purpose.

**The cost:** a registry or proxy that sends bare LF line endings,
folded headers or any transfer coding but chunked cannot be pulled from
until this record is revisited.

## ADR-020: TLS scope widened to a complete implementation

Supersedes the **Scope** section of ADR-003. Everything else in ADR-003
stays in force: why TLS is written here, the rules for writing it, the
measuring instruments, and the condition under which it may be called
secure. Until that condition is met, every public text calls it
unreviewed.

ADR-003 kept the scope narrow and said it would widen only when a real
peer needed more. Planning the consumers through showed that every item it
deferred already has such a peer, so the scope is set once, in full,
instead of being reopened item by item:

- TLS 1.2 (RFC 5246): container registries, corporate proxies and
  middleboxes that still terminate 1.2. Only ECDHE key exchange with AEAD
  suites, and Extended Master Secret (RFC 7627) is required of the peer.
- Session resumption with PSK: the image puller opens many short
  connections to the same registry.
- Server side as well as client side: QuantyKube serves etcd's gRPC API
  with mutual TLS, and the QuantyDB server will serve TLS.
- ChaCha20-Poly1305 and AES-256-GCM next to AES-128-GCM, P-384, Ed25519,
  and RSA PSS signing from 2048 to 4096 bits: these are what certificates
  and peers in the wild actually use, and a client that cannot verify a
  P-384 intermediate cannot talk to a public registry.
- Loading the system trust store from PEM files, for the same registries.
- Name Constraints, Extended Key Usage, and SAN matching for DNS and IP
  with wildcards (RFC 6125).
- Generating keys, certificates and CSRs, because QuantyKube issues its
  own cluster certificates.
- X25519MLKEM768 with ML-KEM-768 (FIPS 203), last, because Go offers it by
  default and traffic recorded today is decrypted by the first large
  quantum computer.

**Not built, and why.**

- 0-RTT data: it is replayable by design (RFC 8446 section 8), and every
  application on top would have to prove its first flight idempotent.
- Renegotiation: the source of the triple handshake and renegotiation
  injection attacks; TLS 1.3 removed it.
- SSL 3.0, TLS 1.0 and 1.1, CBC suites, RC4, 3DES, static RSA key
  exchange: each is broken or lacks forward secrecy, and no peer we target
  requires one.
- Compression: CRIME.
- DTLS: no consumer uses datagrams.
- QUIC is not part of this work, but the handshake is kept apart from the
  record layer, handshake messages in and out plus the secrets per
  epoch, so a QUIC transport can drive it later without a rewrite.

**Shape.** A sans-IO state machine that takes bytes in and gives bytes
out, with a thin blocking wrapper over `Read + Write`, so it runs under
QuantyDB's own reactor as well as over a `TcpStream`. Configuration is
safe by default: TLS 1.3 only, hostname verification on. There are no
switches that turn verification off; a caller who must trust one
specific certificate configures it as a root.

**What it costs.** ADR-003 estimated eight to fifteen thousand lines. With
TLS 1.2, a server, P-384, Ed25519, RSA signing, certificate issuance and
ML-KEM it is closer to twenty thousand, and the attack surface grows with
every one of them. TLS 1.2 in particular brings back a second key schedule
and a second state machine that has to be kept as strict as the first.

**Rejected:** keeping the narrow scope and widening per peer. Each
widening would have touched the handshake again, and a handshake
reopened five times is reviewed five times or not at all.

## ADR-021: AEAD built for constant time, not speed

AES is bitsliced four blocks at a time: the 64 bytes of four blocks are
transposed into eight 64-bit bit planes and the S-box is the Boyar and
Peralta circuit, so no byte value ever selects a memory address. GHASH
multiplies with integer multiplications on operands spread out with
three zero bits between data bits, the method of BearSSL's
`ghash_ctmul64`, instead of the usual table of multiples of H.
ChaCha20-Poly1305 needs no such care; it is constant time as written.

**What it costs.** Measured once while writing this, on the development
machine: AES-128-GCM here is roughly two orders of magnitude slower than
OpenSSL's, which uses the AES and carryless multiply instructions, and
ChaCha20-Poly1305 here is about four times faster than AES-GCM here. For
the consumers in ADR-003 (control plane traffic, image pulls) this is
acceptable; for bulk transfer it is not, and hardware AES behind its own
record is the answer then, as ADR-003 already says.

Because of that ratio, a server built on this crate prefers
ChaCha20-Poly1305 whenever the client offers it, and falls back to
AES-GCM otherwise. Clients state their own preference as usual.

**Narrowed on purpose:**

- Only AES encryption is built. GCM and TLS never run AES backwards.
- No AES-192: no TLS cipher suite uses it.
- Only 96-bit nonces and 128-bit tags, the only ones TLS uses. Other
  nonce lengths in GCM go through GHASH and are a known source of nonce
  collisions.
- Opening checks the tag before decrypting anything, and on failure leaves
  the buffer exactly as it was, so no unauthenticated plaintext can leak
  to a caller that ignores the error.

**Rejected:** a 32-bit bitsliced AES on two blocks, which is simpler but
half as fast on the 64-bit machines every consumer runs on; and table
based AES with the tables preloaded into cache before every block, which
narrows the leak but does not close it.

## ADR-022: The TLS 1.3 handshake: sans I/O, compatibility mode, stateless tickets

**Shape.** A connection takes received bytes with `read_tls`, hands out
bytes to send with `take_tls`, and carries plaintext with `write` and
`read`. It never touches a socket. Each handshake state is its own type
that consumes the next message and returns the next state, so a message
that arrives out of order has no state that would accept it. The key
schedule hands out secrets and the record layer derives keys from them,
which is the split a QUIC transport needs later.

**Choices a later reader might question:**

- The client always uses middlebox compatibility mode (RFC 8446 D.4): a
  random 32-byte legacy session id and a dummy change_cipher_spec before
  its second flight. Costs 38 bytes per handshake; without it, some
  corporate middleboxes drop TLS 1.3 handshakes as malformed 1.2.
- Resumption only with `psk_dhe_ke`, so every resumed connection still
  runs a fresh key exchange and a stolen ticket does not decrypt it.
  No 0-RTT (ADR-020).
- Tickets are stateless: the session, sealed with ChaCha20-Poly1305
  under a key that lives only in the server process. A restart
  invalidates every ticket, which costs each client one full handshake.
  Sharing the key across server instances would mean distributing a
  secret that decrypts every ticket, and is not built until a deployment
  needs it.
- The server sends two tickets per handshake and the client uses each
  once (RFC 8446 C.4), so two parallel connections can both resume
  without reusing a ticket.
- A HelloRetryRequest carries no cookie: the server keeps the first
  hello's hash in the connection, which exists anyway in this design.
- Limits against a peer that only wants to occupy memory or time: 256
  KiB per handshake message, and 32 records in a row that carry nothing
  (empty data, change_cipher_spec, warning alerts).

**Not public yet.** Building a configuration needs a certificate
verifier, and the only correct verifier is X.509 path validation, which
does not exist yet. The constructors therefore stay inside the crate and
only the tests use them, with a verifier that compares a raw Ed25519
key. There is deliberately no way to build a client that skips
verification, not even temporarily.

**Checked by:** the RFC 8448 traces, where the client, started from the
trace's ClientHello and key, has to produce every one of the trace's
client records byte for byte, and the server has to produce the trace's
ServerHello; loopback tests of both sides against each other; and
tampered hellos in both directions, each of which must end with the
alert RFC 8446 prescribes.

## ADR-023: Constant time is measured, not assumed

`tests/tls_timing.rs` runs each secret handling primitive on a fixed and
a random class of secret input in random order and compares the two
timing distributions with Welch's t-test, as dudect does. Its first test
is a comparison with an early exit, which it must flag, so a run that
cannot see a leak fails instead of passing.

**It already paid for itself.** Ed25519 signing showed |t| of 27 with
ten thousand samples. The cause was the bit by bit reduction modulo the
group order: the source selects with a mask, `(r & !m) | (s & m)`, and
the optimizer recognised that the mask is all ones or zero and compiled
a branch on the borrow. Zero scalars reduced twice as fast as random
ones. Hiding the mask behind `std::hint::black_box` closed it, and the
same guard went onto the one masked selection in Poly1305. The X25519
ladder, which selects through the same kind of mask inside
`Fe::cswap`, was already guarded and measured clean.

**What it cannot show.** A t-test finds differences in the mean or the
spread; it sees nothing on inputs it does not generate, nothing below
its resolution with the given number of samples, and nothing on a
processor that is not the CI runner's. It is evidence against a leak,
not a proof, which is why the source still follows the rules of ADR-003
and why a review is still required before anything is called secure.

**Cost.** A CI job of a few minutes. Shared runners are noisy, so a
primitive only fails when two consecutive runs cross the threshold; a
leak large enough to matter crosses it every time.

## ADR-024: X.509 validation like webpki, not like a browser

Path validation follows RFC 5280 where TLS needs it and takes the
stricter reading where RFC 5280 leaves room, as rustls' webpki does:

- Names are matched against subjectAltName only. The subject common
  name is never used as a host name (RFC 6125 6.4.4 allows it as a
  fallback; every current browser has dropped it). Wildcards only as the
  whole leftmost label, standing for exactly one label, never as `*.tld`.
- Issuers are found by the exact DER of their subject Name. RFC 5280
  describes a normalised comparison; in practice CAs encode the issuer
  of a certificate by copying their own subject, and byte comparison
  cannot be tricked by two encodings that normalise to the same Name.
- A trust anchor is a subject, a key and optional name constraints. Its
  own validity period, key usage and path length are not checked (RFC
  5280 6.1.1(d)), so an expired root in the system store still anchors
  chains, as it does for OpenSSL and Go.
- Intermediates must be v3 CAs, in their validity period, with
  keyCertSign if KeyUsage is present and the requested purpose if
  ExtendedKeyUsage is present. A CA certificate is refused as a leaf.
- Name constraints are evaluated for DNS names, IP addresses and
  directory names, including a wildcard that could stand for an excluded
  name. Constraints of other kinds (email, URI) fail closed when the
  certificate carries a name of that kind.
- Unknown critical extensions are refused, which includes certificate
  policies when marked critical: policies are not evaluated.
- Not built: CRLs, OCSP, certificate transparency. A private cluster
  rotates short lived certificates instead; for public servers this is
  the same position Go's crypto/tls takes by default.

**Limits against a hostile peer.** At most 32 intermediates are
considered, paths are at most six intermediates deep, and one validation
performs at most 64 signature checks. Two tests show that each of the
last two limits is reached on its own: a valid chain eight deep, and two
levels of sixteen look-alike issuers that all really sign the level
below.

**Rejected:** chain building that fetches missing intermediates over
the network (AIA). It makes validation depend on an HTTP request made
on behalf of the peer, and a server that sends an incomplete chain is
misconfigured.

**Checked by:** chains issued here and broken one way at a time; every
root in the system store parsed; chains issued here verified by
`openssl verify`, chains issued by OpenSSL verified here; and handshakes
over real sockets against OpenSSL and Go in both directions, with and
without client certificates. The x509-limbo suite follows once ECDSA
exists, because nearly all of its chains are ECDSA or RSA.

## ADR-025: X.509 measured against x509-limbo, and expired roots refused

Supersedes one point of ADR-024: an expired (or not yet valid) root no
longer anchors a chain. ADR-024 followed webpki in treating a trust
anchor as information without a validity period; OpenSSL and Go both
refuse an expired root, x509-limbo expects the refusal, and a root past
its date is a root nobody maintains. Everything else in ADR-024 stands.

With ECDSA built, the x509-limbo suite runs in CI against a pinned
commit. Its first run found:

- a real bug: when one branch of the path search reached the depth
  limit, the whole search stopped, so valid chains that needed another
  branch (the BetterTLS path building cases) were refused. Only an
  exhausted budget ends the search now;
- a real gap: no limit on name constraint comparisons, so a CA with
  2048 constraints over a leaf with 2048 names cost millions of
  comparisons. Now at most 250,000 per validation, as in webpki;
- self-issued intermediates were checked against name constraints,
  which RFC 5280 6.1.3(b) exempts;
- RFC 5280 rules that were not enforced and now are: NameConstraints,
  PolicyConstraints and a SubjectAltName under an empty subject must be
  critical, key identifiers must not be, dNSName entries and constraints
  must be valid host names (no underscores, no leading dot), serial
  numbers must be positive and at most 20 octets, a leaf must not carry
  keyCertSign or name constraints, and a CA must not have an empty
  subject.

The suite now agrees on every case it runs. What it does not run, and
why, is listed in `tests/tls_limbo.rs`: CRL and ML-DSA cases, the cases
limbo itself marks as pedantic CA/Browser Forum issuance rules, and the
cases that configure a chain depth this API does not expose. Where this
crate deliberately disagrees, each case is named there with its reason;
in short, it is stricter about CA certificates as leaves and about email
name constraints, and more lenient about missing key identifiers and the
extensions of trust anchors, none of which affects what a chain proves.

**Cost:** certificates with underscores in DNS names, which some
private networks issue, are refused. The CA/Browser Forum has forbidden
them in public certificates since 2019.

## ADR-026: RSA without CRT and without key generation

RSA is here because Kubernetes tooling and most public registries use
RSA certificates (ADR-003). It verifies PKCS#1 v1.5 and PSS signatures
and signs with PSS (TLS 1.3 CertificateVerify) and PKCS#1 v1.5
(certificates, and TLS 1.2 later), for moduli of 2048 to 4096 bits.

- **No Chinese remainder theorem.** The private exponentiation runs once
  modulo n, with a fixed 4-bit window that reads the whole table for
  every lookup. CRT would be about three times faster, but a fault in one
  of its two halves hands out a signature from which the modulus can be
  factored (the Bellcore attack). Every signature is also verified
  before it leaves, which catches that fault in either design.
- **Blinding** multiplies the message by r^e before the exponentiation
  and the result by r^-1 after, for a fresh random r. r^-1 is computed
  as r^(phi(n) - 1) with the same constant time exponentiation, so the
  inversion does not need a variable time extended Euclid on a secret.
  This costs a second private exponentiation per signature.
- **Cost:** an RSA-2048 signature takes a few milliseconds and RSA-4096
  tens of milliseconds, once per handshake on the side that signs. A
  server that cares can use an ECDSA certificate.
- **No key generation.** Generating RSA keys needs constant time prime
  testing and is a large piece of code for a key type nobody new should
  choose; QuantyKube issues ECDSA or Ed25519 keys. RSA keys are loaded
  from PKCS#1 or PKCS#8.
- **Refused keys:** moduli outside 2048 to 4096 bits or not a whole
  number of bytes, even exponents, exponents above 2^32, more than two
  primes, and keys whose parts do not fit together (p*q must be n, and
  e*d must be 1 modulo p-1 and q-1, which also accepts keys where d was
  computed modulo lcm(p-1, q-1), as OpenSSL does).
- PKCS#1 v1.5 verification builds the expected encoding and compares it
  whole instead of parsing the padding, which is how the 2006
  Bleichenbacher forgery against lax parsers worked.

**Checked by:** Wycheproof PKCS#1 and PSS verification for 2048, 3072 and
4096 bits, the deterministic PKCS#1 signatures of Wycheproof's signature
generation suite reproduced byte for byte, x509-limbo's RSA chains, the
timing test on RSA-2048 signing, and handshakes with RSA certificates
against OpenSSL and Go.

## ADR-027: A fuzzer of our own, structure aware and checked by mutants

`tests/tls_fuzz.rs` fuzzes the DER and X.509 parsers, PEM, private keys,
every handshake message and extension parser, and whole client and
server connections fed in pieces of random size. Inputs start from real
ones and are mutated; the property is that nothing panics. Each case is
derived from a seed and its number, so a failure prints both and
replays exactly. CI runs 200,000 cases per target with a new seed each
run.

**Not cargo-fuzz or libFuzzer:** both are dependencies from outside
(ADR-001), and coverage guidance needs instrumentation this crate does
not have. Without coverage, the fuzzer has to know the format instead:
it finds length prefixes that match their content and mutates behind
them, and it mutates inside single extensions and re-encodes the
message, because random bytes almost never get past TLS's nested
lengths.

**Checked like every other test,** by breaking the code: four mutants
at four depths (a length read without its bounds check, a DER length
trusted, a record length trusted, an X25519 share indexed without a
length check) must each be found. The first version of the fuzzer
missed the deepest one for two reasons that only the mutant revealed:
plain byte mutation never kept a key share and its length consistent,
and the client target replayed a server flight recorded for another
client, so every case ended at the session id check.

**Cost:** without coverage feedback, paths behind several consistent
checks are reached rarely; the structure aware mutations reduce that,
they do not remove it.

## ADR-028: TLS 1.2 as a fallback, off by default

TLS 1.2 exists for peers that do not speak 1.3 yet. `ClientConfig` and
`ServerConfig` offer it only after `enable_tls12()`; without that call
nothing changes from ADR-022. When enabled, the client offers both
versions in one ClientHello and the server answers 1.2 only to a client
that does not offer 1.3.

**What is built, and nothing more:** ECDHE over X25519, P-256 or P-384,
with AES-128-GCM, AES-256-GCM or ChaCha20-Poly1305, authenticated by
ECDSA, Ed25519 (RFC 8422) or RSA. The extended master secret (RFC 7627)
is required from the peer on both sides: without it, a man in the middle
can make two connections share one master secret (the triple handshake
attack), and every implementation that matters has sent it for a
decade. Signatures may use RSA PKCS#1 v1.5, which TLS 1.2 allows and
1.3 does not; SHA-1 and the RFC 5246 default of SHA-1 when
signature_algorithms is missing are refused.

**Left out on purpose:** renegotiation (any handshake message after the
handshake ends the connection), session resumption by id or ticket (a
full handshake costs one more round trip and keeps no state), static
RSA and finite field Diffie-Hellman key exchange, CBC, compression, and
False Start. Exported keying material (RFC 5705) is always derived with
the context, even an empty one.

**Downgrades:** a server that also speaks 1.3 and answers 1.2 puts
`DOWNGRD\x01` at the end of its random (RFC 8446 4.1.3); the client,
which always offers 1.3, refuses a 1.2 answer carrying either marker.
The random is covered by the ServerKeyExchange signature, so an attacker
cannot remove it.

**Code:** the 1.2 handshake has its own states (`client12.rs`,
`server12.rs`, shared messages and key derivation in `tls12.rs`); the
record layer and the connection core switch on the negotiated version.
In 1.2 change_cipher_spec is not ignored as in 1.3 but switches the read
keys, and only when the handshake has keys ready for it.

**Checked by:** handshakes against OpenSSL (`-tls1_2`) and Go
(`MaxVersion` 1.2) in both directions, with and without client
certificates, with Ed25519, P-256 and RSA keys, every one of the six
suites forced once on the OpenSSL server, and the exported keying
material compared with Go's; loopback tests of every suite and group,
of refused hellos on both sides, of the downgrade marker and of
change_cipher_spec out of place; records built by hand from the RFCs;
fuzzing of the 1.2 hellos; and fourteen mutants, two of which (the
master secret label and the key block seed) only interop can find,
since both sides of a loopback would agree on the same mistake.

## ADR-029: X25519MLKEM768 by default, with X25519 sent along

TLS 1.3 connections use the hybrid X25519MLKEM768
(draft-ietf-tls-ecdhe-mlkem) by default: ML-KEM-768 (FIPS 203) and
X25519 together, the shared secret both concatenated. Traffic recorded
today stays confidential against a future quantum computer as long as
ML-KEM holds, and against everything else as long as X25519 holds. Go
since 1.24, OpenSSL since 3.5 and the major browsers do the same.

**Two key shares:** the client sends the hybrid share (1216 bytes) and
an X25519 share. A server without ML-KEM takes the X25519 one, so the
default costs servers that are not ready yet no extra round trip. The
cost is a ClientHello about 1.2 KB larger. `set_groups` changes the
order or drops groups, on both sides; TLS 1.2 never uses the hybrid.

**ML-KEM-768** is written from FIPS 203 with SHA-3 and SHAKE from FIPS
202 under it. Coefficients are reduced with multiplications and masked
subtractions only. In particular no secret value is divided: a compiler
may turn `x / q` into a division instruction whose time depends on `x`,
which is the KyberSlash attack on implementations that did. Implicit
rejection selects the key without a branch, and the re-encryption check
compares in constant time. Keys are checked as FIPS 203 7.2 and 7.3
require (the modulus check of the encapsulation key, the hash check of
the decapsulation key). Only ML-KEM-768 is built.

**Checked by:** NIST ACVP for SHA3-256, SHA3-512, SHAKE128 and SHAKE256
(including their Monte Carlo tests) and for ML-KEM-768 key generation,
encapsulation, decapsulation and both key checks; Wycheproof's ML-KEM-768
suites, including malformed keys and ciphertexts and the implicit
rejection cases; handshakes with Go 1.24 in both directions that
negotiate X25519MLKEM768 and agree on exported keying material; the
timing test on decapsulation of valid against rejected ciphertexts and
on encapsulation; loopback tests of the fallback and of broken shares;
and mutants, one of which is an early exit in the re-encryption
comparison that only the timing test can see.

## ADR-030: Certificate signing requests

`x509::csr` writes PKCS#10 requests (RFC 2986) for a key, a common name
and subjectAltNames, and reads them back. Reading checks the request's
signature with the key inside it, so a CA that issues from a parsed
request knows that the key's holder asked for those names. Together
with `build::issue` this covers what a private CA needs: a node makes
its key and a request, the CA checks the request and issues for the key
in it, and the private key never leaves the node.

Only the extensionRequest attribute is read, and from it only
subjectAltName with DNS names and IP addresses; anything else a request
asks for is ignored, since the CA decides what goes into the
certificate. A name kind other than those two fails the request rather
than being dropped silently, and so do a DNS name that is not a valid
host name and a repeated extensionRequest or subjectAltName. A wildcard
is a valid request; whether to grant it is the CA's decision.

**Checked by:** OpenSSL verifying requests written here (Ed25519, P-256,
RSA) and showing their names; requests written by OpenSSL (Ed25519,
P-384, RSA) read here, with a flipped signature bit refused, and a
certificate issued from each verified by OpenSSL; a forged request with
another key's signature refused; the fuzzer; and two mutants.

## ADR-031: The client prefers ChaCha20-Poly1305 too

ADR-021 put ChaCha20-Poly1305 first on the server. The client now does
the same. Measured on one x86-64 machine with 16 KiB records, sealing
runs at about 370 MB/s with ChaCha20-Poly1305 and 80 MB/s with
AES-128-GCM; OpenSSL with AES-NI does about 13 GB/s and 3 GB/s. For a
client pulling large image layers over TLS, the cipher can be what
limits throughput.

A server that honours the client's order (OpenSSL by default, and so
does this crate's server, which prefers ChaCha20-Poly1305 itself) will
choose ChaCha20-Poly1305. A server that applies its own order, as Go
does with hardware AES, still chooses AES-GCM; the client then runs at
the slower rate, and that is correct and secure, only not fast.

Both ciphers stay offered. Nothing changes for security: both are
AEADs with 256-bit or 128-bit keys, and both are constant time here.

## ADR-032: AppArmor is written here

QuantyCore gets its own AppArmor stack under `quantycore::apparmor`: a
parser for the profile language, a compiler from profiles to the
automata the kernel enforces, the binary policy format, and the loader
that hands it to the kernel. The first consumer is QuantyKube's node
runtime, which must start containers under the profile the kubelet asks
for (`RuntimeDefault`, `Localhost`, `Unconfined`).

**Why here, although AppArmor is not a wire protocol.** ADR-004 put the
wire protocols here because two parts of QuantyKube need the same stack.
AppArmor fits the same reasoning one level down: the binary policy is a
format the kernel reads, versioned and negotiated through the features
the kernel publishes, and getting it wrong fails silently in the same
way a protocol does. Keeping it here leaves QuantyKube with no knowledge
of kernel policy formats; its syscall crate (its ADR-013) stays a thin
boundary and does not grow a compiler. The pieces are useful without
Kubernetes as well, for any Quanty server that wants to confine itself.
Nothing in it needs `unsafe`: securityfs and procfs are files, so ADR-001
holds without a boundary crate.

**Target.** The language and the behaviour of upstream AppArmor v5.0.2
(commit 909affc32a13), the newest release when this started, which
includes everything `apparmor.d(5)` describes for 4.x. The reference is
`apparmor_parser` built from that same commit: what it accepts is
accepted here, what it refuses is refused, and what it would load gives
the same permissions here, path by path. Which rule kinds end up in a
binary policy is decided by the kernel's feature set, as upstream decides
it, so a policy for an older kernel leaves out what that kernel cannot
enforce.

**Not built, and why.**

- The Python tools (`aa-genprof`, `aa-logprof`, `aa-status` and the
  rest), audit log parsing and profile generation from logs: they help a
  person write profiles. Nothing a runtime does depends on them.
- The notification daemon and the listener for `prompt` upcalls. The
  `prompt` qualifier and profile mode are part of the language and are
  compiled, so a profile using them means here what it means upstream;
  answering the upcalls is a desktop feature.
- The policy cache (`-W`, `/var/cache/apparmor`). A cache is a second copy
  of the truth that can go stale; container profiles are small and are
  compiled when they are loaded.
- zstd compressed policy: the kernel accepts uncompressed policy whatever
  it supports, and a zstd encoder would be a large piece of code for a
  smaller upload.
- `change_hat` and `change_profile` from inside a running process, and
  the label query interface of libapparmor. The runtime only sets the
  profile for the next exec. Hats and `change_profile` rules are still
  parsed and compiled, since profiles use them.
- A command line tool. The API is a library; tests and CI drive it.

**The API the runtime needs, shaped by QuantyKube's ADR-013.** Between
the clone and the exec, the runtime's child makes only syscalls on memory
prepared before the clone. So the exec transition is split: before the
clone, the parent asks this crate for the bytes to write (`exec
<profile>`) and which attribute file to use, the stacking one
`attr/apparmor/exec` or, only when the stacking file is missing and
AppArmor's module parameter says it is enabled, the old `attr/exec` that
other security modules share, as libapparmor decides; the child opens and
writes with its own syscalls. A plain function over `std::fs` does the
same for callers that are single threaded. Two traps go into that API's
documentation, because runc fell into both: the kernel lets a task write
only its own attribute, so a multi threaded caller must use
`/proc/thread-self`, and the file must be opened on the host's procfs
before the pivot, never through a `/proc` the container image can
control (CVE-2019-16884).

**How it is measured,** before the code it measures: upstream's
`parser/tst` at the same commit (every `simple_tests` case accepted or
refused as marked, every `equality.sh` pair equal or unequal as marked);
a differential test that reads `apparmor_parser`'s binary policy back
into automata and compares them with ours through the product automaton;
the profiles shipped by upstream, Ubuntu, Debian, Docker and containerd
as a corpus; a CI job on an Ubuntu runner that loads our policy into a
real kernel and checks that allowed operations succeed and refused ones
fail with EACCES; a structure aware fuzzer; and mutants that each named
test must catch.

**What it costs.** Upstream's parser and compiler are about twenty
thousand lines of C and C++; this will not be much smaller. The language
grows with every release and the kernel format with every new mediation
class, so following upstream is a duty that does not end. Hosts running
an older `apparmor_parser`, such as Ubuntu 24.04 with 4.0.1, may refuse a
profile that uses 5.0 syntax and is accepted here. Until all of the above
runs in CI and someone who did not write it has reviewed it, every public
text calls it unreviewed (ADR-002).

## ADR-033: The profile language is read the way flex and bison read it

Upstream does not define the profile language in a document precise
enough to implement from. `apparmor.d(5)` describes it; the flex scanner
and the bison grammar of `apparmor_parser` decide it, down to which of
two overlapping patterns wins. So the lexer here (`lexer.rs`) is upstream's
rule table, in upstream's order and with upstream's thirty start
conditions, run by a small scanner (`scan.rs`) with flex's semantics:
longest match among the rules active in the current condition, the
earlier rule on a tie, trailing context counted for the length but not
consumed. The patterns are written in flex notation so that they can be
compared with upstream's line by line. Quirks come along on purpose: the
word `open` is the same token as `{`, a file whose last line is a comment
without a newline is an error, and `include` must be followed by a blank.

**The parser follows the bison grammar's productions.** The grammar has
no conflicts, so it accepts exactly the language its productions
describe, and a recursive descent parser that follows them accepts the
same. Checks upstream makes inside grammar actions (permission strings,
names, values) live in a separate semantic pass, so the parser is only
the grammar. The one thing the grammar does to the lexer is kept: which
includes have been read is recorded per profile block, swapped right
after a profile's `{` and right after its `}`, and the parser tells the
lexer at exactly those points without reading further ahead.

**Limits upstream does not have,** because input is treated as hostile:

- Profiles, blocks and conditionals nest at most 1024 deep, held on an
  explicit stack. Upstream's bison stack gives out at a few thousand;
  its own suite nests a hundred.
- Parentheses in conditions nest at most 128 deep; expressions are the
  one place parsed by recursion.
- Includes nest at most 64 deep, a parse reads at most 20,000 files and
  64 MiB, and one file at most 16 MiB. Upstream stops a cycle of
  includes only through its include record, which a path spelled two
  ways defeats.
- Matching one token is linear in the bytes looked at.

**Upstream is read for behaviour, not translated.** `apparmor_parser` is
GPL-2.0 and this crate is Apache-2.0. The token patterns, keyword tables
and limits are facts about the language and are taken as such; the code
that implements them is written here from what upstream does, with its
own structure, and no upstream source or comment is copied into it. The
test suites are fetched in CI and read as data, as the TLS suites are.

**Checked by:** upstream's `simple_tests`, all 73,737 cases at the pinned
commit including the ones upstream generates (`tests/apparmor_simple.rs`).
Every case upstream accepts parses here. Cases upstream refuses for
reasons beyond the grammar are counted as pending until the stage that
refuses them exists, against a ceiling in the test that only goes down
and ends at zero. Cases upstream marks as known wrong (TODO) are expected
to behave as upstream behaves, not as it would like to.

**The cost:** a lexer that reproduces upstream's quirks instead of a
cleaner grammar, and one that has to follow every change upstream makes
to its scanner.
