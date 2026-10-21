# Changelog

All notable changes to QuantyCore are recorded here.

The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html) with
the pre-1.0 rule that a minor version may break anything.

## [Unreleased]

### Added

- `LICENSE-QUANTYDB-EXCEPTION`: QuantyCore may be used under the MIT
  License as part of QuantyDB, and only as part of it. Apache 2.0 remains
  the license everywhere else (ADR-040).

## [0.1.1] - 2026-10-21

### Fixed

- The crate builds on Windows and macOS. 0.1.0 used Unix-only parts of the
  standard library to turn paths into bytes, so it built on Linux and
  nowhere else. Paths are now converted portably; the gRPC server's Unix
  socket listener exists only on Unix, where Unix sockets do (ADR-041).

### Added

- CI builds and tests on macOS and Windows as well, with clippy.

## [0.1.0] - 2026-10-21

The first release on crates.io. Everything below depends on the Rust
standard library and nothing else (ADR-001), and has no `unsafe`.

### Added

- Protobuf wire format, reading and writing messages.
- HPACK: a decoder with the dynamic table, and a stateless encoder,
  checked against fourteen recorded encoders.
- HTTP/2, server side, sans I/O; a gRPC server on blocking sockets and a
  unary client.
- gzip and DEFLATE, streaming, and tar (ustar, GNU, PAX), streaming, both
  in fixed memory.
- JSON, strict RFC 8259, checked against JSONTestSuite.
- An HTTP/1.1 client for registries, blocking.
- TLS 1.3 client and server, TLS 1.2 as an opt-in fallback,
  X25519MLKEM768 by default, X.509 validation, issuance and certificate
  requests, and the primitives under them (ADR-020 to ADR-031). Checked
  against NIST ACVP, CAVP, Wycheproof, x509-limbo, OpenSSL and Go, a
  timing test, a fuzzer and mutants. Unreviewed.
- AppArmor: the profile language, a compiler whose automata equal
  upstream `apparmor_parser` 5.0.2's for all of upstream's tests and 435
  real profiles, the binary policy, loading through securityfs, the
  profile for the next exec, and containerd's default container profile
  as `RuntimeDefault` (ADR-032 to ADR-039). Checked in a real kernel, by
  a fuzzer and by mutants. Unreviewed.

[Unreleased]: https://github.com/QuantyRoot/QuantyCore/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/QuantyRoot/QuantyCore/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/QuantyRoot/QuantyCore/releases/tag/v0.1.0
