# QuantyCore

Shared foundations for the Quanty projects: wire formats, network
protocols and, later, TLS. Written in this repository and depending only
on the Rust standard library.

[![CI](https://github.com/QuantyRoot/QuantyCore/actions/workflows/ci.yml/badge.svg)](https://github.com/QuantyRoot/QuantyCore/actions/workflows/ci.yml)
![Status](https://img.shields.io/badge/status-early-red)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Made by Elchi](https://img.shields.io/badge/made%20by-Elchi-8A2BE2)](https://github.com/Elchi-dev)

## Status

| Part | State |
| --- | --- |
| Protobuf wire format: reading and writing messages | built, tested |
| HPACK: decoder with dynamic table, stateless encoder | built, tested |
| HTTP/2, server side, sans I/O | built, tested |
| gRPC server on blocking sockets, unary client | built, tested |
| gzip and DEFLATE, streaming | built, tested |
| tar: ustar, GNU, PAX, streaming | built, tested |
| JSON, strict RFC 8259 | built, tested |
| HTTP/1.1 client for registries, blocking | built, tested |
| TLS 1.3 | planned, see below |

Planned means no code exists yet.

## TLS

TLS 1.3 will be implemented here, primitives included. It is not written
yet, and when it is, it will be described as unreviewed until the
conditions in [ADR-003](docs/DECISIONS.md#adr-003-tls-is-written-here) are
met. Do not rely on it for anything that matters before then.

## Rules

- No crates from outside the QuantyRoot organization
  ([ADR-001](docs/DECISIONS.md)).
- No `unsafe` in this crate.
- Every decision that might be regretted later is recorded in
  [docs/DECISIONS.md](docs/DECISIONS.md), including what was rejected.

## Building

```
cargo test
```

Rust 1.89 or newer.

## License

Apache License 2.0, see [LICENSE](LICENSE).

QuantyCore is a project by Elchi Studios.
