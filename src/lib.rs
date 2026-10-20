//! Shared foundations for Quanty projects.
//!
//! Everything here is written in this repository and depends on nothing but
//! the Rust standard library. `docs/DECISIONS.md` records why, and what that
//! costs.
//!
//! Built so far:
//!
//! - [`proto`]: the protobuf wire format, starting with varints and field
//!   keys.
//! - [`hpack`]: HTTP/2 header compression.
//!
//! Planned, in the order the first consumer needs them: HTTP/2 framing,
//! gRPC, and TLS 1.3. None of those exist yet.

#![forbid(unsafe_code)]

pub mod hpack;
pub mod proto;
