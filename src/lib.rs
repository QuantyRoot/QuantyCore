//! Shared foundations for the Quanty projects, written against the standard
//! library alone. `docs/DECISIONS.md` says why and what it costs.

#![forbid(unsafe_code)]

pub mod grpc;
pub mod h2;
pub mod hpack;
pub mod inflate;
pub mod json;
pub mod proto;
pub mod tar;
