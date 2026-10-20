//! TLS 1.3 and 1.2, client and server, with the cryptography under them.
//!
//! Unreviewed. Do not rely on it for anything that matters until the
//! conditions in ADR-003 and ADR-020 of `docs/DECISIONS.md` are met.

pub(crate) mod codec;
pub mod crypto;
pub mod error;
pub mod key_schedule;
pub mod msgs;
pub mod record;
mod rfc8448;
pub mod suites;
