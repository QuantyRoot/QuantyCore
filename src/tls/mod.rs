//! TLS 1.3 and 1.2, client and server, with the cryptography under them.
//!
//! Unreviewed. Do not rely on it for anything that matters until the
//! conditions in ADR-003 and ADR-020 of `docs/DECISIONS.md` are met.

pub mod auth;
mod client;
mod client12;
pub(crate) mod codec;
mod config;
mod conn;
pub mod crypto;
pub mod error;
pub mod key_schedule;
pub mod kx;
mod loopback;
mod loopback12;
pub mod msgs;
pub mod record;
mod rfc8448;
mod server;
mod server12;
mod stream;
pub mod suites;
mod tls12;
pub mod x509;

pub use client::ClientConnection;
pub use config::{ClientConfig, ServerConfig};
pub use conn::Connection;
pub use error::Error;
pub use server::ServerConnection;
pub use stream::Stream;
