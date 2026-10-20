//! AppArmor: the profile language, its compiler, the binary policy the
//! kernel loads, and loading it. Unreviewed; see ADR-032.
//!
//! The reference for every behaviour here is upstream `apparmor_parser`
//! v5.0.2: what it accepts is accepted, what it refuses is refused, and a
//! compiled profile grants what upstream's would grant.

pub mod ast;
pub(crate) mod lexer;
pub mod parser;
pub(crate) mod scan;
pub mod source;

pub use source::{Error, FsResolver, Location, MemResolver, Opened, Resolver, Span};

/// Everything `apparmor_parser` does with a profile file short of writing
/// the policy out: parse it with its includes, and check it. An error is
/// what upstream would refuse the file for.
pub fn check(resolver: &mut dyn Resolver, name: &str, text: Vec<u8>) -> Result<(), Error> {
    parser::parse(resolver, name, text).map(|_| ())
}
