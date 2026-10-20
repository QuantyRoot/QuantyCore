//! AppArmor: the profile language, its compiler, the binary policy the
//! kernel loads, and loading it. Unreviewed; see ADR-032.
//!
//! The reference for every behaviour here is upstream `apparmor_parser`
//! v5.0.2: what it accepts is accepted, what it refuses is refused, and a
//! compiled profile grants what upstream's would grant.

pub mod ast;
pub(crate) mod build;
pub(crate) mod eval;
pub(crate) mod lexer;
pub mod model;
pub mod parser;
pub(crate) mod process;
pub(crate) mod scan;
pub mod source;
pub(crate) mod tables;

pub use source::{Error, FsResolver, Location, MemResolver, Opened, Resolver, Span};

/// Everything `apparmor_parser` does with a profile file short of writing
/// the policy out: parse it with its includes, and check it. An error is
/// what upstream would refuse the file for.
pub fn check(resolver: &mut dyn Resolver, name: &str, text: Vec<u8>) -> Result<(), Error> {
    let parsed = parser::parse(resolver, name, text)?;
    let mut b = build::Builder::new(&parsed.sources);
    let mut policy = b.file(&parsed.file)?;
    let mut p = process::Processor {
        sources: &parsed.sources,
        symtab: b.symtab,
        aliases: b.aliases,
    };
    p.policy(&mut policy)?;
    Ok(())
}
