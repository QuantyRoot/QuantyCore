//! AppArmor: the profile language, its compiler, the binary policy the
//! kernel loads, and loading it. Unreviewed; see ADR-032.
//!
//! The reference for every behaviour here is upstream `apparmor_parser`
//! v5.0.2: what it accepts is accepted, what it refuses is refused, and a
//! compiled profile grants what upstream's would grant.

pub mod ast;
pub(crate) mod build;
pub mod compile;
pub(crate) mod eval;
pub mod features;
pub(crate) mod lexer;
pub mod model;
pub mod parser;
pub(crate) mod process;
pub(crate) mod scan;
pub mod source;
pub(crate) mod tables;

pub use features::Features;
pub use source::{Error, FsResolver, Location, MemResolver, Opened, Resolver, Span};

/// How to compile: the kernel's features, and bounds on the work.
#[derive(Clone, Debug)]
pub struct Options {
    /// What the kernel supports, as read from
    /// `/sys/kernel/security/apparmor/features` or given as a file. A
    /// policy's own `abi` rule narrows it.
    pub kernel_features: Features,
    /// Features to compile against when the policy declares no abi, as
    /// upstream's -M sets them. When None, upstream's default abi.
    pub policy_features: Option<Features>,
    pub limits: compile::dfa::Limits,
}

impl Default for Options {
    fn default() -> Options {
        Options {
            kernel_features: Features::from_text(features::DEFAULT_ABI.as_bytes())
                .expect("the default abi fits"),
            policy_features: None,
            limits: compile::dfa::Limits::default(),
        }
    }
}

/// Parses, checks and compiles a profile file with its includes.
pub fn compile(
    resolver: &mut dyn Resolver,
    name: &str,
    text: Vec<u8>,
    opts: &Options,
) -> Result<model::Policy, Error> {
    let parsed = parser::parse(resolver, name, text)?;
    let mut b = build::Builder::new(
        &parsed.sources,
        opts.kernel_features.clone(),
        opts.policy_features.clone(),
    );
    let mut policy = b.file(&parsed.file, resolver)?;
    let support = b.support(opts.limits);
    let mut p = process::Processor {
        sources: &parsed.sources,
        symtab: b.symtab,
        aliases: b.aliases,
        support,
    };
    p.policy(&mut policy)?;
    Ok(policy)
}

/// Everything `apparmor_parser` does with a profile file short of writing
/// the policy out. An error is what upstream would refuse the file for.
pub fn check(
    resolver: &mut dyn Resolver,
    name: &str,
    text: Vec<u8>,
    opts: &Options,
) -> Result<(), Error> {
    compile(resolver, name, text, opts).map(|_| ())
}
