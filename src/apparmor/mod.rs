//! AppArmor: the profile language, its compiler, the binary policy the
//! kernel loads, and loading it. Unreviewed; see ADR-032.
//!
//! The reference for every behaviour here is upstream `apparmor_parser`
//! v5.0.2: what it accepts is accepted, what it refuses is refused, and a
//! compiled profile grants what upstream's would grant.

pub mod ast;
pub mod binary;
pub(crate) mod build;
pub mod class;
pub mod compile;
pub(crate) mod eval;
pub mod features;
pub mod kernel;
pub(crate) mod lexer;
pub mod model;
pub mod parser;
pub(crate) mod process;
pub mod runtime_default;
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
        net: policy.net_table.take(),
    };
    p.policy(&mut policy)?;
    policy.net_table = p.net.take();
    policy.support = p.support;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Conditions, hats and child profiles nested as deep as the parser
    /// allows compile in a thread with a 2 MiB stack, the default for
    /// threads a caller spawns.
    #[test]
    fn deepest_nesting_fits_a_small_stack() {
        let n = 1020;
        let mut texts = Vec::new();
        let mut s = String::from("$a = true\n/p {\n");
        s.push_str(&"if $a {\n".repeat(n));
        s.push_str("/x r,\nsignal,\n");
        s.push_str(&"} else { /y r, }\n".repeat(n));
        s.push_str("}\n");
        texts.push(s);
        for open in ["profile c{} {\n", "^h{} {\n"] {
            let mut s = String::from("/p {\n");
            for i in 0..n {
                s.push_str(&open.replace("{}", &i.to_string()));
            }
            s.push_str("/x r,\nsignal,\n");
            s.push_str(&"}\n".repeat(n + 1));
            texts.push(s);
        }
        for t in texts {
            std::thread::Builder::new()
                .stack_size(2 << 20)
                .spawn(move || {
                    let mut r = MemResolver::default();
                    compile(&mut r, "deep", t.into_bytes(), &Options::default()).unwrap();
                })
                .unwrap()
                .join()
                .unwrap();
        }
    }
}
