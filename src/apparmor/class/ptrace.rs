//! `ptrace` rules: upstream's ptrace.cc.

use super::{
    apply_prefix, conds_upstream, deny_owner, hex, move_value, pattern, perm_words, require_eq,
    x_perms, Head,
};
use super::{ANYONE, CLASS_LABEL, CLASS_PTRACE};
use crate::apparmor::ast::{Cond, PermWord};
use crate::apparmor::compile::rules::RuleSet;
use crate::apparmor::compile::Support;
use crate::apparmor::lexer::T;
use crate::apparmor::model::Prefix;

pub const READ: u32 = 4;
pub const TRACE: u32 = 2;
pub const READBY: u32 = 0x10;
pub const TRACEDBY: u32 = 8;
pub const VALID: u32 = READ | TRACE | READBY | TRACEDBY;

#[derive(Debug, Clone)]
pub struct Ptrace {
    pub head: Head,
    pub peer: Option<Vec<u8>>,
}

fn word(w: &PermWord) -> Result<u32, String> {
    Ok(match (w.t, &w.text[..]) {
        (T::Trace, _) | (T::Write, _) => TRACE,
        (T::TracedBy, _) => TRACEDBY,
        (T::Read, _) => READ,
        (T::ReadBy, _) => READBY,
        (T::Mode, m) => x_perms("ptrace", VALID, m)?,
        (T::Value, b"trace" | b"write") => TRACE,
        (T::Value, b"read") => READ,
        (T::Value, b"tracedby") => TRACEDBY,
        (T::Value, b"readby") => READBY,
        (T::Value, m) => x_perms("ptrace", VALID, m)?,
        _ => 0,
    })
}

impl Ptrace {
    pub fn new(
        perms: &Option<Vec<PermWord>>,
        conds: &[Cond],
        prefix: Prefix,
    ) -> Result<Ptrace, String> {
        let p = perm_words(perms, word)?;
        if p & !VALID != 0 {
            return Err("perms contains invalid permissions for ptrace".into());
        }
        let mut peer = None;
        for c in conds_upstream(conds) {
            require_eq("ptrace", c)?;
            if c.name == b"peer" {
                move_value("ptrace", &mut peer, c)?;
            } else {
                return Err(format!(
                    "invalid ptrace rule conditional \"{}\"",
                    String::from_utf8_lossy(&c.name)
                ));
            }
        }
        deny_owner("ptrace", &prefix)?;
        Ok(Ptrace {
            head: Head {
                prefix: apply_prefix(prefix),
                perms: if p != 0 { p } else { VALID },
            },
            peer,
        })
    }

    pub fn expand(
        &mut self,
        f: &mut dyn FnMut(&mut Vec<u8>) -> Result<(), String>,
    ) -> Result<(), String> {
        match self.peer.as_mut() {
            Some(p) => f(p),
            None => Ok(()),
        }
    }

    pub fn gen(&self, set: &mut RuleSet, s: &Support) -> Result<(), String> {
        if !s.ptrace {
            return Ok(());
        }
        let mut re = format!("({}|){}", hex(CLASS_LABEL), hex(CLASS_PTRACE));
        match &self.peer {
            Some(p) => re.push_str(&pattern(p)?),
            None => re.push_str(ANYONE),
        }
        if self.head.perms & VALID != 0 {
            self.head
                .add(set, &re, self.head.perms, self.head.audit_mask())?;
        }
        Ok(())
    }
}
