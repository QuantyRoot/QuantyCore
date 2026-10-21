//! `userns` rules: upstream's userns.cc.

use super::{apply_prefix, conds_upstream, deny_owner, hex, perm_words, Head, CLASS_NS};
use crate::apparmor::ast::{Cond, CondOp, PermWord};
use crate::apparmor::compile::rules::RuleSet;
use crate::apparmor::compile::Support;
use crate::apparmor::lexer::T;
use crate::apparmor::model::Prefix;

pub const CREATE: u32 = 8;
pub const VALID: u32 = CREATE;

#[derive(Debug, Clone)]
pub struct Userns {
    pub head: Head,
}

fn word(w: &PermWord) -> Result<u32, String> {
    Ok(match w.t {
        T::Create => CREATE,
        T::Value if w.text == b"create" => CREATE,
        _ => 0,
    })
}

impl Userns {
    pub fn new(
        perms: &Option<Vec<PermWord>>,
        conds: &[Cond],
        prefix: Prefix,
    ) -> Result<Userns, String> {
        let p = perm_words(perms, word)?;
        if p & !VALID != 0 {
            return Err("perms contains invalid permissions for userns".into());
        }
        let perms = if p != 0 { p } else { VALID };
        if let Some(c) = conds_upstream(conds).next() {
            if c.op != CondOp::Eq {
                return Err("only \"=\" allowed in conditions of userns rules".into());
            }
            return Err(format!(
                "invalid userns rule conditional \"{}\"",
                String::from_utf8_lossy(&c.name)
            ));
        }
        deny_owner("userns", &prefix)?;
        Ok(Userns {
            head: Head {
                prefix: apply_prefix(prefix),
                perms,
            },
        })
    }

    pub fn gen(&self, set: &mut RuleSet, s: &Support) -> Result<(), String> {
        if !s.userns {
            return Ok(());
        }
        let re = hex(CLASS_NS);
        if self.head.perms & VALID != 0 {
            self.head
                .add(set, &re, self.head.perms, self.head.audit_mask())?;
            // Every userns rule brings a mediates rule of its own
            // priority, since the permissions sit on the class byte.
            set.add(
                re.as_bytes(),
                self.head.prefix.priority,
                crate::apparmor::model::RuleMode::Allow,
                crate::apparmor::model::perm::MAY_READ,
                0,
            )
            .map_err(|_| "bad regular expression in policy rule".to_string())?;
        }
        Ok(())
    }
}
