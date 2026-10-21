//! `io_uring` rules: upstream's io_uring.cc.

use super::{apply_prefix, conds_upstream, deny_owner, hex, pattern, perm_words, require_eq, Head};
use super::{move_value, CLASS_IO_URING, DEFAULT};
use crate::apparmor::ast::{Cond, CondList, PermWord};
use crate::apparmor::compile::rules::RuleSet;
use crate::apparmor::compile::Support;
use crate::apparmor::lexer::T;
use crate::apparmor::model::{perm::MAY_READ, Prefix, RuleMode};

pub const OVERRIDE_CREDS: u32 = 8;
pub const SQPOLL: u32 = 0x10;
pub const VALID: u32 = OVERRIDE_CREDS | SQPOLL;

/// The label is never expanded: upstream's expand_variables for this
/// kind does nothing.
#[derive(Debug, Clone)]
pub struct IoUring {
    pub head: Head,
    pub label: Option<Vec<u8>>,
}

fn word(w: &PermWord) -> Result<u32, String> {
    Ok(match (w.t, &w.text[..]) {
        (T::OverrideCreds, _) | (T::Value, b"override_creds") => OVERRIDE_CREDS,
        (T::Sqpoll, _) | (T::Value, b"sqpoll") => SQPOLL,
        _ => 0,
    })
}

fn take(label: &mut Option<Vec<u8>>, conds: &[Cond]) -> Result<(), String> {
    for c in conds_upstream(conds) {
        require_eq("io_uring", c)?;
        if c.values.len() > 1 {
            return Err(format!(
                "io_uring conditional \"{}\" only supports a single value",
                String::from_utf8_lossy(&c.name)
            ));
        }
        if c.name == b"label" {
            move_value("io_uring", label, c)?;
        } else {
            return Err(format!(
                "invalid io_uring conditional \"{}\"",
                String::from_utf8_lossy(&c.name)
            ));
        }
    }
    Ok(())
}

impl IoUring {
    /// The group's name after the conditions is not checked, as
    /// upstream's grammar does not check it for this kind.
    pub fn new(
        perms: &Option<Vec<PermWord>>,
        conds: &[Cond],
        ring: &Option<CondList>,
        prefix: Prefix,
    ) -> Result<IoUring, String> {
        let p = perm_words(perms, word)?;
        if p & !VALID != 0 {
            return Err("perms contains invalid permissions for io_uring".into());
        }
        let mut label = None;
        take(&mut label, conds)?;
        if let Some(r) = ring {
            take(&mut label, &r.conds)?;
        }
        deny_owner("io_uring", &prefix)?;
        Ok(IoUring {
            head: Head {
                prefix: apply_prefix(prefix),
                perms: if p != 0 { p } else { VALID },
            },
            label,
        })
    }

    pub fn gen(&self, set: &mut RuleSet, s: &Support) -> Result<(), String> {
        if !s.io_uring {
            return Ok(());
        }
        let class = hex(CLASS_IO_URING);
        let with_label = match &self.label {
            Some(l) => format!("{class}{}", pattern(l)?),
            None => format!("{class}{DEFAULT}"),
        };
        let h = &self.head;
        if h.perms & VALID != 0 {
            h.add(set, &class, h.perms, h.audit_mask())?;
            set.add(
                class.as_bytes(),
                h.prefix.priority,
                RuleMode::Allow,
                MAY_READ,
                0,
            )
            .map_err(|_| "bad regular expression in policy rule".to_string())?;
            if h.perms & OVERRIDE_CREDS != 0 {
                h.add(set, &with_label, h.perms, h.audit_mask())?;
            }
        }
        Ok(())
    }
}
