//! `mqueue` rules: upstream's mqueue.cc. POSIX and System V queues share
//! the rule; a name starting with `/` means POSIX, a number System V.

use super::{
    apply_prefix, conds_upstream, deny_owner, hex, pattern, perm_words, require_eq, x_perms, Head,
};
use super::{move_value, ANYONE, CLASS_POSIX_MQUEUE, CLASS_SYSV_MQUEUE, DEFAULT};
use crate::apparmor::ast::{Cond, PermWord};
use crate::apparmor::compile::rules::RuleSet;
use crate::apparmor::compile::Support;
use crate::apparmor::lexer::T;
use crate::apparmor::model::Prefix;

pub const WRITE: u32 = 2;
pub const READ: u32 = 4;
pub const CREATE: u32 = 0x10;
pub const DELETE: u32 = 0x20;
pub const OPEN: u32 = 0x40;
pub const SETATTR: u32 = 0x100;
pub const GETATTR: u32 = 0x200;
pub const VALID_POSIX: u32 = WRITE | READ | CREATE | DELETE | OPEN | SETATTR | GETATTR;
pub const VALID_SYSV: u32 = VALID_POSIX;
pub const VALID: u32 = VALID_POSIX | VALID_SYSV;
const CREATE_PERMS: u32 = CREATE | READ | WRITE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QType {
    Unspecified,
    Posix,
    Sysv,
}

#[derive(Debug, Clone)]
pub struct Mqueue {
    pub head: Head,
    pub qtype: QType,
    pub qname: Option<Vec<u8>>,
    pub label: Option<Vec<u8>>,
}

/// upstream's map_mqueue_perms: the attribute bits move up next to the
/// others the kernel checks.
fn map(mask: u32) -> u32 {
    (mask & 0x7f) | ((mask & (GETATTR | SETATTR)) << 6)
}

fn word(w: &PermWord) -> Result<u32, String> {
    Ok(match (w.t, &w.text[..]) {
        (T::Create, _) | (T::Value, b"create") => CREATE,
        (T::Open, _) | (T::Value, b"open") => OPEN,
        (T::Delete, _) | (T::Value, b"delete") => DELETE,
        (T::GetAttr, _) | (T::Value, b"getattr") => GETATTR,
        (T::SetAttr, _) | (T::Value, b"setattr") => SETATTR,
        (T::Write, _) | (T::Value, b"write") => WRITE,
        (T::Read, _) | (T::Value, b"read") => READ,
        (T::Mode, m) | (T::Value, m) => x_perms("mqueue", VALID, m)?,
        _ => 0,
    })
}

fn all_digits(s: &[u8]) -> bool {
    !s.is_empty() && s.iter().all(|c| c.is_ascii_digit())
}

impl Mqueue {
    pub fn new(
        perms: &Option<Vec<PermWord>>,
        conds: &[Cond],
        qname: &Option<Vec<u8>>,
        prefix: Prefix,
    ) -> Result<Mqueue, String> {
        let p = perm_words(perms, word)?;
        let mut qtype = QType::Unspecified;
        let mut label = None;
        for c in conds_upstream(conds) {
            require_eq("mqueue", c)?;
            if c.name == b"label" {
                move_value("mqueue", &mut label, c)?;
            } else if c.name == b"type" {
                let mut t = None;
                move_value("mqueue", &mut t, c)?;
                qtype = match t.as_deref() {
                    Some(b"posix") => QType::Posix,
                    Some(b"sysv") => QType::Sysv,
                    other => {
                        return Err(format!(
                            "mqueue invalid type='{}'",
                            String::from_utf8_lossy(other.unwrap_or_default())
                        ))
                    }
                };
            } else {
                return Err(format!(
                    "invalid mqueue rule conditional \"{}\"",
                    String::from_utf8_lossy(&c.name)
                ));
            }
        }
        if let Some(q) = qname {
            let shown = String::from_utf8_lossy(q);
            if q.first() == Some(&b'/') {
                if qtype == QType::Sysv {
                    return Err(format!(
                        "mqueue type=sysv invalid name '{shown}', sysv message queues must be identified by a positive integer."
                    ));
                }
                qtype = QType::Posix;
            } else if all_digits(q) {
                if qtype == QType::Posix {
                    return Err(format!(
                        "mqueue type=posix invalid name '{shown}', posix message queues names must begin with a /"
                    ));
                }
                qtype = QType::Sysv;
            } else {
                return Err(format!(
                    "mqueue invalid name '{shown}', message queue names must begin with a / or be a positive integer."
                ));
            }
        }
        let perms = if p != 0 {
            if qtype == QType::Posix && p & !VALID_POSIX != 0 {
                return Err("perms contains invalid permissions for mqueue type=posix".into());
            } else if qtype == QType::Sysv && p & !VALID_SYSV != 0 {
                return Err("perms contains invalid permissions for mqueue type=sysv".into());
            } else if p & !VALID != 0 {
                return Err("perms contains invalid permissions for mqueue".into());
            }
            p
        } else {
            VALID
        };
        deny_owner("mqueue", &prefix)?;
        Ok(Mqueue {
            head: Head {
                prefix: apply_prefix(prefix),
                perms,
            },
            qtype,
            qname: qname.clone(),
            label,
        })
    }

    pub fn expand(
        &mut self,
        f: &mut dyn FnMut(&mut Vec<u8>) -> Result<(), String>,
    ) -> Result<(), String> {
        for v in [&mut self.qname, &mut self.label].into_iter().flatten() {
            f(v)?;
        }
        Ok(())
    }

    fn add_three(&self, set: &mut RuleSet, vec: [&str; 2], valid: u32) -> Result<(), String> {
        let h = &self.head;
        if h.perms & valid == 0 {
            return Ok(());
        }
        let audit = |m: u32| if h.audit_mask() != 0 { m } else { 0 };
        let add = |set: &mut RuleSet, perms: u32, n: usize| {
            let parts: Vec<&[u8]> = vec[..n].iter().map(|v| v.as_bytes()).collect();
            set.add_vec(
                h.prefix.priority,
                h.prefix.mode,
                perms,
                audit(perms),
                &parts,
                false,
            )
            .map_err(|_| "bad regular expression in mqueue rule".to_string())
        };
        // Permissions sit on the name too, so an unlabelled rule needs
        // no label match; creating is allowed by name alone, since the
        // queue needs creating before it has a label.
        if self.label.is_none() {
            add(set, map(h.perms), 1)?;
        }
        if h.perms & CREATE != 0 {
            add(set, map(h.perms & CREATE_PERMS), 1)?;
        }
        add(set, map(h.perms), 2)
    }

    pub fn gen(&self, set: &mut RuleSet, s: &Support) -> Result<(), String> {
        let supported = match self.qtype {
            QType::Posix => s.posix_mqueue,
            QType::Sysv => s.sysv_mqueue,
            QType::Unspecified => s.posix_mqueue || s.sysv_mqueue,
        };
        if !supported {
            return Ok(());
        }
        // upstream converts the label into one buffer for both kinds of
        // queue without clearing it, so where both are generated the
        // System V rules match the label written twice.
        let mut labelbuf = String::new();
        let label = |labelbuf: &mut String| -> Result<String, String> {
            match &self.label {
                Some(l) => {
                    labelbuf.push_str(&pattern(l)?);
                    Ok(labelbuf.clone())
                }
                None => Ok(ANYONE.to_string()),
            }
        };
        if self.qtype != QType::Sysv {
            let label = label(&mut labelbuf)?;
            let mut name = hex(CLASS_POSIX_MQUEUE);
            match &self.qname {
                Some(q) => name.push_str(&pattern(q)?),
                None => name.push_str(DEFAULT),
            }
            self.add_three(set, [&name, &label], VALID_POSIX)?;
        }
        if self.qtype != QType::Posix {
            let mut name = hex(CLASS_SYSV_MQUEUE);
            match &self.qname {
                Some(q) => {
                    // sscanf("%d"): a long, truncated to int.
                    let key = scan_int(q) as i32 as u32;
                    for b in key.to_be_bytes() {
                        name.push_str(&hex(b as u32));
                    }
                }
                None => name.push_str("...."),
            }
            let label = label(&mut labelbuf)?;
            self.add_three(set, [&name, &label], VALID_SYSV)?;
        }
        Ok(())
    }
}

/// A decimal number at the start of `s`, as `%d` reads one.
fn scan_int(s: &[u8]) -> i64 {
    let mut i = 0;
    while i < s.len() && s[i].is_ascii_whitespace() {
        i += 1;
    }
    let neg = s.get(i) == Some(&b'-');
    if matches!(s.get(i), Some(b'-' | b'+')) {
        i += 1;
    }
    let mut v: i64 = 0;
    while i < s.len() && s[i].is_ascii_digit() {
        v = v.saturating_mul(10).saturating_add((s[i] - b'0') as i64);
        i += 1;
    }
    if neg {
        -v
    } else {
        v
    }
}
