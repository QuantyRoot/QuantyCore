//! `dbus` rules: upstream's dbus.cc.

use super::{
    apply_prefix, conds_upstream, deny_owner, hex, move_value, pattern, perm_words, require_eq,
    x_perms, Head,
};
use super::{CLASS_DBUS, DEFAULT};
use crate::apparmor::ast::{Cond, CondList, PermWord};
use crate::apparmor::compile::rules::RuleSet;
use crate::apparmor::compile::Support;
use crate::apparmor::lexer::T;
use crate::apparmor::model::Prefix;
use crate::apparmor::process::filter_slashes;

pub const SEND: u32 = 1 << 1;
pub const RECEIVE: u32 = 1 << 2;
pub const EAVESDROP: u32 = 1 << 5;
pub const BIND: u32 = 1 << 6;
pub const VALID: u32 = SEND | RECEIVE | BIND | EAVESDROP;

#[derive(Debug, Clone, Default)]
pub struct Dbus {
    pub head: Head,
    pub bus: Option<Vec<u8>>,
    /// The subject's name in a bind rule, the peer's otherwise.
    pub name: Option<Vec<u8>>,
    pub peer_label: Option<Vec<u8>>,
    pub path: Option<Vec<u8>>,
    pub interface: Option<Vec<u8>>,
    pub member: Option<Vec<u8>>,
}

fn word(w: &PermWord) -> Result<u32, String> {
    Ok(match (w.t, &w.text[..]) {
        (T::Bind, _) => BIND,
        (T::Send, _) | (T::Write, _) => SEND,
        (T::Receive, _) | (T::Read, _) => RECEIVE,
        (T::Eavesdrop, _) => EAVESDROP,
        (T::Mode, m) => x_perms("DBus", VALID, m)?,
        (T::Value, b"bind") => BIND,
        (T::Value, b"send" | b"write") => SEND,
        (T::Value, b"receive" | b"read") => RECEIVE,
        (T::Value, b"eavesdrop") => EAVESDROP,
        (T::Value, m) => x_perms("DBus", VALID, m)?,
        _ => 0,
    })
}

impl Dbus {
    fn take(&mut self, conds: &[Cond]) -> Result<(), String> {
        for c in conds_upstream(conds) {
            require_eq("dbus", c)?;
            if c.values.len() > 1 {
                return Err(format!(
                    "dbus conditional \"{}\" only supports a single value",
                    String::from_utf8_lossy(&c.name)
                ));
            }
            let dst = match &c.name[..] {
                b"bus" => &mut self.bus,
                b"name" => &mut self.name,
                b"label" => &mut self.peer_label,
                b"path" => &mut self.path,
                b"interface" => &mut self.interface,
                b"member" => &mut self.member,
                other => {
                    return Err(format!(
                        "invalid dbus conditional \"{}\"",
                        String::from_utf8_lossy(other)
                    ))
                }
            };
            move_value("dbus", dst, c)?;
        }
        Ok(())
    }

    pub fn new(
        perms: &Option<Vec<PermWord>>,
        conds: &[Cond],
        peer: &Option<CondList>,
        prefix: Prefix,
    ) -> Result<Dbus, String> {
        let p = perm_words(perms, word)?;
        if let Some(l) = peer {
            if l.name != b"peer" {
                return Err(format!(
                    "dbus rule: invalid conditional group {}=()",
                    String::from_utf8_lossy(&l.name)
                ));
            }
        }
        let mut r = Dbus::default();
        r.take(conds)?;
        let subject_name = r.name.is_some();
        if r.peer_label.is_some() {
            return Err(
                "dbus \"label\" conditional can only be used inside of the \"peer=()\" grouping"
                    .into(),
            );
        }
        if let Some(l) = peer {
            r.take(&l.conds)?;
        }
        let message = r.path.is_some()
            || r.interface.is_some()
            || r.member.is_some()
            || r.peer_label.is_some()
            || (r.name.is_some() && !subject_name);
        let service = r.name.is_some() && subject_name;
        if message && service {
            return Err("dbus rule contains message conditionals and service conditionals".into());
        }
        let perms = if p != 0 {
            if p & !VALID != 0 {
                return Err("perms contains unknown dbus access".into());
            } else if message && p & BIND != 0 {
                return Err(
                    "dbus \"bind\" access cannot be used with message rule conditionals".into(),
                );
            } else if service && p & (SEND | RECEIVE) != 0 {
                return Err(
                    "dbus \"send\" and/or \"receive\" accesses cannot be used with service rule conditionals"
                        .into(),
                );
            } else if p & EAVESDROP != 0
                && (r.path.is_some()
                    || r.interface.is_some()
                    || r.member.is_some()
                    || r.peer_label.is_some()
                    || r.name.is_some())
            {
                return Err("dbus \"eavesdrop\" access can only contain a bus conditional".into());
            }
            p
        } else if message {
            SEND | RECEIVE
        } else if service {
            BIND
        } else {
            VALID
        };
        deny_owner("dbus", &prefix)?;
        r.head = Head {
            prefix: apply_prefix(prefix),
            perms,
        };
        Ok(r)
    }

    pub fn expand(
        &mut self,
        f: &mut dyn FnMut(&mut Vec<u8>) -> Result<(), String>,
    ) -> Result<(), String> {
        for v in [
            &mut self.bus,
            &mut self.name,
            &mut self.peer_label,
            &mut self.path,
        ]
        .into_iter()
        .flatten()
        {
            f(v)?;
        }
        if let Some(p) = self.path.as_mut() {
            filter_slashes(p);
        }
        for v in [&mut self.interface, &mut self.member]
            .into_iter()
            .flatten()
        {
            f(v)?;
        }
        Ok(())
    }

    pub fn gen(&self, set: &mut RuleSet, s: &Support) -> Result<(), String> {
        if !s.dbus {
            return Ok(());
        }
        let field = |v: &Option<Vec<u8>>| -> Result<String, String> {
            match v {
                Some(v) => pattern(v),
                None => Ok(DEFAULT.to_string()),
            }
        };
        let bus = format!("{}{}", hex(CLASS_DBUS), field(&self.bus)?);
        let vec = [
            bus,
            field(&self.name)?,
            field(&self.peer_label)?,
            field(&self.path)?,
            field(&self.interface)?,
            field(&self.member)?,
        ];
        let h = &self.head;
        let add = |set: &mut RuleSet, mask: u32, n: usize| -> Result<(), String> {
            if h.perms & mask == 0 {
                return Ok(());
            }
            let parts: Vec<&[u8]> = vec[..n].iter().map(|v| v.as_bytes()).collect();
            let audit = h.audit_mask() & mask;
            set.add_vec(
                h.prefix.priority,
                h.prefix.mode,
                h.perms & mask,
                audit,
                &parts,
                false,
            )
            .map_err(|_| "bad regular expression in dbus rule".to_string())
        };
        add(set, BIND, 2)?;
        add(set, SEND | RECEIVE, 6)?;
        add(set, EAVESDROP, 1)?;
        Ok(())
    }
}
