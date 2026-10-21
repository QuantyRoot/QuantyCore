//! `signal` rules: upstream's signal.cc.

use std::collections::BTreeSet;

use super::{
    apply_prefix, conds_upstream, deny_owner, hex, move_value, pattern, perm_words, require_eq,
    x_perms, Head,
};
use super::{ANYONE, CLASS_LABEL, CLASS_SIGNAL};
use crate::apparmor::ast::{Cond, PermWord};
use crate::apparmor::compile::rules::RuleSet;
use crate::apparmor::compile::Support;
use crate::apparmor::eval::strtoul_prefix;
use crate::apparmor::lexer::T;
use crate::apparmor::model::Prefix;

pub const SEND: u32 = 2;
pub const RECEIVE: u32 = 4;
pub const VALID: u32 = SEND | RECEIVE;

const MINRT: u32 = 128;
const MAXRT: u64 = 32;

const NAMES: &[(&str, u32)] = &[
    ("hup", 1),
    ("int", 2),
    ("quit", 3),
    ("ill", 4),
    ("trap", 5),
    ("abrt", 6),
    ("bus", 7),
    ("fpe", 8),
    ("kill", 9),
    ("usr1", 10),
    ("segv", 11),
    ("usr2", 12),
    ("pipe", 13),
    ("alrm", 14),
    ("term", 15),
    ("stkflt", 16),
    ("chld", 17),
    ("cont", 18),
    ("stop", 19),
    ("stp", 20),
    ("tstp", 20),
    ("ttin", 21),
    ("ttou", 22),
    ("urg", 23),
    ("xcpu", 24),
    ("xfsz", 25),
    ("vtalrm", 26),
    ("prof", 27),
    ("winch", 28),
    ("io", 29),
    ("poll", 29),
    ("pwr", 30),
    ("sys", 31),
    ("emt", 32),
    ("exists", 35),
];

/// upstream's find_signal_mapping. Its check for a missing number after
/// `rtmin+` compares against the wrong pointer, so `rtmin+` alone is
/// `rtmin+0`, and anything after the digits is ignored.
fn mapping(sig: &[u8]) -> Option<u32> {
    if let Some(rest) = sig.strip_prefix(b"rtmin+") {
        let n = strtoul_prefix(rest).unwrap_or(0);
        return (n <= MAXRT).then_some(MINRT + n as u32);
    }
    NAMES
        .iter()
        .find(|(n, _)| n.as_bytes() == sig)
        .map(|&(_, v)| v)
}

#[derive(Debug, Clone)]
pub struct Signal {
    pub head: Head,
    pub signals: BTreeSet<u32>,
    pub peer: Option<Vec<u8>>,
}

fn word(w: &PermWord) -> Result<u32, String> {
    Ok(match (w.t, &w.text[..]) {
        (T::Send, _) | (T::Write, _) => SEND,
        (T::Receive, _) | (T::Read, _) => RECEIVE,
        (T::Mode, m) => x_perms("signal", VALID, m)?,
        (T::Value, b"send" | b"write") => SEND,
        (T::Value, b"receive" | b"read") => RECEIVE,
        (T::Value, m) => x_perms("signal", VALID, m)?,
        _ => 0,
    })
}

impl Signal {
    pub fn new(
        perms: &Option<Vec<PermWord>>,
        conds: &[Cond],
        prefix: Prefix,
    ) -> Result<Signal, String> {
        let p = perm_words(perms, word)?;
        if p & !VALID != 0 {
            return Err("perms contains invalid permission for signals".into());
        }
        let mut signals = BTreeSet::new();
        let mut peer = None;
        for c in conds_upstream(conds) {
            require_eq("signal", c)?;
            if c.name == b"set" {
                for v in &c.values {
                    match mapping(v) {
                        Some(s) => {
                            signals.insert(s);
                        }
                        None => {
                            return Err(format!(
                                "unknown signal \"{}\"",
                                String::from_utf8_lossy(v)
                            ));
                        }
                    }
                }
            } else if c.name == b"peer" {
                move_value("signal", &mut peer, c)?;
            } else {
                return Err(format!(
                    "invalid signal rule conditional \"{}\"",
                    String::from_utf8_lossy(&c.name)
                ));
            }
        }
        deny_owner("signal", &prefix)?;
        Ok(Signal {
            head: Head {
                prefix: apply_prefix(prefix),
                perms: if p != 0 { p } else { VALID },
            },
            signals,
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
        if !s.signal {
            return Ok(());
        }
        let mut re = String::new();
        if self.signals.is_empty() {
            // upstream prints the second class byte after its stream has
            // dropped the zero padding: `\xa`, not `\x0a`.
            re.push_str(&format!("({}\\x{:x}|", hex(CLASS_LABEL), CLASS_SIGNAL));
        }
        re.push_str(&hex(CLASS_SIGNAL));
        if self.signals.is_empty() {
            re.push_str(".)");
        } else {
            re.push('[');
            for s in &self.signals {
                re.push_str(&hex(*s));
            }
            re.push(']');
        }
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
