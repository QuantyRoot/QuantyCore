//! The rule kinds compiled into the policy automaton: signals, ptrace,
//! user namespaces, message queues, io_uring, D-Bus, unix sockets,
//! networking and mounts. Each kind follows its upstream class
//! (`signal.cc` and so on): the constructor's checks run while the
//! profile is built, variables are expanded with the file rules, and
//! the rule becomes expressions in the policy automaton.
//!
//! An expression starts with the class byte the kernel looks up first,
//! followed by the rule's fields; upstream writes them as `\xNN`
//! escapes, and the same text is produced here.

pub mod dbus;
pub mod io_uring;
pub mod mount;
pub mod mqueue;
pub mod network;
pub mod ptrace;
pub mod signal;
pub mod unix;
pub mod userns;

use super::ast::{Cond, CondOp, PermWord};
use super::compile::aare::{convert, Glob};
use super::compile::rules::RuleSet;
use super::compile::Support;
use super::lexer::T;
use super::model::{Audit, Prefix};

pub const CLASS_FILE: u32 = 2;
pub const CLASS_NET: u32 = 4;
pub const CLASS_MOUNT: u32 = 7;
pub const CLASS_PTRACE: u32 = 9;
pub const CLASS_SIGNAL: u32 = 10;
pub const CLASS_NETV8: u32 = 14;
pub const CLASS_NETV9: u32 = 15;
pub const CLASS_LABEL: u32 = 16;
pub const CLASS_POSIX_MQUEUE: u32 = 17;
pub const CLASS_SYSV_MQUEUE: u32 = 18;
pub const CLASS_NS: u32 = 21;
pub const CLASS_IO_URING: u32 = 22;
pub const CLASS_NETV9_SKB: u32 = 30;
pub const CLASS_DBUS: u32 = 32;

/// upstream's anyone_match_pattern.
pub const ANYONE: &str = "[^\\000]+";
/// upstream's default_match_pattern.
pub const DEFAULT: &str = "[^\\000]*";

/// A compiled rule of one of the kinds above.
#[derive(Debug, Clone)]
pub enum ClassRule {
    Signal(signal::Signal),
    Ptrace(ptrace::Ptrace),
    Userns(userns::Userns),
    Dbus(dbus::Dbus),
    Mqueue(mqueue::Mqueue),
    IoUring(io_uring::IoUring),
    Unix(unix::Unix),
    Network(network::Network),
    Mount(mount::Mount),
}

/// What every class rule carries: its prefix, as upstream's add_prefix
/// leaves it, and its permissions.
#[derive(Debug, Clone, Copy, Default)]
pub struct Head {
    pub prefix: Prefix,
    pub perms: u32,
}

impl Head {
    pub fn audit_mask(&self) -> u32 {
        if self.prefix.audit == Audit::Force {
            self.perms
        } else {
            0
        }
    }

    pub fn add(&self, set: &mut RuleSet, re: &str, perms: u32, audit: u32) -> Result<(), String> {
        set.add(
            re.as_bytes(),
            self.prefix.priority,
            self.prefix.mode,
            perms,
            audit,
        )
        .map_err(|_| "bad regular expression in policy rule".to_string())
    }
}

/// `\xNN`, as upstream's streams print a class or field byte.
pub fn hex(n: u32) -> String {
    format!("\\x{n:02x}")
}

/// A label or name pattern in the policy dialect.
pub fn pattern(aare: &[u8]) -> Result<String, String> {
    let mut out = Vec::new();
    convert(aare, Glob::Default, &mut out).map_err(|_| {
        format!(
            "Invalid pattern '{}' in policy rule",
            String::from_utf8_lossy(aare)
        )
    })?;
    String::from_utf8(out).map_err(|_| "pattern is not text".to_string())
}

/// upstream's add_prefix on a rule that had no prefix of its own:
/// `deny` turns into a forced audit (for a deny rule, quiet), and
/// `audit deny` loses its audit.
pub fn apply_prefix(p: Prefix) -> Prefix {
    super::build::rule_prefix(&p)
}

/// upstream's prefix_rule_t::add_prefix on a rule whose prefix is
/// `cur`: conflicting prefixes are errors, then the same changes as
/// [`apply_prefix`].
pub fn add_prefix(mut cur: Prefix, p: Prefix) -> Result<Prefix, String> {
    use super::model::{Owner, RuleMode};
    if cur.priority != 0 {
        return Err("priority levels not supported".into());
    }
    cur.priority = p.priority;
    if p.audit != Audit::Unspecified && cur.audit != Audit::Unspecified && cur.audit != p.audit {
        return Err("conflicting audit prefix".into());
    }
    if p.mode != RuleMode::Unspecified {
        if cur.mode != RuleMode::Unspecified && cur.mode != p.mode {
            return Err("conflicting mode prefix".into());
        }
        cur.mode = p.mode;
    }
    if p.owner != Owner::Unspecified {
        if cur.owner != Owner::Unspecified && cur.owner != p.owner {
            return Err("conflicting owner prefix".into());
        }
        cur.owner = p.owner;
    }
    if p.mode == RuleMode::Deny && p.audit == Audit::Force {
        cur.mode = RuleMode::Deny;
    } else if p.mode == RuleMode::Deny {
        cur.mode = RuleMode::Deny;
        cur.audit = Audit::Force;
    } else if p.audit != Audit::Unspecified {
        cur.audit = p.audit;
    }
    Ok(cur)
}

/// The conditions in the order upstream walks them: its grammar builds
/// the list by prepending.
pub fn conds_upstream(conds: &[Cond]) -> impl Iterator<Item = &Cond> {
    conds.iter().rev()
}

/// upstream's move_conditional_value: the first value of the condition,
/// once.
pub fn move_value(kind: &str, dst: &mut Option<Vec<u8>>, c: &Cond) -> Result<(), String> {
    if dst.is_some() {
        return Err(format!(
            "{kind} conditional \"{}\" can only be specified once",
            String::from_utf8_lossy(&c.name)
        ));
    }
    *dst = c.values.first().cloned();
    Ok(())
}

pub fn require_eq(kind: &str, c: &Cond) -> Result<(), String> {
    if c.op != CondOp::Eq {
        return Err(format!("only \"=\" allowed in conditions of {kind} rules"));
    }
    Ok(())
}

/// upstream's parse_X_perms: a mode string of `r` and `w` only, upper
/// case accepted, mapped to receive and send.
pub fn x_perms(kind: &str, valid: u32, s: &[u8]) -> Result<u32, String> {
    let mut perms = 0;
    for &c in s {
        match c.to_ascii_lowercase() {
            b'r' => perms |= 4,
            b'w' => perms |= 2,
            _ => {
                return Err(format!(
                    "Internal: unexpected {kind} perms character '{}' in input",
                    c as char
                ))
            }
        }
    }
    if perms & !valid != 0 {
        return Err(format!(
            "Internal error generated invalid {kind} perm 0x{perms:x}"
        ));
    }
    Ok(perms)
}

/// The permission words of a rule, each mapped by `word`; `None` and
/// an empty list give 0, which the kinds read as "all".
pub fn perm_words(
    words: &Option<Vec<PermWord>>,
    word: impl Fn(&PermWord) -> Result<u32, String>,
) -> Result<u32, String> {
    let mut perms = 0;
    for w in words.iter().flatten() {
        perms |= word(w)?;
    }
    Ok(perms)
}

pub fn is_value(w: &PermWord, s: &str) -> bool {
    w.t == T::Value && w.text == s.as_bytes()
}

impl ClassRule {
    pub fn expand(
        &mut self,
        f: &mut dyn FnMut(&mut Vec<u8>) -> Result<(), String>,
    ) -> Result<(), String> {
        match self {
            ClassRule::Signal(r) => r.expand(f),
            ClassRule::Ptrace(r) => r.expand(f),
            ClassRule::Dbus(r) => r.expand(f),
            ClassRule::Mqueue(r) => r.expand(f),
            ClassRule::Unix(r) => r.expand(f),
            ClassRule::Mount(r) => r.expand(f),
            ClassRule::Userns(_) | ClassRule::IoUring(_) | ClassRule::Network(_) => Ok(()),
        }
    }

    pub fn gen(&self, set: &mut RuleSet, s: &Support) -> Result<(), String> {
        match self {
            ClassRule::Signal(r) => r.gen(set, s),
            ClassRule::Ptrace(r) => r.gen(set, s),
            ClassRule::Userns(r) => r.gen(set, s),
            ClassRule::Dbus(r) => r.gen(set, s),
            ClassRule::Mqueue(r) => r.gen(set, s),
            ClassRule::IoUring(r) => r.gen(set, s),
            ClassRule::Network(r) => r.gen(set, s),
            ClassRule::Mount(r) => r.gen(set, s),
            ClassRule::Unix(r) => r.gen(set, s),
        }
    }
}

/// Bytes that identify a rule for upstream's merge_rules: two rules of
/// a kind whose keys are equal are merged into one, their permissions
/// joined. The key holds everything upstream's cmp compares except the
/// permissions.
#[derive(Default)]
struct Key(Vec<u8>);

impl Key {
    fn n(&mut self, v: i64) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }

    fn s(&mut self, v: &Option<Vec<u8>>) -> &mut Self {
        match v {
            None => {
                self.0.push(0);
            }
            Some(v) => {
                self.0.push(1);
                self.n(v.len() as i64);
                self.0.extend_from_slice(v);
            }
        }
        self
    }

    fn head(&mut self, kind: i64, h: &Head) -> &mut Self {
        self.n(kind)
            .n(h.prefix.priority as i64)
            .n(h.prefix.audit as i64)
            .n(h.prefix.mode as i64)
            .n(h.prefix.owner as i64)
    }
}

impl ClassRule {
    fn head_mut(&mut self) -> &mut Head {
        match self {
            ClassRule::Signal(r) => &mut r.head,
            ClassRule::Ptrace(r) => &mut r.head,
            ClassRule::Userns(r) => &mut r.head,
            ClassRule::Dbus(r) => &mut r.head,
            ClassRule::Mqueue(r) => &mut r.head,
            ClassRule::IoUring(r) => &mut r.head,
            ClassRule::Unix(r) => &mut r.head,
            ClassRule::Network(r) => &mut r.head,
            ClassRule::Mount(r) => &mut r.head,
        }
    }

    /// The merge key, or None for kinds upstream only deduplicates,
    /// where merging changes nothing.
    fn merge_key(&self) -> Option<Vec<u8>> {
        let mut k = Key::default();
        match self {
            ClassRule::Signal(r) => {
                k.head(1, &r.head).s(&r.peer).n(r.signals.len() as i64);
                for s in &r.signals {
                    k.n(*s as i64);
                }
            }
            ClassRule::Ptrace(r) => {
                k.head(2, &r.head).s(&r.peer);
            }
            ClassRule::Userns(r) => {
                k.head(3, &r.head);
            }
            ClassRule::Dbus(r) => {
                k.head(4, &r.head)
                    .s(&r.bus)
                    .s(&r.name)
                    .s(&r.peer_label)
                    .s(&r.path)
                    .s(&r.interface)
                    .s(&r.member);
            }
            ClassRule::Mqueue(r) => {
                k.head(5, &r.head).n(r.qtype as i64).s(&r.qname).s(&r.label);
            }
            ClassRule::IoUring(r) => {
                k.head(6, &r.head).s(&r.label);
            }
            ClassRule::Unix(r) => {
                k.head(7, &r.head)
                    .n(r.sock_type_n as i64)
                    .s(&r.sock_type)
                    .s(&r.label)
                    .s(&r.peer_label)
                    .s(&r.addr)
                    .s(&r.peer_addr);
            }
            ClassRule::Mount(r) => {
                k.head(8, &r.head)
                    .s(&r.mnt_point)
                    .s(&r.device)
                    .s(&r.trans)
                    .n(r.dev_type.len() as i64);
                for v in &r.dev_type {
                    k.s(&Some(v.clone()));
                }
                k.n(r.flagsv.len() as i64);
                for f in &r.flagsv {
                    k.n(*f as i64);
                }
                k.n(r.opt_flagsv.len() as i64);
                for f in &r.opt_flagsv {
                    k.n(*f as i64);
                }
            }
            ClassRule::Network(_) => return None,
        }
        Some(k.0)
    }
}

/// upstream's Profile::merge_rules for the kinds that join permissions:
/// rules equal in everything but their permissions become one. This
/// matters where a kind uses its permissions to choose what it encodes;
/// a mount rule merged with a umount rule encodes umount on the mount
/// patterns too.
pub fn merge_rules(rules: &mut Vec<(ClassRule, crate::apparmor::source::Span)>) {
    let mut first: std::collections::HashMap<Vec<u8>, usize> = std::collections::HashMap::new();
    let mut keep = vec![true; rules.len()];
    for i in 0..rules.len() {
        let Some(key) = rules[i].0.merge_key() else {
            continue;
        };
        match first.get(&key) {
            Some(&j) => {
                let perms = rules[i].0.head_mut().perms;
                if let (ClassRule::Unix(a), ClassRule::Unix(b)) = (&rules[i].0, &rules[j].0) {
                    let d = a.downgrade || b.downgrade;
                    if let ClassRule::Unix(b) = &mut rules[j].0 {
                        b.downgrade = d;
                    }
                }
                rules[j].0.head_mut().perms |= perms;
                keep[i] = false;
            }
            None => {
                first.insert(key, i);
            }
        }
    }
    let mut it = keep.into_iter();
    rules.retain(|_| it.next().unwrap_or(true));
}

pub(crate) fn deny_owner(kind: &str, p: &Prefix) -> Result<(), String> {
    if p.owner != super::ast::Owner::Unspecified {
        return Err(format!("owner prefix not allowed on {kind} rules"));
    }
    Ok(())
}
