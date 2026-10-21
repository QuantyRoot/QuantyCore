//! From profiles to automata: the file rules, the attachment match, and
//! (in later modules) every other rule kind.

pub mod aare;
pub mod dfa;
pub mod kperms;
pub mod regex;
pub mod rules;
pub mod tree;

use self::aare::{convert, Glob, PatternType};
use self::dfa::{Dfa, DfaError, Limits};
use self::rules::RuleSet;
use super::build::parse_label;
use super::model::{perm::*, *};
use super::process::{filter_slashes, local_name};

/// What the compiler needs to know about the kernel and the policy's
/// declared abi; upstream derives the same from the two feature sets.
#[derive(Clone, Debug)]
pub struct Support {
    pub stacking: bool,
    pub domain_xattr: bool,
    pub oob: bool,
    /// 0 when the kernel takes permissions in the accept tables.
    pub permstable32_version: u32,
    pub limits: Limits,
    /// The kernel has a policy automaton at all.
    pub policydb: bool,
    /// The newest policy version the kernel takes, 5 to 7.
    pub abi_version: u32,
    pub network: bool,
    pub networkv8: bool,
    pub networkv9: bool,
    pub networkv9_skb: bool,
    pub ifacev9_skb: bool,
    pub inetv8: bool,
    pub inetv9: bool,
    pub unixv7: bool,
    pub unixv9: bool,
    pub mount: bool,
    pub detached_mount: bool,
    pub dbus: bool,
    pub signal: bool,
    pub ptrace: bool,
    pub userns: bool,
    pub posix_mqueue: bool,
    pub sysv_mqueue: bool,
    pub io_uring: bool,
    pub flag_interruptible: bool,
    pub flag_signal: bool,
    pub flag_error: bool,
    pub flag_disconnected_ipc: bool,
    pub identity_names: bool,
}

impl Support {
    /// Whether network rules go into the policy automaton rather than
    /// the per family table older kernels take.
    pub fn network_policydb(&self) -> bool {
        self.networkv8 || self.networkv9
    }
}

impl Default for Support {
    fn default() -> Support {
        Support {
            stacking: true,
            domain_xattr: true,
            oob: false,
            permstable32_version: 0,
            limits: Limits::default(),
            policydb: true,
            abi_version: 7,
            network: true,
            networkv8: false,
            networkv9: false,
            networkv9_skb: false,
            ifacev9_skb: false,
            inetv8: false,
            inetv9: false,
            unixv7: true,
            unixv9: false,
            mount: true,
            detached_mount: false,
            dbus: true,
            signal: true,
            ptrace: true,
            userns: false,
            posix_mqueue: false,
            sysv_mqueue: false,
            io_uring: false,
            flag_interruptible: false,
            flag_signal: false,
            flag_error: false,
            flag_disconnected_ipc: false,
            identity_names: false,
        }
    }
}

fn dfa_error(e: DfaError, what: &str) -> String {
    match e {
        DfaError::TooLarge => format!("{what}: the automaton is too large"),
        DfaError::ConflictingExec => "profile has merged rule with conflicting x modifiers".into(),
    }
}

fn convert_into(name: &[u8], glob: Glob, out: &mut Vec<u8>) -> Result<PatternType, String> {
    convert(name, glob, out).map(|(t, _)| t).map_err(|m| {
        format!(
            "{m}: Unable to parse input line '{}'",
            String::from_utf8_lossy(name)
        )
    })
}

/// The rules of a profile's file automaton: upstream's process_dfa_entry
/// for every file, link and change_profile entry.
pub fn file_rules(prof: &mut Profile, s: &Support) -> Result<RuleSet, String> {
    let mut set = RuleSet::default();
    for e in prof.entries.iter_mut() {
        let cp = e.perms & CHANGE_PROFILE != 0;
        if !cp {
            filter_slashes(&mut e.name);
        }
        let mut tbuf = Vec::new();
        convert_into(&e.name, Glob::Default, &mut tbuf)?;
        let bad = |_| "bad regular expression in rule".to_string();
        let audit_of = |p: u32| if e.audit == Audit::Force { p } else { 0 };
        if e.mode == RuleMode::Deny {
            if e.perms & !LINK_BITS != 0 && !cp {
                let p = e.perms & !(LINK_BITS | CHANGE_PROFILE);
                set.add(&tbuf, e.priority, e.mode, p, audit_of(p))
                    .map_err(bad)?;
            }
        } else if !cp {
            set.add(&tbuf, e.priority, e.mode, e.perms, audit_of(e.perms))
                .map_err(bad)?;
        }
        if e.perms & LINK_BITS != 0 {
            let mut perms = LINK_BITS & e.perms;
            let subset_bit = (perms << 1) & (OLD_MAY_LINK << 1);
            let lbuf = match e.link_name.as_mut() {
                Some(l) => {
                    filter_slashes(l);
                    let mut b = Vec::new();
                    convert_into(l, Glob::Default, &mut b)?;
                    if e.subset {
                        perms |= subset_bit;
                    }
                    b
                }
                None => {
                    perms |= subset_bit;
                    b"/[^/].*".to_vec()
                }
            };
            let audit = audit_of(perms & LINK_BITS);
            set.add_vec(e.priority, e.mode, perms, audit, &[&tbuf, &lbuf], false)
                .map_err(bad)?;
        }
        if cp {
            let xbuf = match &e.link_name {
                Some(x) => {
                    let mut b = Vec::new();
                    convert_into(x, Glob::Default, &mut b)?;
                    b
                }
                None => b"/[^/\\x00][^\\x00]*".to_vec(),
            };
            let mut target: Vec<Vec<u8>> = Vec::new();
            if !s.stacking {
                let (stack, ns, name) = parse_label(&tbuf)?;
                if stack {
                    return Err(format!(
                        "The current kernel does not support stacking of named transitions: {}",
                        String::from_utf8_lossy(&tbuf)
                    ));
                }
                if let Some(ns) = ns {
                    target.push(ns);
                }
                target.push(name);
            } else {
                target.push(tbuf.clone());
            }
            let t: Vec<&[u8]> = target.iter().map(|v| v.as_slice()).collect();
            set.add_vec(e.priority, e.mode, CHANGE_PROFILE | ONEXEC, 0, &t, false)
                .map_err(bad)?;
            set.add_vec(e.priority, e.mode, ONEXEC, 0, &[&xbuf], false)
                .map_err(bad)?;
            let onexec = ONEXEC | (e.perms & (EXEC_BITS | ALL_EXEC_UNSAFE));
            let mut all: Vec<&[u8]> = vec![&xbuf];
            all.extend(t.iter().copied());
            set.add_vec(e.priority, e.mode, onexec, 0, &all, false)
                .map_err(bad)?;
        }
    }
    Ok(set)
}

pub fn file_dfa(prof: &mut Profile, s: &Support) -> Result<Option<Dfa>, String> {
    let set = file_rules(prof, s)?;
    if set.is_empty() {
        return Ok(None);
    }
    set.build(true, true, s.limits)
        .map(|(d, _)| Some(d))
        .map_err(|e| dfa_error(e, "file rules"))
}

/// upstream's mediates rules: one per class the kernel should mediate
/// for this profile, so the kernel finds a state where the class byte
/// leads.
fn mediates(prof: &Profile, s: &Support, set: &mut RuleSet) -> Result<(), String> {
    use crate::apparmor::class::*;
    let bad = |_| "bad regular expression in mediates rule".to_string();
    let add = |class: &str, priority: i32, set: &mut RuleSet| {
        set.add(class.as_bytes(), priority, RuleMode::Allow, MAY_READ, 0)
            .map_err(bad)
    };
    let d = |c: u32| format!("\\d{c}");
    let sub = |c: u32, sub: u32| format!("\\d{c}\\000{sub}");
    const AF_UNIX: u32 = 1;
    if s.userns {
        add(&d(CLASS_NS), MIN_INTERNAL_PRIORITY, set)?;
    }
    if prof.flags.mode == Mode::Unconfined || prof.flags.mode == Mode::DefaultAllow {
        return Ok(());
    }
    let top = MAX_INTERNAL_PRIORITY;
    if s.abi_version > 5 {
        add(&d(CLASS_FILE), top, set)?;
    }
    if s.mount {
        add(&d(CLASS_MOUNT), top, set)?;
    }
    if s.dbus {
        add(&d(CLASS_DBUS), top, set)?;
    }
    if s.signal {
        add(&d(CLASS_SIGNAL), top, set)?;
    }
    if s.ptrace {
        add(&d(CLASS_PTRACE), top, set)?;
    }
    if s.networkv8 {
        add(&d(CLASS_NETV8), top, set)?;
    }
    if s.networkv9_skb {
        add(&d(CLASS_NETV9_SKB), top, set)?;
    }
    // upstream writes these as `if (v9 && (!add || !add)) goto out;
    // else if (v7 && ...)`: the else follows every successful v9 add,
    // so a kernel with both gets both.
    if s.unixv9 {
        add(&d(CLASS_NETV9), top, set)?;
        add(&sub(CLASS_NETV9, AF_UNIX), top, set)?;
    }
    if s.unixv7 {
        add(&d(CLASS_NET), top, set)?;
        add(&sub(CLASS_NET, AF_UNIX), top, set)?;
    }
    if s.posix_mqueue {
        add(&d(CLASS_POSIX_MQUEUE), top, set)?;
    }
    if s.sysv_mqueue {
        add(&d(CLASS_SYSV_MQUEUE), top, set)?;
    }
    if s.io_uring {
        add(&d(CLASS_IO_URING), MIN_INTERNAL_PRIORITY, set)?;
    }
    Ok(())
}

/// The policy automaton: every class rule, then the mediates rules.
/// An error names the rule it came from when there is one.
pub fn policydb(
    prof: &mut Profile,
    s: &Support,
    net: &mut Option<crate::apparmor::binary::NetTable>,
) -> Result<Option<Dfa>, (String, Option<crate::apparmor::source::Span>)> {
    use crate::apparmor::class::ClassRule;
    let mut set = RuleSet::default();
    for r in &prof.rules {
        if let PolicyRule::Class { rule, span } = r {
            let at = |m| (m, Some(*span));
            if let ClassRule::Unix(u) = &**rule {
                // A unix rule always adds its downgraded network rule,
                // whether or not the kernel mediates unix sockets.
                u.downgrade_table(net);
                if let Some(n) = u.downgraded().map_err(at)? {
                    if !s.network_policydb() {
                        n.update_compat(net);
                    }
                    n.gen(&mut set, s).map_err(at)?;
                }
            }
            rule.gen(&mut set, s).map_err(at)?;
        }
    }
    mediates(prof, s, &mut set).map_err(|m| (m, None))?;
    if set.is_empty() {
        return Ok(None);
    }
    set.build(false, true, s.limits)
        .map(|(d, _)| Some(d))
        .map_err(|e| (dfa_error(e, "policy rules"), None))
}

/// The automaton the kernel matches executables against to pick this
/// profile, and its priority length. None when the profile attaches by a
/// plain path, which the kernel compares without an automaton.
pub fn xmatch(prof: &mut Profile, s: &Support) -> Result<Option<(Dfa, usize)>, String> {
    let mut name = match &prof.attachment {
        Some(a) => a.clone(),
        None => local_name(&prof.name).to_vec(),
    };
    filter_slashes(&mut name);
    if let Some(a) = prof.attachment.as_mut() {
        *a = name.clone();
    }
    let mut tbuf = Vec::new();
    let ptype = convert_into(&name, Glob::Default, &mut tbuf).map_err(|_| {
        format!(
            "Invalid profile name '{}' - bad regular expression",
            String::from_utf8_lossy(&name)
        )
    })?;
    let has_xattrs = prof.xattrs.as_ref().is_some_and(|x| !x.conds.is_empty());
    if ptype == PatternType::Basic
        && prof.altnames.is_empty()
        && prof.attachment.is_none()
        && !has_xattrs
    {
        return Ok(None);
    }
    let bad = |_| "bad regular expression in attachment".to_string();
    let mut set = RuleSet::default();
    set.add(&tbuf, 0, RuleMode::Allow, MAY_EXEC, 0)
        .map_err(bad)?;
    for alt in prof.altnames.iter_mut() {
        filter_slashes(alt);
        let mut b = Vec::new();
        let _ = convert(alt, Glob::Default, &mut b);
        set.add(&b, 0, RuleMode::Allow, MAY_EXEC, 0).map_err(bad)?;
    }
    if has_xattrs {
        if !(s.domain_xattr && s.oob) {
            prof.xattrs = None;
        } else if let Some(x) = &prof.xattrs {
            // Upstream's condition list is in reverse text order.
            for c in x.conds.iter().rev() {
                let value: &[u8] =
                    if c.op == crate::apparmor::ast::CondOp::Eq && !c.values.is_empty() {
                        &c.values[0]
                    } else {
                        b"**"
                    };
                let mut b = b"\\x00".to_vec();
                let _ = convert(value, Glob::Null, &mut b);
                set.append(&b, true, true).map_err(bad)?;
            }
        }
    }
    let (dfa, len) = set
        .build(false, true, s.limits)
        .map_err(|e| dfa_error(e, "attachment"))?;
    Ok(Some((dfa, len)))
}
