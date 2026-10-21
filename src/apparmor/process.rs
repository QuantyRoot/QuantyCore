//! What upstream does to each profile after the whole file is parsed and
//! before it builds automata: implied rules, variables, aliases, and the
//! merging of identical file rules. Profiles are processed in name order,
//! each before its hats, as upstream walks them.

use super::eval::Symtab;
use super::model::{perm::*, *};
use super::source::{Error, Sources};

/// The class rules an `all` rule implies, each given the `all` rule's
/// prefix once more through add_prefix, whose errors upstream ignores.
fn implied_class_rules(p: &Prefix) -> Result<Vec<super::class::ClassRule>, String> {
    use super::class::*;
    let fail = |m: String| m;
    let with = |mut h: Head| {
        if let Ok(np) = add_prefix(h.prefix, *p) {
            h.prefix = np;
        }
        h
    };
    let mut out = Vec::new();
    let mut u = unix::Unix::implied(u32::MAX, p.audit, p.mode).map_err(fail)?;
    u.head = with(u.head);
    out.push(ClassRule::Unix(u));
    let mut d = dbus::Dbus::new(&None, &[], &None, Prefix::default()).map_err(fail)?;
    d.head = with(Head {
        prefix: Prefix::default(),
        perms: d.head.perms,
    });
    out.push(ClassRule::Dbus(d));
    let mut i = io_uring::IoUring::new(&None, &[], &None, Prefix::default()).map_err(fail)?;
    i.head = with(Head {
        prefix: Prefix::default(),
        perms: i.head.perms,
    });
    out.push(ClassRule::IoUring(i));
    let mut m = mqueue::Mqueue::new(&None, &[], &None, Prefix::default()).map_err(fail)?;
    m.head = with(Head {
        prefix: Prefix::default(),
        perms: m.head.perms,
    });
    out.push(ClassRule::Mqueue(m));
    let mut t = ptrace::Ptrace::new(&None, &[], Prefix::default()).map_err(fail)?;
    t.head = with(Head {
        prefix: Prefix::default(),
        perms: t.head.perms,
    });
    out.push(ClassRule::Ptrace(t));
    let mut sg = signal::Signal::new(&None, &[], Prefix::default()).map_err(fail)?;
    sg.head = with(Head {
        prefix: Prefix::default(),
        perms: sg.head.perms,
    });
    out.push(ClassRule::Signal(sg));
    let mut us = userns::Userns::new(&None, &[], Prefix::default()).map_err(fail)?;
    us.head = with(Head {
        prefix: Prefix::default(),
        perms: us.head.perms,
    });
    out.push(ClassRule::Userns(us));
    for kind in [
        crate::apparmor::ast::MountKind::Mount,
        crate::apparmor::ast::MountKind::Remount,
        crate::apparmor::ast::MountKind::Umount,
        crate::apparmor::ast::MountKind::PivotRoot,
    ] {
        let mut m = mount::Mount::parse(kind, &[], &None, &None, &None).map_err(fail)?;
        m.head = with(m.head);
        out.push(ClassRule::Mount(m));
    }
    let mut n = network::Network::parse(0, &[], &[], &None).map_err(fail)?;
    if let Ok(np) = add_prefix(n.head.prefix, *p) {
        n.head.prefix = np;
    }
    out.push(ClassRule::Network(n));
    Ok(out)
}

pub(crate) struct Processor<'s> {
    pub sources: &'s Sources,
    pub symtab: Symtab,
    pub aliases: Vec<(Vec<u8>, Vec<u8>)>,
    pub support: super::compile::Support,
    /// upstream's per family network table, shared by the whole file.
    pub net: Option<super::binary::NetTable>,
}

/// Upstream's filter_slashes: runs of slashes become one, except that a
/// path starting with exactly two keeps them, as Linux reserves `//`.
pub(crate) fn filter_slashes(path: &mut Vec<u8>) {
    if path.len() < 2 {
        return;
    }
    let mut out = Vec::with_capacity(path.len());
    let mut i = 0;
    if path[0] == b'/' && path[1] == b'/' && path.get(2) != Some(&b'/') {
        out.extend_from_slice(b"//");
        i = 2;
    }
    let mut seen = false;
    while i < path.len() {
        let c = path[i];
        if c == b'/' {
            if !seen {
                out.push(c);
                seen = true;
            }
        } else {
            seen = false;
            out.push(c);
        }
        i += 1;
    }
    *path = out;
}

/// The last component of a name made of `parent//child` parts.
pub(crate) fn local_name(name: &[u8]) -> &[u8] {
    let mut n = name;
    while let Some(p) = n.windows(2).position(|w| w == b"//") {
        n = &n[p + 2..];
    }
    n
}

/// Escapes what a profile name could contain that the pattern compiler
/// would read as a pattern, for `@{profile_name}`.
fn escape_re(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'\\' {
            out.push(s[i]);
            if let Some(&n) = s.get(i + 1) {
                out.push(n);
            }
            i += 2;
            continue;
        }
        if b"{}[]*?".contains(&s[i]) {
            out.push(b'\\');
        }
        out.push(s[i]);
        i += 1;
    }
    out
}

type R<T> = Result<T, Error>;

impl Processor<'_> {
    pub(crate) fn policy(&mut self, policy: &mut Policy) -> R<()> {
        let mut aliases = self.aliases.clone();
        aliases.sort();
        aliases.dedup();
        self.aliases = aliases;
        for prof in policy.profiles.values_mut() {
            self.tree(prof)?;
        }
        Ok(())
    }

    /// What an `all` rule implies: every file permission but exec,
    /// inherit execution two priorities lower so that any other exec
    /// rule wins, every capability, and a rule of every kind in the
    /// policy automaton. The rule's prefix is applied twice, once when
    /// the rule is made and once to each implied rule, so `deny all`
    /// ends up unquieted and `audit deny all` quieted.
    fn all_rules(&mut self, prof: &mut Profile) -> R<()> {
        let alls: Vec<(Prefix, super::source::Span)> = prof
            .rules
            .iter()
            .filter_map(|r| match r {
                PolicyRule::All { prefix, span } => Some((*prefix, *span)),
                _ => None,
            })
            .collect();
        for (p, span) in alls {
            let p = super::build::rule_prefix(&p);
            let deny = p.mode == RuleMode::Deny;
            let mut perms = BASE_PERMS & !(EXEC_TYPE | MAY_EXEC);
            if !deny {
                perms |= perms << OTHER_SHIFT;
            }
            let mut e = Entry::new(b"/{**,}".to_vec(), perms, None, span);
            super::build::entry_add_prefix(&mut e, &p)
                .map_err(|m| self.sources.error_at(span, m))?;
            prof.add_entry(e);

            let mut perms = MAY_EXEC;
            if !deny {
                perms |= EXEC_INHERIT;
            }
            perms |= perms << OTHER_SHIFT;
            let ix = Prefix {
                priority: p.priority - 2,
                ..p
            };
            let mut e = Entry::new(b"/{**,}".to_vec(), perms, None, span);
            super::build::entry_add_prefix(&mut e, &ix)
                .map_err(|m| self.sources.error_at(span, m))?;
            prof.add_entry(e);

            for rule in implied_class_rules(&p).map_err(|m| self.sources.error_at(span, m))? {
                if let (super::class::ClassRule::Network(n), false) =
                    (&rule, self.support.network_policydb())
                {
                    n.update_compat(&mut self.net);
                }
                prof.rules.push(PolicyRule::Class {
                    rule: Box::new(rule),
                    span,
                });
            }
            if deny {
                prof.caps.deny |= u64::MAX;
                if p.audit != Audit::Force {
                    prof.caps.quiet |= u64::MAX;
                }
            } else {
                prof.caps.allow |= u64::MAX;
                if p.audit != Audit::Unspecified {
                    prof.caps.audit |= u64::MAX;
                }
            }
        }
        Ok(())
    }

    fn merge_class_rules(&mut self, prof: &mut Profile) {
        let mut class = Vec::new();
        let mut rest = Vec::new();
        for r in prof.rules.drain(..) {
            match r {
                PolicyRule::Class { rule, span } => class.push((*rule, span)),
                other => rest.push(other),
            }
        }
        super::class::merge_rules(&mut class);
        prof.rules = rest;
        prof.rules
            .extend(class.into_iter().map(|(rule, span)| PolicyRule::Class {
                rule: Box::new(rule),
                span,
            }));
    }

    fn profile(&mut self, prof: &mut Profile, parents: &[Vec<u8>]) -> R<()> {
        self.all_rules(prof)?;
        if prof.is_hat() || !prof.hats.is_empty() {
            let span = prof.span;
            prof.add_entry(Entry::new(
                b"/proc/*/attr/apparmor/".to_vec(),
                MAY_READ,
                None,
                span,
            ));
            prof.add_entry(Entry::new(
                b"/sys/module/apparmor/parameters/enabled".to_vec(),
                MAY_READ,
                None,
                span,
            ));
            prof.add_entry(Entry::new(
                b"/proc/[0-9]*/attr/{apparmor/,}current".to_vec(),
                MAY_WRITE,
                None,
                span,
            ));
        }
        self.variables(prof, parents)?;
        self.apply_aliases(prof);
        self.merge(prof)?;
        self.merge_class_rules(prof);
        let span = prof.span;
        prof.xmatch = super::compile::xmatch(prof, &self.support)
            .map_err(|m| self.sources.error_at(span, m))?;
        prof.file_dfa = super::compile::file_dfa(prof, &self.support)
            .map_err(|m| self.sources.error_at(span, m))?;
        prof.policydb = super::compile::policydb(prof, &self.support, &mut self.net)
            .map_err(|(m, at)| self.sources.error_at(at.unwrap_or(span), m))?;
        Ok(())
    }

    /// A profile and, after it, each of its hats and child profiles in
    /// name order, each before its own: upstream's order, from an
    /// explicit stack since profiles nest as deep as the parser allows.
    /// Hats are taken out while they are processed and put back after.
    fn tree(&mut self, root: &mut Profile) -> R<()> {
        type Key = super::model::ProfileKey;
        struct Work {
            hat: Box<Profile>,
            parent: usize,
            key: Key,
            chain: Vec<Vec<u8>>,
        }
        const ROOT: usize = usize::MAX;
        self.profile(root, &[])?;
        let mut work: Vec<Work> = Vec::new();
        let chain = vec![root.name.clone()];
        for (key, hat) in std::mem::take(&mut root.hats).into_iter().rev() {
            work.push(Work {
                hat,
                parent: ROOT,
                key,
                chain: chain.clone(),
            });
        }
        let mut done: Vec<(Box<Profile>, usize, Key)> = Vec::new();
        while let Some(Work {
            mut hat,
            parent,
            key,
            chain,
        }) = work.pop()
        {
            self.profile(&mut hat, &chain)?;
            let me = done.len();
            let mut sub = chain.clone();
            sub.push(hat.name.clone());
            for (key, h) in std::mem::take(&mut hat.hats).into_iter().rev() {
                work.push(Work {
                    hat: h,
                    parent: me,
                    key,
                    chain: sub.clone(),
                });
            }
            done.push((hat, parent, key));
        }
        while let Some((hat, parent, key)) = done.pop() {
            if parent == ROOT {
                root.hats.insert(key, hat);
            } else {
                done[parent].0.hats.insert(key, hat);
            }
        }
        Ok(())
    }

    fn expand(&mut self, s: &mut Vec<u8>, span: super::source::Span) -> R<()> {
        let e = self
            .symtab
            .expand_alternation(s)
            .map_err(|m| self.sources.error_at(span, m))?;
        *s = e;
        Ok(())
    }

    fn variables(&mut self, prof: &mut Profile, parents: &[Vec<u8>]) -> R<()> {
        let span = prof.span;
        self.expand(&mut prof.name, span)?;
        if let Some(a) = prof.attachment.as_mut() {
            let e = self
                .symtab
                .expand_alternation(a)
                .map_err(|m| self.sources.error_at(span, m))?;
            *a = e;
        } else if prof.name.first() == Some(&b'/') {
            let mut a = local_name(&prof.name).to_vec();
            filter_slashes(&mut a);
            prof.attachment = Some(a);
        }
        for p in [
            &mut prof.flags.disconnected_path,
            &mut prof.flags.disconnected_ipc,
        ]
        .into_iter()
        .flatten()
        {
            let mut e = self
                .symtab
                .expand_alternation(p)
                .map_err(|m| self.sources.error_at(span, m))?;
            filter_slashes(&mut e);
            if e.first() != Some(&b'/') {
                return Err(self
                    .sources
                    .error_at(span, "attach_disconnected path must begin with a /"));
            }
            while e.last() == Some(&b'/') {
                e.pop();
            }
            *p = e;
        }

        let mut hname = Vec::new();
        for p in parents {
            hname.extend_from_slice(p);
            hname.extend_from_slice(b"//");
        }
        hname.extend_from_slice(&prof.name);

        // The path variables replace the user's only for a profile that
        // has an attachment; otherwise a user's own stays visible.
        let mut names: Vec<&[u8]> = vec![b"profile_name"];
        if prof.attachment.is_some() {
            names.push(b"attach_path");
            names.push(b"exec_path");
        }
        let saved: Vec<(&[u8], Option<super::eval::Var>)> = names
            .into_iter()
            .map(|n| (n, self.symtab.remove(n)))
            .collect();
        let result = self.variables_inner(prof, &hname);
        for (n, v) in saved {
            self.symtab.restore(n, v);
        }
        result
    }

    fn variables_inner(&mut self, prof: &mut Profile, hname: &[u8]) -> R<()> {
        let span = prof.span;
        let err = |m: String| self.sources.error_at(span, m);
        self.symtab
            .define_set(b"profile_name", escape_re(hname))
            .map_err(err)?;
        if let Some(a) = &prof.attachment {
            self.symtab
                .define_set(b"attach_path", a.clone())
                .map_err(|m| self.sources.error_at(span, m))?;
            self.symtab
                .define_set(b"exec_path", a.clone())
                .map_err(|m| self.sources.error_at(span, m))?;
        }
        for e in prof.entries.iter_mut() {
            let n = self
                .symtab
                .expand_alternation(&e.name)
                .map_err(|m| self.sources.error_at(e.span, m))?;
            e.name = n;
            if let Some(l) = e.link_name.as_mut() {
                let n = self
                    .symtab
                    .expand_alternation(l)
                    .map_err(|m| self.sources.error_at(e.span, m))?;
                *l = n;
            }
        }
        let symtab = &mut self.symtab;
        for r in prof.rules.iter_mut() {
            if let PolicyRule::Class { rule, span } = r {
                let span = *span;
                rule.expand(&mut |s: &mut Vec<u8>| {
                    *s = symtab.expand_alternation(s)?;
                    Ok(())
                })
                .map_err(|m| self.sources.error_at(span, m))?;
            }
        }
        Ok(())
    }

    /// Aliases give the profile alternate attachment names and duplicate
    /// file rules under the aliased path. They are applied in sorted
    /// order, and a duplicate is not aliased again.
    fn apply_aliases(&mut self, prof: &mut Profile) {
        for (from, to) in &self.aliases {
            let name = prof.attachment.as_ref().unwrap_or(&prof.name);
            if name.starts_with(from) {
                let mut n = to.clone();
                n.extend_from_slice(&name[from.len()..]);
                prof.altnames.insert(0, n);
            }
        }
        for (from, to) in &self.aliases {
            let mut i = 0;
            while i < prof.entries.len() {
                let e = &prof.entries[i];
                if e.perms & SHARED_PERMS != 0 || e.alias_ignore {
                    i += 1;
                    continue;
                }
                let mut dup: Option<Entry> = None;
                if e.name.starts_with(from) {
                    let mut d = e.clone();
                    let mut n = to.clone();
                    n.extend_from_slice(&e.name[from.len()..]);
                    d.name = n;
                    dup = Some(d);
                }
                if let Some(l) = &e.link_name {
                    if l.starts_with(from) {
                        let mut d = dup.take().unwrap_or_else(|| e.clone());
                        let mut n = to.clone();
                        n.extend_from_slice(&l[from.len()..]);
                        d.link_name = Some(n);
                        dup = Some(d);
                    }
                }
                if let Some(mut d) = dup {
                    d.alias_ignore = true;
                    prof.entries.insert(i + 1, d);
                }
                i += 1;
            }
        }
    }

    /// Upstream's process_file_entries: identical file rules are merged,
    /// and two that name different exec transitions for the same path are
    /// an error.
    fn merge(&mut self, prof: &mut Profile) -> R<()> {
        if prof.entries.len() < 2 {
            return Ok(());
        }
        let mut v: Vec<Entry> = prof.entries.drain(..).collect();
        v.sort_by(file_cmp);
        let mut out: Vec<Entry> = Vec::with_capacity(v.len());
        for e in v {
            if let Some(last) = out.last_mut() {
                if file_cmp(last, &e).is_eq() {
                    if !x_consistent(last.perms, e.perms) {
                        return Err(self.sources.error_at(
                            e.span,
                            format!(
                                "profile {}: has merged rule {} with conflicting x modifiers",
                                String::from_utf8_lossy(&prof.name),
                                String::from_utf8_lossy(&last.name)
                            ),
                        ));
                    }
                    last.perms |= e.perms;
                    continue;
                }
            }
            out.push(e);
        }
        prof.entries = out.into();
        Ok(())
    }
}

/// Compares two strings from their last byte backwards, as upstream's
/// strrcmp does for the merge order. Only equality matters for what is
/// merged; the order only groups equal entries.
fn rcmp(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    a.iter().rev().cmp(b.iter().rev())
}

fn file_cmp(a: &Entry, b: &Entry) -> std::cmp::Ordering {
    use std::cmp::Ordering::*;
    match (&a.link_name, &b.link_name) {
        (Some(x), Some(y)) => {
            let r = rcmp(x, y);
            if r != Equal {
                return r;
            }
            let r = b.subset.cmp(&a.subset);
            if r != Equal {
                return r;
            }
        }
        (Some(_), None) => return Greater,
        (None, Some(_)) => return Less,
        (None, None) => {}
    }
    let r = (a.mode as u8).cmp(&(b.mode as u8));
    if r != Equal {
        return r;
    }
    let r = a.audit.cmp(&b.audit);
    if r != Equal {
        return r;
    }
    let r = b.priority.cmp(&a.priority);
    if r != Equal {
        return r;
    }
    rcmp(&a.name, &b.name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slashes_collapse_except_a_leading_pair() {
        let f = |s: &str| {
            let mut v = s.as_bytes().to_vec();
            filter_slashes(&mut v);
            String::from_utf8(v).unwrap()
        };
        assert_eq!(f("///foo//////f//oo////////////////"), "/foo/f/oo/");
        assert_eq!(f("//usr"), "//usr");
        assert_eq!(f("///usr"), "/usr");
        assert_eq!(f("/"), "/");
    }

    #[test]
    fn profile_names_are_escaped_for_patterns() {
        assert_eq!(escape_re(b"a{b}[c]*?"), b"a\\{b\\}\\[c\\]\\*\\?".to_vec());
        assert_eq!(escape_re(b"a\\*"), b"a\\*".to_vec());
    }
}
