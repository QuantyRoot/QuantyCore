//! From the syntax tree to profiles: what upstream's grammar actions do
//! while it parses. The preamble is evaluated in order, conditions are
//! decided, prefixes are applied, permission strings become bit masks,
//! and the checks upstream makes at that point are made here.
//!
//! Both branches of an `if` are built before one is chosen, because
//! upstream runs the actions of both and reports errors in either.

use super::ast::{self, ExecMode, Item, ProfileKeyword};
use super::class::{self, ClassRule};
use super::eval::Symtab;
use super::features::{Features, DEFAULT_ABI};
use super::model::{perm::*, *};
use super::source::{Error, Opened, Resolver, Sources, Span};
use super::tables;

struct CapEntry {
    name: Vec<u8>,
    cap: u32,
    backmap: Option<u32>,
    in_kernel: bool,
}

pub(crate) struct Builder<'s> {
    pub sources: &'s Sources,
    pub symtab: Symtab,
    pub aliases: Vec<(Vec<u8>, Vec<u8>)>,
    pub warnings: Vec<Error>,
    kernel: Features,
    /// Fixed by the caller (upstream's -M), else None.
    pinned: Option<Features>,
    policy: Option<Features>,
    caps: Vec<CapEntry>,
    abi_rules: Vec<ast::Abi>,
    /// upstream's per family network table as parsing leaves it: filled
    /// by network rules, and freed whenever a block or a condition's
    /// branch is deleted, since every profile object holds the shared
    /// table and frees it when it goes.
    net: Option<super::binary::NetTable>,
}

type R<T> = Result<T, Error>;

impl<'s> Builder<'s> {
    pub(crate) fn new(
        sources: &'s Sources,
        kernel: Features,
        pinned: Option<Features>,
    ) -> Builder<'s> {
        let mut b = Builder {
            sources,
            symtab: Symtab::default(),
            aliases: Vec::new(),
            warnings: Vec::new(),
            kernel,
            pinned,
            policy: None,
            caps: tables::CAPABILITIES
                .iter()
                .map(|&(n, cap, backmap)| CapEntry {
                    name: n.to_vec(),
                    cap,
                    backmap,
                    in_kernel: false,
                })
                .collect(),
            abi_rules: Vec::new(),
            net: None,
        };
        let k = b.kernel.clone();
        b.add_caps(&k, true);
        b
    }

    /// upstream's add_cap_feature_mask: a feature set's capability mask
    /// numbers its names by position. A known name at another number is
    /// ignored; an unknown one is added, with backmap 0, which upstream's
    /// table sets for every added entry.
    fn add_caps(&mut self, f: &Features, kernel: bool) {
        let Some(v) = f.value("caps/mask") else {
            return;
        };
        for (n, w) in v
            .split(|c| c.is_ascii_whitespace())
            .filter(|w| !w.is_empty())
            .enumerate()
        {
            let n = n as u32;
            match self.caps.iter_mut().find(|e| e.name == w) {
                Some(e) => {
                    if e.cap == n && kernel {
                        e.in_kernel = true;
                    }
                }
                None => self.caps.push(CapEntry {
                    name: w.to_vec(),
                    cap: n,
                    backmap: Some(0),
                    in_kernel: kernel,
                }),
            }
        }
    }

    /// A capability rule's number. The backmap and kernel flag are looked
    /// up by number, finding the first entry with it, as upstream's maps
    /// keep the first insert.
    fn capability(&self, name: &[u8]) -> Option<u32> {
        let cap = self.caps.iter().find(|e| e.name == name)?.cap;
        let by_num = self.caps.iter().find(|e| e.cap == cap);
        match by_num {
            Some(&CapEntry {
                backmap: Some(b),
                in_kernel: false,
                ..
            }) => Some(b),
            _ => Some(cap),
        }
    }

    /// The features a profile is compiled against: the kernel's, as far
    /// as the policy's abi allows.
    pub(crate) fn policy_features(&self) -> Features {
        self.policy.clone().expect("set after the preamble")
    }

    fn both(&self, f: &str) -> bool {
        self.kernel.supports(f) && self.policy_features().supports(f)
    }

    pub(crate) fn support(&self, limits: super::compile::dfa::Limits) -> super::compile::Support {
        let p = self.policy_features();
        let both = |f: &str| self.kernel.supports(f) && p.supports(f);
        let permstable = if self.kernel.supports("policy/permstable32") {
            if self.kernel.supports("policy/permstable32_version/0x000003") {
                3
            } else if self.kernel.supports("policy/permstable32_version/0x000002") {
                2
            } else {
                0
            }
        } else {
            0
        };
        let k = |f: &str| self.kernel.supports(f);
        super::compile::Support {
            stacking: both("domain/stack"),
            domain_xattr: both("domain/attach_conditions/xattr"),
            oob: k("policy/outofband"),
            permstable32_version: permstable,
            limits,
            policydb: k("file"),
            abi_version: if k("policy/versions/v7") {
                7
            } else if k("policy/versions/v6") {
                6
            } else {
                5
            },
            network: both("network"),
            networkv8: both("network_v8"),
            networkv9: both("network_v9"),
            networkv9_skb: both("network_v9_skb"),
            ifacev9_skb: both("network_v9_skb/iface"),
            inetv8: both("network_v8/af_inet"),
            inetv9: both("network_v9/af_inet"),
            unixv7: both("network/af_unix"),
            unixv9: both("network_v9/af_unix"),
            mount: both("mount"),
            detached_mount: k("mount/move_mount/detached"),
            dbus: both("dbus"),
            signal: both("signal"),
            ptrace: both("ptrace"),
            userns: both("namespaces/mask/userns_create"),
            posix_mqueue: both("ipc/posix_mqueue"),
            sysv_mqueue: both("ipc/sysv_mqueue"),
            io_uring: both("io_uring"),
            flag_interruptible: both("policy/profile/interruptible"),
            flag_signal: both("policy/profile/kill.signal"),
            flag_error: both("policy/profile/error"),
            flag_disconnected_ipc: both("domain/disconnected.ipc"),
            identity_names: both("domain/identity"),
        }
    }

    /// Loads the feature set an `abi` rule names.
    fn abi_features(&self, a: &ast::Abi, resolver: &mut dyn Resolver) -> R<Features> {
        let shown = String::from_utf8_lossy(&a.name).into_owned();
        let text = if a.search {
            if a.name == b"kernel" {
                return Ok(self.kernel.clone());
            }
            if a.name == b"default" {
                return Ok(Features::from_text(DEFAULT_ABI.as_bytes()).expect("default abi"));
            }
            let mut found = None;
            for dir in resolver.search_path().to_vec() {
                let mut full = dir;
                full.push(b'/');
                full.extend_from_slice(&a.name);
                match resolver.open(&full) {
                    Opened::NotFound => continue,
                    o => {
                        found = Some(o);
                        break;
                    }
                }
            }
            found
        } else {
            match resolver.open(&a.name) {
                Opened::NotFound => None,
                o => Some(o),
            }
        };
        match text {
            None => Err(self.err(a.span, format!("Could not open '{shown}'"))),
            Some(Opened::File(t)) => Features::from_text(&t).map_err(|m| self.err(a.span, m)),
            Some(_) => Err(self.err(a.span, format!("failed to find features abi '{shown}'"))),
        }
    }

    fn err(&self, span: Span, msg: impl Into<String>) -> Error {
        self.sources.error_at(span, msg)
    }

    fn warn(&mut self, span: Span, msg: impl Into<String>) {
        let e = self.sources.error_at(span, msg);
        self.warnings.push(e);
    }

    pub(crate) fn file(&mut self, f: &ast::File, resolver: &mut dyn Resolver) -> R<Policy> {
        for p in &f.preamble {
            match p {
                ast::Preamble::Alias { from, to, .. } => {
                    self.aliases.push((from.clone(), to.clone()));
                }
                ast::Preamble::SetVar {
                    name,
                    op,
                    values,
                    span,
                } => self
                    .symtab
                    .assign_set(name, *op, values)
                    .map_err(|m| self.err(*span, m))?,
                ast::Preamble::BoolVar {
                    name,
                    op,
                    expr,
                    span,
                } => self
                    .symtab
                    .assign_bool(name, *op, expr)
                    .map_err(|m| self.err(*span, m))?,
                ast::Preamble::Abi(a) => {
                    let feats = self.abi_features(a, resolver)?;
                    if self.policy.is_none() {
                        self.policy = Some(feats);
                    }
                }
            }
        }
        if self.policy.is_none() {
            self.policy = Some(match &self.pinned {
                Some(p) => p.clone(),
                None => Features::from_text(DEFAULT_ABI.as_bytes()).expect("default abi"),
            });
        }
        let pf = self.policy_features();
        self.add_caps(&pf, false);
        let mut policy = Policy {
            aliases: self.aliases.clone(),
            ..Policy::default()
        };
        for p in &f.profiles {
            let prof = self.profile(p, false)?;
            for a in std::mem::take(&mut self.abi_rules) {
                self.abi_features(&a, resolver)?;
            }
            if prof.ns.is_none()
                && prof.name.first() != Some(&b'/')
                && p.keyword == ProfileKeyword::None
            {
                return Err(self.err(
                    p.span,
                    "Profile names must begin with a '/', namespace or keyword 'profile' or 'hat'.",
                ));
            }
            let key = (prof.ns.clone(), prof.name.clone());
            if policy.profiles.contains_key(&key) {
                return Err(self.err(
                    p.span,
                    format!(
                        "Multiple definitions for profile {} exist",
                        String::from_utf8_lossy(&prof.name)
                    ),
                ));
            }
            policy.profiles.insert(key, *prof);
        }
        policy.net_table = self.net.take();
        Ok(policy)
    }

    /// What upstream does once a profile's body is built: its name,
    /// attachment, conditions and flags. Only a hat inside a profile is
    /// refused xattrs; upstream does not check a top level `^name`.
    fn finish_profile(
        &mut self,
        p: &ast::Profile,
        nested: bool,
        mut prof: Box<Profile>,
    ) -> R<Box<Profile>> {
        let (stack, ns, name) = parse_label(&p.name)
            .map_err(|m| self.err(p.span, m.replace("%s", &String::from_utf8_lossy(&p.name))))?;
        if stack {
            return Err(self.err(p.span, "Profile names must begin with a '/' or a namespace"));
        }
        prof.ns = ns;
        prof.name = name;
        if let Some(a) = &p.attachment {
            if !(a.first() == Some(&b'/') || a.starts_with(b"@{")) {
                return Err(self.err(
                    p.span,
                    "Profile attachment must begin with a '/' or variable.",
                ));
            }
            prof.attachment = Some(a.clone());
        }
        if let Some(x) = &p.xattrs {
            if x.name != b"xattrs" {
                return Err(self.err(
                    x.span,
                    format!(
                        "profile id: invalid conditional group {}=()",
                        String::from_utf8_lossy(&x.name)
                    ),
                ));
            }
            prof.xattrs = Some(x.clone());
        }
        for id in &p.identities {
            if id.first() != Some(&b'/') && id.contains(&b' ') {
                return Err(self.err(
                    p.span,
                    format!(
                        "Space character not allowed in identities: '{}'",
                        String::from_utf8_lossy(id)
                    ),
                ));
            }
        }
        prof.identities = p.identities.clone();
        let mut flags = Flags::default();
        for (i, f) in p.flags.iter().enumerate() {
            let one = flag(f).map_err(|m| self.err(p.span, m))?;
            if i == 0 {
                flags = one;
            } else {
                merge_flags(&mut flags, one).map_err(|m| self.err(p.span, m))?;
            }
        }
        prof.flags = flags;
        if p.keyword == ProfileKeyword::Hat {
            if nested && p.xattrs.is_some() {
                return Err(self.err(p.span, "hat profiles can't use xattrs matches"));
            }
            prof.flags.flags |= FLAG_HAT;
        }
        self.post_parse(&mut prof)?;
        Ok(prof)
    }

    /// The part of upstream's post_parse_profile that runs at the end of
    /// each profile while parsing: named exec transitions move into the
    /// exec table, and change_profile rules bring access to the attribute
    /// files they need.
    fn post_parse(&mut self, prof: &mut Profile) -> R<()> {
        let mut cp_perms = 0;
        let name = prof.name.clone();
        for i in 0..prof.entries.len() {
            if prof.entries[i].nt_name.is_some() {
                let span = prof.entries[i].span;
                let n = add_named_transition(prof, i);
                if n == 0 {
                    return Err(self.err(
                        span,
                        format!(
                            "Profile {} has too many specified profile transitions.",
                            String::from_utf8_lossy(&name)
                        ),
                    ));
                }
                let e = &mut prof.entries[i];
                let mut perms = 0;
                if e.perms & USER_EXEC != 0 {
                    perms |= shift(n << 10, USER_SHIFT);
                }
                if e.perms & OTHER_EXEC != 0 {
                    perms |= shift(n << 10, OTHER_SHIFT);
                }
                e.perms = (e.perms & !ALL_EXEC_MODIFIERS) | (perms & ALL_EXEC_MODIFIERS);
            }
            cp_perms |= prof.entries[i].perms & CHANGE_PROFILE;
        }
        if cp_perms & CHANGE_PROFILE != 0 {
            add_proc_access(prof, b"/proc/*/attr/{apparmor/,}{current,exec}");
        }
        Ok(())
    }

    /// One item of a block, in the block's profile. Items that open a
    /// block of their own return it, to be built before this one
    /// continues.
    fn item<'a>(&mut self, prof: &mut Profile, item: &'a Item) -> R<Option<Frame<'a>>> {
        match item {
            Item::Abi(a) => {
                self.abi_rules.push(a.clone());
                Ok(None)
            }
            Item::Rule { prefix, rule, span } => {
                let prefix = self.prefix(prefix)?;
                self.rule(prof, prefix, rule, *span)?;
                Ok(None)
            }
            Item::Block {
                prefix,
                items,
                span,
            } => {
                let prefix = self.prefix(prefix)?;
                if prefix.priority != 0 {
                    return Err(self.err(*span, "priority is not allowed on rule blocks"));
                }
                Ok(Some(Frame::body(items, *span, Done::Block(prefix))))
            }
            Item::Hat(p) | Item::Child(p) => {
                Ok(Some(Frame::body(&p.body, p.span, Done::Profile(p, true))))
            }
            Item::If(i) => {
                let truth = self.truth(i)?;
                Ok(Some(Frame::body(&i.then, i.span, Done::Then(i, truth))))
            }
            Item::Rlimit {
                resource,
                value,
                unit,
                span,
            } => {
                self.rlimit(prof, resource, value, unit.as_deref(), *span)?;
                Ok(None)
            }
        }
    }

    /// Only the file rules of a prefixed block survive in upstream;
    /// everything else in it is dropped with the block.
    fn block(&mut self, prof: &mut Profile, prefix: Prefix, block: Box<Profile>) -> R<()> {
        for mut e in block.entries {
            entry_add_prefix(&mut e, &prefix).map_err(|m| self.err(e.span, m))?;
            prof.add_entry(e);
        }
        Ok(())
    }

    fn truth(&mut self, i: &ast::If) -> R<bool> {
        self.symtab.eval(&i.cond).map_err(|m| self.err(i.span, m))
    }

    /// A profile, hat or child profile, with its whole body. The blocks
    /// nest as deep as the parser allows, so they are built from an
    /// explicit stack, in the order upstream's grammar builds them: a
    /// condition is evaluated, then its branch, then the branch after
    /// `else`, each in a profile of its own.
    fn profile(&mut self, p: &ast::Profile, nested: bool) -> R<Box<Profile>> {
        let mut stack = vec![Frame::body(&p.body, p.span, Done::Profile(p, nested))];
        loop {
            let Some(Frame::Body { items, prof, .. }) = stack.last_mut() else {
                unreachable!("the top of the stack is a block being built");
            };
            if let Some(item) = items.next() {
                if let Some(f) = self.item(prof, item)? {
                    stack.push(f);
                }
                continue;
            }
            let Some(Frame::Body { prof, done, .. }) = stack.pop() else {
                unreachable!("checked above");
            };
            match done {
                Done::Profile(p, nested) => {
                    let prof = self.finish_profile(p, nested, prof)?;
                    match stack.last_mut() {
                        None => return Ok(prof),
                        Some(Frame::Body { prof: parent, .. }) => {
                            add_hat(parent, prof).map_err(|m| self.err(p.span, m))?;
                        }
                        Some(Frame::Cond { .. }) => unreachable!("a profile is an item of a block"),
                    }
                }
                Done::Block(prefix) => {
                    let Some(Frame::Body { prof: parent, .. }) = stack.last_mut() else {
                        unreachable!("a block is an item of a block");
                    };
                    self.block(parent, prefix, prof)?;
                    self.net = None;
                }
                Done::Then(i, truth) => match &i.otherwise {
                    None => self.deliver(&mut stack, truth.then_some(prof))?,
                    Some(ast::Else::Block(b)) => {
                        stack.push(Frame::body(b, i.span, Done::Else(truth, prof)))
                    }
                    Some(ast::Else::If(inner)) => {
                        stack.push(Frame::Cond { truth, then: prof });
                        let t = self.truth(inner)?;
                        stack.push(Frame::body(&inner.then, inner.span, Done::Then(inner, t)));
                    }
                },
                Done::Else(truth, then) => {
                    let chosen = if truth { then } else { prof };
                    self.deliver(&mut stack, Some(chosen))?;
                }
            }
        }
    }

    /// Hands the branch a condition chose, after the conditions waiting
    /// on it have chosen, to the block the condition is in.
    fn deliver(&mut self, stack: &mut Vec<Frame<'_>>, mut chosen: Option<Box<Profile>>) -> R<()> {
        // Every condition deletes at least one branch.
        self.net = None;
        while let Some(Frame::Cond { .. }) = stack.last() {
            let Some(Frame::Cond { truth, then }) = stack.pop() else {
                unreachable!("checked above");
            };
            chosen = if truth { Some(then) } else { chosen };
        }
        let Some(Frame::Body { prof, .. }) = stack.last_mut() else {
            unreachable!("a condition is an item of a block");
        };
        if let Some(c) = chosen {
            self.merge(prof, c)?;
        }
        Ok(())
    }

    /// Upstream's merge_policy for a chosen branch: its entries go after
    /// the existing ones, capabilities, rules and hats are combined.
    /// Resource limits set inside the branch are not carried over, and
    /// neither is whether it used prompt rules, as upstream does.
    fn merge(&mut self, prof: &mut Profile, b: Box<Profile>) -> R<()> {
        let b = *b;
        prof.entries.extend(b.entries);
        prof.flags.audit |= b.flags.audit;
        prof.caps.allow |= b.caps.allow;
        prof.caps.audit |= b.caps.audit;
        prof.caps.deny |= b.caps.deny;
        prof.caps.quiet |= b.caps.quiet;
        prof.rules.extend(b.rules);
        for (_, hat) in b.hats {
            let span = hat.span;
            add_hat(prof, hat).map_err(|m| self.err(span, m))?;
        }
        Ok(())
    }

    fn prefix(&self, p: &ast::Prefix) -> R<Prefix> {
        let mut out = Prefix {
            priority: 0,
            audit: if p.audit {
                Audit::Force
            } else {
                Audit::Unspecified
            },
            mode: p.mode,
            owner: p.owner,
        };
        if let Some((text, span)) = &p.priority {
            let s = String::from_utf8_lossy(text);
            let v: i64 = match s.parse::<i64>() {
                Ok(v) => v,
                Err(_) if !s.is_empty() && s[1..].bytes().all(|b| b.is_ascii_digit()) => {
                    if s.starts_with('-') {
                        i64::MIN
                    } else {
                        i64::MAX
                    }
                }
                Err(_) => return Err(self.err(*span, format!("invalid priority {s}"))),
            };
            if v > MAX_POLICY_PRIORITY as i64 {
                return Err(self.err(
                    *span,
                    format!("invalid priority {v} > {MAX_POLICY_PRIORITY}"),
                ));
            }
            if v < MIN_POLICY_PRIORITY as i64 {
                return Err(self.err(
                    *span,
                    format!("invalid priority {v} > {MIN_POLICY_PRIORITY}"),
                ));
            }
            out.priority = v as i32;
        }
        Ok(out)
    }

    fn rule(&mut self, prof: &mut Profile, prefix: Prefix, rule: &ast::Rule, span: Span) -> R<()> {
        use ast::Rule as A;
        match rule {
            A::FileAll => {
                let base = (BASE_PERMS & !EXEC_TYPE) | (EXEC_INHERIT | MAY_EXEC);
                let perms = base | (base << OTHER_SHIFT);
                let mut e = Entry::new(b"/{**,}".to_vec(), perms, None, span);
                entry_add_prefix(&mut e, &prefix).map_err(|m| self.err(span, m))?;
                prof.add_entry(e);
            }
            A::File {
                exec_mode,
                path,
                perms,
                perms_first,
                subset,
                target,
                ..
            } => {
                let p = parse_perms(perms).map_err(|m| self.err(span, m))?;
                let mut e = if *perms_first {
                    if *subset && p & !LINK_BITS != 0 {
                        return Err(self.err(span, "subset can only be used with link rules."));
                    }
                    if target.is_some() && p & LINK_BITS != 0 && p & EXEC_BITS != 0 {
                        return Err(
                            self.err(span, "link and exec perms conflict on a file rule using ->")
                        );
                    }
                    if let Some(t) = target {
                        if label_contains_ns(t) && p & LINK_BITS != 0 {
                            return Err(self.err(
                                span,
                                "link perms are not allowed on a named profile transition.",
                            ));
                        }
                    }
                    if p & LINK_BITS != 0 {
                        let mut e = Entry::new(path.clone(), p, target.clone(), span);
                        e.subset = *subset;
                        e
                    } else {
                        let mut e = Entry::new(path.clone(), p, None, span);
                        e.nt_name = target.clone();
                        e
                    }
                } else if target.is_some() && p & LINK_BITS != 0 && p & EXEC_BITS == 0 {
                    Entry::new(path.clone(), p, target.clone(), span)
                } else {
                    if target.is_some() && p & LINK_BITS != 0 {
                        self.warn(
                            span,
                            "ambiguous rule specifies both link target and exec transition target. Using as exec transition",
                        );
                    }
                    let mut e = Entry::new(path.clone(), p, None, span);
                    e.nt_name = target.clone();
                    e
                };
                match exec_mode {
                    ExecMode::Empty => {}
                    m => {
                        if e.perms & EXEC_BITS == 0 {
                            return Err(self.err(span, "unsafe rule missing exec permissions"));
                        }
                        if *m == ExecMode::Unsafe {
                            e.perms |= ((e.perms & EXEC_BITS) << 8) & ALL_EXEC_UNSAFE;
                        } else {
                            e.perms &= !ALL_EXEC_UNSAFE;
                        }
                    }
                }
                entry_add_prefix(&mut e, &prefix).map_err(|m| self.err(span, m))?;
                prof.add_entry(e);
            }
            A::Link { subset, from, to } => {
                let mut e = Entry::new(from.clone(), LINK_BITS, Some(to.clone()), span);
                e.subset = *subset;
                entry_add_prefix(&mut e, &prefix).map_err(|m| self.err(span, m))?;
                prof.add_entry(e);
            }
            A::ChangeProfile {
                exec_mode,
                exec,
                target,
            } => {
                let mut perms = CHANGE_PROFILE;
                if exec.is_some() {
                    perms |= EXEC_BITS;
                    if *exec_mode == ExecMode::Unsafe {
                        perms |= ALL_EXEC_UNSAFE;
                    }
                } else if *exec_mode != ExecMode::Empty {
                    return Err(self.err(
                        span,
                        "Exec condition is required when unsafe or safe keywords are present",
                    ));
                }
                if let Some(x) = exec {
                    if !(x.first() == Some(&b'/') || x.starts_with(b"@{")) {
                        return Err(self.err(span, "Exec condition must begin with '/'."));
                    }
                }
                let target = target.clone().unwrap_or_else(|| b"**".to_vec());
                let mut e = Entry::new(target, perms, exec.clone(), span);
                if prefix.owner != Owner::Unspecified {
                    return Err(self.err(span, "owner conditional not allowed on unix rules"));
                }
                if prefix.mode == RuleMode::Deny && prefix.audit == Audit::Force {
                    e.mode = RuleMode::Deny;
                } else if prefix.mode == RuleMode::Deny {
                    e.mode = RuleMode::Deny;
                    e.audit = Audit::Force;
                } else if prefix.audit != Audit::Unspecified {
                    e.audit = prefix.audit;
                }
                prof.add_entry(e);
            }
            A::Capability { names } => {
                if prefix.owner != Owner::Unspecified {
                    return Err(self.err(span, "owner conditional not allowed on capability rules"));
                }
                let mut set = 0u64;
                for (n, nspan) in names {
                    let Some(cap) = self.capability(n) else {
                        return Err(self.err(
                            *nspan,
                            format!("Invalid capability {}.", String::from_utf8_lossy(n)),
                        ));
                    };
                    set |= 1u64 << cap;
                }
                if set == 0 {
                    set = u64::MAX;
                }
                if prefix.mode == RuleMode::Deny && prefix.audit == Audit::Force {
                    prof.caps.deny |= set;
                } else if prefix.mode == RuleMode::Deny {
                    prof.caps.deny |= set;
                    prof.caps.quiet |= set;
                } else {
                    prof.caps.allow |= set;
                    if prefix.audit != Audit::Unspecified {
                        prof.caps.audit |= set;
                    }
                }
            }
            A::All if prefix.priority != 0 => {
                return Err(self.err(span, "priority prefix not allowed on all rules"));
            }
            A::All if prefix.owner != Owner::Unspecified => {
                return Err(self.err(span, "owner prefix not allowed on all rules"));
            }
            A::All => prof.rules.push(PolicyRule::All { prefix, span }),
            A::Signal { perms, conds } => {
                let r = class::signal::Signal::new(perms, conds, prefix)
                    .map_err(|m| self.err(span, m))?;
                push_class(prof, ClassRule::Signal(r), span);
            }
            A::Ptrace { perms, conds } => {
                let r = class::ptrace::Ptrace::new(perms, conds, prefix)
                    .map_err(|m| self.err(span, m))?;
                push_class(prof, ClassRule::Ptrace(r), span);
            }
            A::Userns { perms, conds } => {
                let r = class::userns::Userns::new(perms, conds, prefix)
                    .map_err(|m| self.err(span, m))?;
                push_class(prof, ClassRule::Userns(r), span);
            }
            A::Dbus { perms, conds, peer } => {
                let r = class::dbus::Dbus::new(perms, conds, peer, prefix)
                    .map_err(|m| self.err(span, m))?;
                push_class(prof, ClassRule::Dbus(r), span);
            }
            A::Mqueue { perms, conds, name } => {
                let r = class::mqueue::Mqueue::new(perms, conds, name, prefix)
                    .map_err(|m| self.err(span, m))?;
                push_class(prof, ClassRule::Mqueue(r), span);
            }
            A::IoUring { perms, conds, list } => {
                let r = class::io_uring::IoUring::new(perms, conds, list, prefix)
                    .map_err(|m| self.err(span, m))?;
                push_class(prof, ClassRule::IoUring(r), span);
            }
            A::Unix { perms, conds, peer } => {
                let r = class::unix::Unix::new(perms, conds, peer, prefix)
                    .map_err(|m| self.err(span, m))?;
                push_class(prof, ClassRule::Unix(r), span);
            }
            A::Network {
                perms,
                words,
                conds,
                peer,
            } => {
                let r = class::network::Network::new(perms, words, conds, peer, prefix)
                    .map_err(|m| self.err(span, m))?;
                if !(self.both("network_v8") || self.both("network_v9")) {
                    r.update_compat(&mut self.net);
                }
                // upstream's grammar adds a unix rule for every AF_UNIX
                // entry, with the prefix's audit and mode as written.
                for t in r.unix_types() {
                    let u = class::unix::Unix::implied(t, prefix.audit, prefix.mode)
                        .map_err(|m| self.err(span, m))?;
                    push_class(prof, ClassRule::Unix(u), span);
                }
                push_class(prof, ClassRule::Network(r), span);
            }
            A::Mount {
                kind,
                conds,
                source,
                dest,
                transition,
            } => {
                let r = class::mount::Mount::new(*kind, conds, source, dest, transition, prefix)
                    .map_err(|m| self.err(span, m))?;
                push_class(prof, ClassRule::Mount(r), span);
            }
        }
        Ok(())
    }

    fn rlimit(
        &mut self,
        prof: &mut Profile,
        resource: &[u8],
        value: &[u8],
        unit: Option<&[u8]>,
        span: Span,
    ) -> R<()> {
        let name = String::from_utf8_lossy(resource).into_owned();
        let vtext = String::from_utf8_lossy(value).into_owned();
        let utext = unit
            .map(|u| String::from_utf8_lossy(u).into_owned())
            .unwrap_or_default();
        let Some(limit) = tables::rlimit(resource) else {
            return Err(self.err(span, format!("INVALID RLIMIT '{name}'")));
        };
        let invalid = || format!("RLIMIT '{name}' invalid value {vtext} {utext}");
        let v: u64 = if value == b"infinity" {
            u64::MAX
        } else {
            let (n, _, _) = super::eval::strtol0(value);
            let parsed = !value.is_empty();
            match limit {
                tables::RLIMIT_CPU => {
                    if !parsed || n < 0 {
                        return Err(self.err(span, invalid()));
                    }
                    let t = time_units(n, 1_000_000, unit);
                    if t == -1 {
                        return Err(self.err(
                            span,
                            format!("RLIMIT '{name} {vtext}' < minimum value of 1s"),
                        ));
                    }
                    if t < 0 {
                        return Err(self.err(span, invalid()));
                    }
                    if unit.is_none() {
                        self.warn(
                            span,
                            "RLIMIT 'cpu' no units specified using default units of seconds",
                        );
                    }
                    t as u64
                }
                tables::RLIMIT_RTTIME => {
                    if !parsed || n < 0 {
                        return Err(self.err(span, invalid()));
                    }
                    let t = time_units(n, 1, unit);
                    if t < 0 {
                        return Err(self.err(span, invalid()));
                    }
                    t as u64
                }
                tables::RLIMIT_NOFILE
                | tables::RLIMIT_NPROC
                | tables::RLIMIT_LOCKS
                | tables::RLIMIT_SIGPENDING
                | tables::RLIMIT_RTPRIO => {
                    if !parsed || unit.is_some() || n < 0 {
                        return Err(self.err(span, invalid()));
                    }
                    n as u64
                }
                tables::RLIMIT_NICE => {
                    if !parsed || unit.is_some() {
                        return Err(self.err(span, invalid()));
                    }
                    if !(-20..=19).contains(&n) {
                        return Err(self.err(
                            span,
                            format!("RLIMIT '{name}' out of range (-20 .. 19) {n}"),
                        ));
                    }
                    (n + 20) as u64
                }
                _ => {
                    if !parsed || n < 0 {
                        return Err(self.err(span, invalid()));
                    }
                    let mult: i64 = match unit {
                        None => 1,
                        Some(u) if !u.is_empty() && b"KB".starts_with(u) => 1024,
                        Some(u) if !u.is_empty() && b"MB".starts_with(u) => 1024 * 1024,
                        Some(u) if !u.is_empty() && b"GB".starts_with(u) => 1024 * 1024 * 1024,
                        Some(_) => return Err(self.err(span, invalid())),
                    };
                    n.wrapping_mul(mult) as u64
                }
            }
        };
        prof.rlimits.specified |= 1 << limit;
        prof.rlimits.limits[limit as usize] = v;
        Ok(())
    }
}

/// Upstream's convert_time_units: without a unit the value stays as
/// given; with one it is scaled from microseconds to `base`. -1 means
/// below one `base`, -2 an unknown unit.
fn time_units(value: i64, base: i64, unit: Option<&[u8]>) -> i64 {
    let Some(u) = unit else {
        return value;
    };
    let us: i64 = match u {
        b"us" | b"microsecond" | b"microseconds" => 1,
        b"ms" | b"millisecond" | b"milliseconds" => 1000,
        b"s" | b"sec" | b"second" | b"seconds" => 1_000_000,
        b"min" | b"minute" | b"minutes" => 60_000_000,
        b"h" | b"hour" | b"hours" => 3_600_000_000,
        b"d" | b"day" | b"days" => 86_400_000_000,
        b"week" | b"weeks" => 604_800_000_000,
        _ => return -2,
    };
    let total = value.wrapping_mul(us);
    if total < base {
        return -1;
    }
    total / base
}

/// Upstream's parse_label: an optional leading `&` for stacking, then
/// either a plain name or `:ns:name` / `:ns://name`.
/// Whether the label stacks, its namespace, and its name.
pub(crate) type Label = (bool, Option<Vec<u8>>, Vec<u8>);

pub(crate) fn parse_label(label: &[u8]) -> Result<Label, String> {
    let (stack, l) = match label.first() {
        Some(b'&') => (true, &label[1..]),
        _ => (false, label),
    };
    if l.first() != Some(&b':') {
        if l.is_empty() {
            return Err("Empty named transition profile name: %s".into());
        }
        return Ok((stack, None, l.to_vec()));
    }
    let rest = &l[1..];
    let Some(end) = rest.iter().position(|&c| c == b':') else {
        return Err("Namespace not terminated: %s".into());
    };
    let ns = &rest[..end];
    let mut name = &rest[end + 1..];
    if name.starts_with(b"//") {
        name = &name[2..];
    }
    if ns.is_empty() {
        return Err("Empty namespace: %s".into());
    }
    if name.is_empty() {
        return Err("Empty named transition profile name: %s".into());
    }
    Ok((stack, Some(ns.to_vec()), name.to_vec()))
}

pub(crate) fn label_contains_ns(label: &[u8]) -> bool {
    matches!(parse_label(label), Ok((_, Some(_), _)))
}

/// A permission string such as `rwix` as a mask for both the owner and
/// everyone else.
pub(crate) fn parse_perms(s: &[u8]) -> Result<u32, String> {
    let p = parse_sub_perms(s)?;
    let perms = shift(p, USER_SHIFT) | shift(p, OTHER_SHIFT);
    Ok(perms)
}

fn diff_qual(perms: u32, q: u32) -> bool {
    perms & MAY_EXEC != 0 && (perms & EXEC_TYPE) != (q & EXEC_TYPE)
}

fn parse_sub_perms(s: &[u8]) -> Result<u32, String> {
    let mut perms = 0u32;
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        let next = s.get(i + 1).copied().unwrap_or(0);
        match c.to_ascii_lowercase() {
            b'r' => perms |= MAY_READ,
            b'w' => {
                if perms & MAY_APPEND != 0 && perms & MAY_WRITE == 0 {
                    return Err("Conflict 'a' and 'w' perms are mutually exclusive.".into());
                }
                perms |= MAY_WRITE | MAY_APPEND;
            }
            b'a' if c == b'a' => {
                if perms & MAY_WRITE != 0 {
                    return Err("Conflict 'a' and 'w' perms are mutually exclusive.".into());
                }
                perms |= MAY_APPEND;
            }
            b'l' => perms |= OLD_MAY_LINK,
            b'k' if c == b'k' => perms |= OLD_MAY_LOCK,
            b'i' => {
                if perms & EXEC_MODIFIERS != 0 {
                    return Err(
                        "Exec qualifier 'i' invalid, conflicting qualifier already specified"
                            .into(),
                    );
                }
                perms |= EXEC_INHERIT | MAY_EXEC;
                i += 1;
            }
            // Lowercase u, p and c keep the environment (unsafe), the
            // uppercase forms scrub it.
            b'u' => {
                let mut t = EXEC_UNCONFINED | MAY_EXEC;
                if c == b'u' {
                    t |= EXEC_UNSAFE;
                }
                if diff_qual(perms, t) {
                    return Err(format!(
                        "Exec qualifier '{}' invalid, conflicting qualifier already specified",
                        c as char
                    ));
                }
                perms |= t;
                i += 1;
            }
            b'p' | b'c' => {
                let mut t = if c.is_ascii_lowercase() {
                    EXEC_UNSAFE
                } else {
                    0
                };
                t |= if c.eq_ignore_ascii_case(&b'p') {
                    EXEC_PROFILE | MAY_EXEC
                } else {
                    EXEC_LOCAL | MAY_EXEC
                };
                match next.to_ascii_lowercase() {
                    b'i' => {
                        t |= EXEC_INHERIT;
                        if diff_qual(perms, t) {
                            return Err(format!(
                                "Exec qualifier '{}{}' invalid, conflicting qualifier already specified",
                                c as char, next as char
                            ));
                        }
                        perms |= t;
                        i += 2;
                    }
                    b'u' => {
                        t |= EXEC_PUX;
                        if diff_qual(perms, t) {
                            return Err(format!(
                                "Exec qualifier '{}{}' invalid, conflicting qualifier already specified",
                                c as char, next as char
                            ));
                        }
                        perms |= t;
                        i += 2;
                    }
                    _ => {
                        if diff_qual(perms, t) {
                            return Err(format!(
                                "Exec qualifier '{}' invalid, conflicting qualifier already specified",
                                c as char
                            ));
                        }
                        perms |= t;
                        i += 1;
                    }
                }
            }
            b'm' => perms |= OLD_EXEC_MMAP,
            b'x' => perms |= MAY_EXEC,
            _ => {
                return Err(format!(
                    "Internal: unexpected perms character '{}' in input",
                    c as char
                ))
            }
        }
        i += 1;
    }
    Ok(perms)
}

/// Upstream's check_x_qualifier: in deny rules exec takes no qualifier,
/// elsewhere it must have one.
fn check_x_qualifier(e: &Entry) -> Result<(), String> {
    if e.perms & EXEC_BITS != 0 {
        if e.mode == RuleMode::Deny && e.perms & ALL_EXEC_TYPE != 0 {
            return Err("Invalid perms, in deny rules 'x' must not be preceded by exec qualifier 'i', 'p', or 'u'".into());
        } else if e.mode != RuleMode::Deny && e.perms & ALL_EXEC_TYPE == 0 {
            return Err(
                "Invalid perms, 'x' must be preceded by exec qualifier 'i', 'p', or 'u'".into(),
            );
        }
    }
    Ok(())
}

/// Applies a prefix to a file entry the way upstream does: the mode is
/// replaced, owner and other mask the permissions, and a deny without
/// audit is quiet.
/// The prefix a non-file rule keeps once upstream's add_prefix has
/// applied it: `deny` alone turns into a forced audit, which for a deny
/// rule means quiet, and `audit deny` loses its audit.
pub(crate) fn rule_prefix(p: &Prefix) -> Prefix {
    let audit = match (p.mode, p.audit) {
        (RuleMode::Deny, Audit::Force) => Audit::Unspecified,
        (RuleMode::Deny, _) => Audit::Force,
        (_, a) => a,
    };
    Prefix { audit, ..*p }
}

pub(crate) fn entry_add_prefix(e: &mut Entry, p: &Prefix) -> Result<(), String> {
    e.mode = p.mode;
    match p.owner {
        Owner::Owner => e.perms &= USER_PERMS | SHARED_PERMS,
        Owner::Other => e.perms &= OTHER_PERMS | SHARED_PERMS,
        Owner::Unspecified => {}
    }
    e.priority = p.priority;
    let deny = e.mode == RuleMode::Deny;
    if (p.audit == Audit::Force) != deny {
        e.audit = Audit::Force;
    }
    check_x_qualifier(e)
}

/// What to do with a block's profile once its items are built.
enum Done<'a> {
    Profile(&'a ast::Profile, bool),
    Block(Prefix),
    /// The `then` branch of a condition, and whether the condition held.
    Then(&'a ast::If, bool),
    /// The `else` block, with the condition and its `then` branch.
    Else(bool, Box<Profile>),
}

enum Frame<'a> {
    Body {
        items: std::slice::Iter<'a, Item>,
        prof: Box<Profile>,
        done: Done<'a>,
    },
    /// A condition whose `then` branch is built, waiting for the chain
    /// of `else if` after it to choose.
    Cond { truth: bool, then: Box<Profile> },
}

impl<'a> Frame<'a> {
    fn body(items: &'a [Item], span: Span, done: Done<'a>) -> Frame<'a> {
        Frame::Body {
            items: items.iter(),
            prof: boxed_empty(span),
            done,
        }
    }
}

fn push_class(prof: &mut Profile, rule: ClassRule, span: Span) {
    prof.rules.push(PolicyRule::Class {
        rule: Box::new(rule),
        span,
    });
}

fn boxed_empty(span: Span) -> Box<Profile> {
    Box::new(Profile::empty(span))
}

fn add_hat(prof: &mut Profile, hat: Box<Profile>) -> Result<(), String> {
    let key = (hat.ns.clone(), hat.name.clone());
    if prof.hats.contains_key(&key) {
        return Err(format!(
            "Multiple definitions for hat {} in profile {} exist",
            String::from_utf8_lossy(&hat.name),
            String::from_utf8_lossy(&prof.name)
        ));
    }
    prof.hats.insert(key, hat);
    Ok(())
}

fn add_proc_access(prof: &mut Profile, rule: &[u8]) {
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
    prof.add_entry(Entry::new(rule.to_vec(), MAY_WRITE, None, span));
}

/// C's strncmp(a, b, n) == 0 for strings without NUL bytes.
fn strncmp_eq(a: &[u8], b: &[u8], n: usize) -> bool {
    for i in 0..n {
        let (x, y) = (
            a.get(i).copied().unwrap_or(0),
            b.get(i).copied().unwrap_or(0),
        );
        if x != y {
            return false;
        }
        if x == 0 {
            return true;
        }
    }
    true
}

/// Moves a named transition into the profile's exec table and returns
/// its index, or 0 when the table is full. A transition to a child
/// profile of the same name needs no entry.
fn add_named_transition(prof: &mut Profile, i: usize) -> u32 {
    let e = &mut prof.entries[i];
    let nt = e.nt_name.take().expect("named transition");
    let name = if !label_contains_ns(&nt) {
        let sub = nt.windows(2).position(|w| w == b"//");
        // Upstream compares the profile name with the text from the "//"
        // on, not with the part before it; kept, since it decides which
        // rules count as local.
        if let Some(pos) = sub {
            if !strncmp_eq(&prof.name, &nt[pos..], pos) && nt[pos + 2..] == e.name[..] {
                return EXEC_LOCAL >> 10;
            }
        }
        if (e.perms & USER_EXEC_MODIFIERS) == shift(EXEC_LOCAL, USER_SHIFT)
            || (e.perms & OTHER_EXEC_MODIFIERS) == shift(EXEC_LOCAL, OTHER_SHIFT)
        {
            if nt == e.name {
                return EXEC_LOCAL >> 10;
            }
            let mut n = prof.name.clone();
            n.extend_from_slice(b"//");
            n.extend_from_slice(&nt);
            n
        } else {
            nt
        }
    } else {
        nt
    };
    let first = (EXEC_LOCAL >> 10) as usize + 1;
    for idx in first..EXEC_COUNT {
        match &prof.exec_table[idx] {
            None => {
                prof.exec_table[idx] = Some(name);
                return idx as u32;
            }
            Some(existing) if *existing == name => return idx as u32,
            Some(_) => {}
        }
    }
    0
}

fn flag(s: &[u8]) -> Result<Flags, String> {
    let mut f = Flags::default();
    use path_flag::*;
    if s == b"debug" {
        f.flags |= FLAG_DEBUG1;
    } else if let Some(m) = Mode::from_name(s) {
        f.mode = m;
    } else if s == b"audit" {
        f.audit = true;
    } else if s == b"chroot_relative" {
        f.path |= CHROOT_REL;
    } else if s == b"namespace_relative" {
        f.path |= NS_REL;
    } else if s == b"mediate_deleted" {
        f.path |= MEDIATE_DELETED;
    } else if s == b"delegate_deleted" {
        f.path |= DELEGATE_DELETED;
    } else if s == b"attach_disconnected" {
        f.path |= ATTACH;
    } else if s == b"no_attach_disconnected" {
        f.path |= NO_ATTACH;
    } else if s == b"chroot_attach" {
        f.path |= CHROOT_NSATTACH;
    } else if s == b"chroot_no_attach" {
        f.path |= CHROOT_NO_ATTACH;
    } else if let Some(p) = s.strip_prefix(b"attach_disconnected.path=") {
        f.path |= ATTACH;
        f.disconnected_path = Some(p.to_vec());
    } else if let Some(sig) = s.strip_prefix(b"kill.signal=") {
        f.signal = tables::signal(sig).ok_or_else(|| {
            format!(
                "unknown signal specified for kill.signal='{}'",
                String::from_utf8_lossy(sig)
            )
        })?;
    } else if let Some(e) = s.strip_prefix(b"error=") {
        f.error = tables::errno(e).ok_or_else(|| {
            format!(
                "unknown error code specified for error='{}'",
                String::from_utf8_lossy(e)
            )
        })?;
    } else if s == b"interruptible" {
        f.flags |= FLAG_INTERRUPTIBLE;
    } else if s == b"attach_disconnected.ipc" {
        f.path |= IPC_ATTACH;
    } else if let Some(p) = s.strip_prefix(b"attach_disconnected.ipc=") {
        f.path |= IPC_ATTACH;
        f.disconnected_ipc = Some(p.to_vec());
    } else {
        return Err(format!(
            "Invalid profile flag: {}.",
            String::from_utf8_lossy(s)
        ));
    }
    Ok(f)
}

fn merge_mode(l: Mode, r: Mode) -> Option<Mode> {
    if l == r || r == Mode::Unspecified {
        Some(l)
    } else if l == Mode::Unspecified {
        Some(r)
    } else {
        None
    }
}

fn merge_flags(a: &mut Flags, b: Flags) -> Result<(), String> {
    use path_flag::*;
    let Some(m) = merge_mode(a.mode, b.mode) else {
        return Err(format!(
            "Profile flag '{}' conflicts with '{}'",
            a.mode.name(),
            b.mode.name()
        ));
    };
    // Upstream's merge leaves `flags` (debug, interruptible) alone, so
    // only the first flag in the list can set them.
    a.mode = m;
    a.audit |= b.audit;
    a.path |= b.path;
    let both = |x: u32| a.path & x == x;
    if both(CHROOT_REL | NS_REL) {
        return Err("Profile flag chroot_relative conflicts with namespace_relative".into());
    }
    if both(MEDIATE_DELETED | DELEGATE_DELETED) {
        return Err("Profile flag mediate_deleted conflicts with delegate_deleted".into());
    }
    if both(ATTACH | NO_ATTACH) {
        return Err(
            "Profile flag attach_disconnected conflicts with no_attach_disconnected".into(),
        );
    }
    if both(IPC_ATTACH | NO_ATTACH) {
        return Err(
            "Profile flag attach_disconnected.ipc conflicts with no_attach_disconnected".into(),
        );
    }
    if both(CHROOT_NSATTACH | CHROOT_NO_ATTACH) {
        return Err("Profile flag chroot_attach conflicts with chroot_no_attach".into());
    }
    for (mine, theirs) in [
        (&mut a.disconnected_path, b.disconnected_path),
        (&mut a.disconnected_ipc, b.disconnected_ipc),
    ] {
        if let Some(t) = theirs {
            match mine {
                Some(m) if *m != t => {
                    return Err(format!(
                        "Profile flag attach_disconnected set to conflicting values: '{}' and '{}'",
                        String::from_utf8_lossy(m),
                        String::from_utf8_lossy(&t)
                    ))
                }
                Some(_) => {}
                None => *mine = Some(t),
            }
        }
    }
    if b.signal != 0 {
        if a.signal != 0 && a.signal != b.signal {
            return Err(format!(
                "Profile flag kill.signal set to conflicting values: '{}' and '{}'",
                a.signal, b.signal
            ));
        }
        a.signal = b.signal;
    }
    if b.error != 0 {
        if a.error != 0 && a.error != b.error {
            return Err("Profile flag error set to conflicting values".into());
        }
        a.error = b.error;
    }
    Ok(())
}
