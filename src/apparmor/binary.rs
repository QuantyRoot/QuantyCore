//! The binary policy the kernel loads: a stream of typed values per
//! profile (Linux's security/apparmor/policy_unpack.c reads it), with
//! each automaton as a set of flex style tables (match.c runs them).
//!
//! The layout of every value is upstream's parser_interface.c. The
//! tables are packed differently: upstream compresses the transitions
//! without byte classes and with difference encoding; here every
//! automaton carries its byte classes in an equivalence table, which the
//! kernel has always accepted, and each state keeps one default target.
//! The kernel matches both the same way.

use super::compile::dfa::{Dfa, Perms, DEAD, START};
use super::compile::kperms::AaPerms;
use super::compile::Support;
use super::model::{path_flag, Mode, Policy, Profile, FLAG_INTERRUPTIBLE};

const SD_U16: u8 = 1;
const SD_U32: u8 = 2;
const SD_U64: u8 = 3;
const SD_NAME: u8 = 4;
const SD_STRING: u8 = 5;
const SD_BLOB: u8 = 6;
const SD_STRUCT: u8 = 7;
const SD_STRUCTEND: u8 = 8;
const SD_ARRAY: u8 = 11;
const SD_ARRAYEND: u8 = 12;

const YYTH_MAGIC: u32 = 0x1B5E_783D;
const YYTH_FLAG_OOB_TRANS: u16 = 2;
const YYTD_ACCEPT: u16 = 1;
const YYTD_BASE: u16 = 2;
const YYTD_CHK: u16 = 3;
const YYTD_DEF: u16 = 4;
const YYTD_EC: u16 = 5;
const YYTD_ACCEPT2: u16 = 7;
const YYTD_NXT: u16 = 8;
const MATCH_FLAG_OOB_TRANSITION: u32 = 0x2000_0000;

/// upstream's 16 bit state tables: an automaton with this many states
/// or more is refused, as upstream refuses it.
pub const MAX_STATES: usize = (1 << 16) - 1;

/// upstream's policy_version and parser_abi_version.
const POLICY_VERSION: u32 = 2;
const PARSER_ABI_VERSION: u32 = 2;

#[derive(Default)]
struct W {
    b: Vec<u8>,
    /// The first value the format cannot hold. Upstream truncates
    /// lengths to 16 bits and cuts strings at a NUL; a policy written that
    /// way names something other than the profile meant, so it is refused.
    err: Option<String>,
}

impl W {
    fn name(&mut self, n: Option<&str>) {
        if let Some(n) = n {
            self.b.push(SD_NAME);
            self.b
                .extend_from_slice(&((n.len() + 1) as u16).to_le_bytes());
            self.b.extend_from_slice(n.as_bytes());
            self.b.push(0);
        }
    }

    fn u16(&mut self, v: u16) {
        self.b.push(SD_U16);
        self.b.extend_from_slice(&v.to_le_bytes());
    }

    fn u32(&mut self, v: u32) {
        self.b.push(SD_U32);
        self.b.extend_from_slice(&v.to_le_bytes());
    }

    fn u64(&mut self, v: u64) {
        self.b.push(SD_U64);
        self.b.extend_from_slice(&v.to_le_bytes());
    }

    fn named_u32(&mut self, n: &str, v: u32) {
        self.name(Some(n));
        self.u32(v);
    }

    /// A string of `s` and a NUL, as upstream's sd_write_strn writes it.
    fn strn(&mut self, s: &[u8], n: Option<&str>) {
        self.name(n);
        if s.len() >= u16::MAX as usize {
            self.fail(format!("a string of {} bytes is too long to load", s.len()));
        }
        self.b.push(SD_STRING);
        self.b
            .extend_from_slice(&((s.len() + 1) as u16).to_le_bytes());
        self.b.extend_from_slice(s);
        self.b.push(0);
    }

    /// A name from the profile, which the kernel reads up to its NUL.
    fn text(&mut self, s: &[u8], n: Option<&str>) {
        self.no_nul(s);
        self.strn(s, n);
    }

    fn no_nul(&mut self, s: &[u8]) {
        if s.contains(&0) {
            self.fail(format!(
                "{} contains a NUL byte",
                String::from_utf8_lossy(s).replace('\0', "\\000")
            ));
        }
    }

    fn structure(&mut self, n: &str) {
        self.name(Some(n));
        self.b.push(SD_STRUCT);
    }

    fn structend(&mut self) {
        self.b.push(SD_STRUCTEND);
    }

    fn array(&mut self, n: Option<&str>, size: usize) {
        self.name(n);
        if size > u16::MAX as usize {
            self.fail(format!("{size} entries are too many for one array"));
        }
        self.b.push(SD_ARRAY);
        self.b.extend_from_slice(&(size as u16).to_le_bytes());
    }

    fn fail(&mut self, m: String) {
        self.err.get_or_insert(m);
    }

    fn arrayend(&mut self) {
        self.b.push(SD_ARRAYEND);
    }

    /// A blob aligned to 8 bytes in the stream, padded at its start, as
    /// upstream's sd_write_aligned_blob writes it.
    fn aligned_blob(&mut self, data: &[u8], n: &str) {
        self.name(Some(n));
        let pad = (self.b.len() + 5).next_multiple_of(8) - (self.b.len() + 5);
        self.b.push(SD_BLOB);
        self.b
            .extend_from_slice(&((data.len() + pad) as u32).to_le_bytes());
        self.b.extend(std::iter::repeat_n(0u8, pad));
        self.b.extend_from_slice(data);
    }
}

/// The transitions of an automaton, compressed into the kernel's base,
/// default, next and check tables.
struct Packed {
    base: Vec<u32>,
    def: Vec<u32>,
    next: Vec<u32>,
    check: Vec<u32>,
    oob: bool,
}

fn pack(d: &Dfa) -> Result<Packed, String> {
    let n = d.states();
    let cols = d.nclasses;
    let mut base = vec![0u32; n];
    let mut def = vec![0u32; n];
    let mut next: Vec<u32> = Vec::new();
    let mut check: Vec<u32> = Vec::new();
    let mut used: Vec<bool> = Vec::new();
    let mut first_free = 1usize;
    let mut oob_any = false;
    let mut counts: std::collections::HashMap<u32, usize> = std::collections::HashMap::new();
    for s in 0..n {
        let row = &d.trans[s * d.columns()..(s + 1) * d.columns()];
        counts.clear();
        for &t in &row[..cols] {
            *counts.entry(t).or_insert(0) += 1;
        }
        // The most common target becomes the default; a tie keeps the
        // lowest state, so the dead state wins one.
        let mut dflt = DEAD;
        let mut best = 0;
        let mut keys: Vec<(&u32, &usize)> = counts.iter().collect();
        keys.sort();
        for (&t, &c) in keys {
            if c > best {
                best = c;
                dflt = t;
            }
        }
        def[s] = dflt;
        // Entries as (offset from base, target); the out of band symbol
        // sits one below the base.
        let mut entries: Vec<(isize, u32)> = Vec::new();
        let oob_target = if d.has_oob { row[cols] } else { DEAD };
        if oob_target != DEAD {
            oob_any = true;
            base[s] |= MATCH_FLAG_OOB_TRANSITION;
            if oob_target != dflt {
                entries.push((-1, oob_target));
            }
        }
        for (c, &t) in row[..cols].iter().enumerate() {
            if t != dflt {
                entries.push((c as isize, t));
            }
        }
        if entries.is_empty() {
            continue;
        }
        let min_off = entries.iter().map(|e| e.0).min().unwrap_or(0);
        let mut b = first_free.max((-min_off).max(0) as usize).max(1);
        loop {
            let fits = entries.iter().all(|&(o, _)| {
                let p = (b as isize + o) as usize;
                p >= used.len() || !used[p]
            });
            if fits {
                break;
            }
            b += 1;
        }
        for &(o, t) in &entries {
            let p = (b as isize + o) as usize;
            if p >= used.len() {
                used.resize(p + 1, false);
                next.resize(p + 1, 0);
                check.resize(p + 1, 0);
            }
            used[p] = true;
            next[p] = t;
            check[p] = s as u32;
        }
        while first_free < used.len() && used[first_free] {
            first_free += 1;
        }
        // The base shares its word with the flags in the top byte.
        if b >= 1 << 24 {
            return Err("transition table too large for the kernel".into());
        }
        base[s] |= b as u32;
    }
    // The kernel reads up to 255 entries past every base, byte classes
    // or not.
    let max_base = base
        .iter()
        .map(|b| (b & 0x00ff_ffff) as usize)
        .max()
        .unwrap_or(0);
    let len = (max_base + 256).max(next.len());
    next.resize(len, 0);
    check.resize(len, 0);
    Ok(Packed {
        base,
        def,
        next,
        check,
        oob: oob_any,
    })
}

fn table(out: &mut Vec<u8>, id: u16, width: usize, vals: impl Iterator<Item = u32>) {
    let start = out.len();
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&(width as u16).to_be_bytes());
    out.extend_from_slice(&0u32.to_be_bytes());
    let len_at = out.len();
    out.extend_from_slice(&0u32.to_be_bytes());
    let mut count = 0u32;
    for v in vals {
        match width {
            1 => out.push(v as u8),
            2 => out.extend_from_slice(&(v as u16).to_be_bytes()),
            _ => out.extend_from_slice(&v.to_be_bytes()),
        }
        count += 1;
    }
    out[len_at..len_at + 4].copy_from_slice(&count.to_be_bytes());
    let size = out.len() - start;
    out.resize(start + size.next_multiple_of(8), 0);
}

/// How the kernel takes permissions for this automaton.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Accept {
    /// Allow mask and packed audit and quiet in the accept tables.
    Masks,
    /// An index into a permissions table; with `owner`, a second
    /// accept table carries the owner flag of the file automaton.
    Table { file: bool, owner: bool },
}

/// One automaton's tables, and its permissions table if it has one.
fn dfa_blob(d: &Dfa, accept: Accept) -> Result<(Vec<u8>, Vec<AaPerms>), String> {
    if d.states() >= MAX_STATES {
        return Err(format!("Too many states ({}) for type state_t", d.states()));
    }
    let p = pack(d)?;
    let n = d.states();
    let mut accept1 = vec![0u32; n];
    let mut accept2: Vec<u32> = Vec::new();
    let mut perms_table: Vec<AaPerms> = Vec::new();
    match accept {
        Accept::Masks => {
            accept2 = vec![0u32; n];
            for s in 0..n {
                let (a1, a2) = d.perms[s].accept_pair();
                accept1[s] = a1;
                accept2[s] = a2;
            }
        }
        Accept::Table { file, owner } => {
            if owner {
                accept2 = vec![0u32; n];
            }
            let mut index: std::collections::HashMap<Perms, u32> = std::collections::HashMap::new();
            let entries = |p: &Perms| -> Vec<AaPerms> {
                if file {
                    p.file_entries().to_vec()
                } else {
                    vec![p.policy_entry()]
                }
            };
            // The first entry is the dead state's; the start state
            // points at it too, whatever its permissions, as upstream's
            // does.
            perms_table.extend(entries(&d.perms[DEAD as usize]));
            index.insert(d.perms[DEAD as usize], 0);
            for s in 0..n {
                if s as u32 == DEAD || s as u32 == START {
                    continue;
                }
                let pm = d.perms[s];
                let i = match index.get(&pm) {
                    Some(&i) => i,
                    None => {
                        let i = perms_table.len() as u32;
                        perms_table.extend(entries(&pm));
                        index.insert(pm, i);
                        i
                    }
                };
                accept1[s] = i;
                if owner {
                    accept2[s] = 1;
                }
            }
        }
    }
    let mut tables = Vec::new();
    table(&mut tables, YYTD_ACCEPT, 4, accept1.iter().copied());
    if !accept2.is_empty() {
        table(&mut tables, YYTD_ACCEPT2, 4, accept2.iter().copied());
    }
    table(&mut tables, YYTD_EC, 1, d.class.iter().map(|&c| c as u32));
    table(&mut tables, YYTD_BASE, 4, p.base.iter().copied());
    table(&mut tables, YYTD_DEF, 2, p.def.iter().copied());
    table(&mut tables, YYTD_NXT, 2, p.next.iter().copied());
    table(&mut tables, YYTD_CHK, 2, p.check.iter().copied());
    let hsize = 24usize;
    let mut out = Vec::with_capacity(hsize + tables.len());
    out.extend_from_slice(&YYTH_MAGIC.to_be_bytes());
    out.extend_from_slice(&(hsize as u32).to_be_bytes());
    out.extend_from_slice(&((hsize + tables.len()) as u32).to_be_bytes());
    let flags = if p.oob { YYTH_FLAG_OOB_TRANS } else { 0 };
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(b"notflex\0");
    out.resize(hsize, 0);
    out.extend_from_slice(&tables);
    Ok((out, perms_table))
}

fn write_perms(w: &mut W, table: &[AaPerms], file: bool, s: &Support) {
    w.structure("perms");
    w.named_u32("version", 1);
    w.array(None, table.len());
    for p in table {
        for v in [
            0, p.allow, p.deny, p.subtree, p.cond, p.kill, p.complain, p.prompt, p.audit, p.quiet,
            p.hide, p.xindex, p.tag, p.label,
        ] {
            w.u32(v);
        }
    }
    w.arrayend();
    w.structend();
    if file && !table.is_empty() && s.permstable32_version >= 3 {
        w.named_u32("permsv", 3);
    }
}

/// upstream's sd_serialize_dfa. The attachment automaton never takes
/// a permissions table: upstream builds it for permissions table
/// version -1.
fn write_dfa(w: &mut W, d: &Dfa, file: bool, xmatch: bool, s: &Support) -> Result<(), String> {
    let accept = if s.permstable32_version >= 2 && !xmatch {
        Accept::Table {
            file,
            owner: file && s.permstable32_version >= 3,
        }
    } else {
        Accept::Masks
    };
    let (blob, table) = dfa_blob(d, accept)?;
    if accept != Accept::Masks && !table.is_empty() {
        write_perms(w, &table, file, s);
    }
    w.aligned_blob(&blob, "aadfa");
    Ok(())
}

/// upstream's sd_serialize_xtable: the named exec targets, from slot 4,
/// a namespace's separator turned into NUL.
fn write_xtable(w: &mut W, p: &Profile) {
    if p.exec_table[4].is_none() {
        return;
    }
    w.structure("xtable");
    let names: Vec<&Vec<u8>> = p.exec_table[4..].iter().flatten().collect();
    w.array(None, names.len());
    for n in names {
        w.no_nul(n);
        let mut v = n.clone();
        if v.first() == Some(&b':') {
            if let Some(i) = v[1..].iter().position(|&c| c == b':') {
                v[i + 1] = 0;
            }
        }
        // The NUL between namespace and name is the kernel's separator.
        w.strn(&v, None);
    }
    w.arrayend();
    w.structend();
}

fn mode_packed(m: Mode) -> u32 {
    let m = if m == Mode::DefaultAllow {
        Mode::Unconfined
    } else {
        m
    };
    (m as u32).saturating_sub(1)
}

/// Per family socket type masks for kernels without network rules in
/// the policy automaton: allow, audit, deny and quiet.
pub type NetTable = Vec<[u32; 4]>;

fn write_profile(
    w: &mut W,
    p: &Profile,
    name: &[u8],
    s: &Support,
    net: Option<&NetTable>,
) -> Result<(), String> {
    w.structure("profile");
    w.text(name, None);
    if let Some((x, len)) = &p.xmatch {
        write_dfa(w, x, false, true, s)?;
        w.u32(*len as u32);
    }
    if let Some(d) = &p.flags.disconnected_path {
        w.text(d, Some("disconnected"));
    }
    if let (Some(d), true) = (&p.flags.disconnected_ipc, s.flag_disconnected_ipc) {
        w.text(d, Some("disconnected_ipc"));
    }
    if p.flags.signal != 0 && s.flag_signal {
        w.named_u32("kill", p.flags.signal);
    }
    if p.flags.error != 0 && s.flag_error {
        w.named_u32("error", p.flags.error);
    }
    w.structure("flags");
    let mut flags = p.flags.flags;
    if !s.flag_interruptible {
        flags &= !FLAG_INTERRUPTIBLE;
    }
    w.u32(flags);
    w.u32(mode_packed(p.flags.mode));
    w.u32(u32::from(p.flags.audit));
    w.structend();
    if p.flags.path != 0 {
        let f = p.flags.path;
        let mut v = 0;
        if f & path_flag::CHROOT_REL != 0 {
            v |= 0x8;
        }
        if f & path_flag::MEDIATE_DELETED != 0 {
            v |= 0x10000;
        }
        if f & path_flag::ATTACH != 0 {
            v |= 0x4;
        }
        if f & path_flag::CHROOT_NSATTACH != 0 {
            v |= 0x10;
        }
        if f & path_flag::IPC_ATTACH != 0 {
            v |= 0x20;
        }
        w.named_u32("path_flags", v);
    }
    let allowed = p.caps.allow & !p.caps.deny;
    let quiet = p.caps.deny & p.caps.quiet;
    w.u32(allowed as u32);
    w.u32((allowed & p.caps.audit) as u32);
    w.u32(quiet as u32);
    w.u32(0);
    w.structure("caps64");
    w.u32((allowed >> 32) as u32);
    w.u32(((allowed & p.caps.audit) >> 32) as u32);
    w.u32((quiet >> 32) as u32);
    w.u32(0);
    w.structend();
    if s.identity_names {
        w.array(Some("identity"), p.identities.len());
        for id in &p.identities {
            w.text(id, None);
        }
        w.arrayend();
    }
    if let Some(x) = &p.xattrs {
        if !x.conds.is_empty() {
            w.structure("xattrs");
            w.array(None, x.conds.len());
            // upstream's list holds the conditions in reverse.
            for c in x.conds.iter().rev() {
                w.text(&c.name, None);
            }
            w.arrayend();
            w.structend();
        }
    }
    if p.rlimits.specified != 0 {
        w.structure("rlimits");
        w.u32(p.rlimits.specified);
        w.array(None, p.rlimits.limits.len());
        for l in p.rlimits.limits {
            w.u64(l);
        }
        w.arrayend();
        w.structend();
    }
    if !s.network_policydb() {
        if let (Some(t), true) = (net, s.network) {
            w.array(Some("net_allowed_af"), t.len());
            for e in t {
                let allowed = e[0] & !e[2];
                w.u16(allowed as u16);
                w.u16((allowed & e[1]) as u16);
                w.u16((e[2] & e[3]) as u16);
            }
            w.arrayend();
        }
    }
    if let Some(d) = &p.policydb {
        w.structure("policydb");
        write_dfa(w, d, false, false, s)?;
        if s.permstable32_version >= 2 {
            write_xtable(w, p);
        }
        w.structend();
    }
    if let Some(d) = &p.file_dfa {
        write_dfa(w, d, true, false, s)?;
        write_xtable(w, p);
    }
    w.structend();
    Ok(())
}

/// upstream's ENCODE_VERSION.
fn version(s: &Support) -> u32 {
    let k = s.abi_version;
    let mut v = k & 0x3ff;
    if k > 5 {
        v |= (PARSER_ABI_VERSION & 0xff) << 12;
        v |= (POLICY_VERSION & 0xff) << 20;
    }
    v
}

/// One loadable unit: a profile, or a hat flattened to `parent//hat`.
pub struct Unit {
    /// The profile's name as the kernel will know it.
    pub name: Vec<u8>,
    pub namespace: Option<Vec<u8>>,
    pub data: Vec<u8>,
}

fn units_of(
    p: &Profile,
    prefix: Option<&[u8]>,
    ns: &Option<Vec<u8>>,
    s: &Support,
    net: Option<&NetTable>,
    out: &mut Vec<Unit>,
) -> Result<(), String> {
    let mut name = Vec::new();
    if let Some(pre) = prefix {
        name.extend_from_slice(pre);
        name.extend_from_slice(b"//");
    }
    name.extend_from_slice(&p.name);
    let mut w = W::default();
    w.named_u32("version", version(s));
    if let Some(n) = ns {
        w.text(n, Some("namespace"));
    }
    write_profile(&mut w, p, &name, s, net)?;
    if let Some(e) = w.err {
        return Err(e);
    }
    out.push(Unit {
        name: name.clone(),
        namespace: ns.clone(),
        data: w.b,
    });
    let mut stack: Vec<(&Profile, Vec<u8>)> = p
        .hats
        .values()
        .rev()
        .map(|h| (&**h, name.clone()))
        .collect();
    while let Some((h, parent)) = stack.pop() {
        let mut hname = parent.clone();
        hname.extend_from_slice(b"//");
        hname.extend_from_slice(&h.name);
        let mut w = W::default();
        w.named_u32("version", version(s));
        if let Some(n) = &h.ns {
            w.text(n, Some("namespace"));
        }
        write_profile(&mut w, h, &hname, s, net)?;
        if let Some(e) = w.err {
            return Err(e);
        }
        out.push(Unit {
            name: hname.clone(),
            namespace: h.ns.clone(),
            data: w.b,
        });
        for hh in h.hats.values().rev() {
            stack.push((&**hh, hname.clone()));
        }
    }
    Ok(())
}

/// The policy as the kernel loads it: one unit per profile and per hat,
/// each written on its own, as upstream writes them.
pub fn serialize(policy: &Policy, s: &Support) -> Result<Vec<Unit>, String> {
    let mut out = Vec::new();
    for p in policy.profiles.values() {
        units_of(p, None, &p.ns, s, policy.net_table.as_ref(), &mut out)?;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use crate::apparmor::{compile, MemResolver, Options};

    fn written(text: &str) -> Result<usize, String> {
        let p = compile(
            &mut MemResolver::default(),
            "t",
            text.as_bytes().to_vec(),
            &Options::default(),
        )
        .map_err(|e| e.to_string())?;
        super::serialize(&p, &p.support).map(|u| u.len())
    }

    #[test]
    fn what_the_format_cannot_hold_is_refused() {
        assert_eq!(written("profile a { }"), Ok(1));
        let mut w = super::W::default();
        w.text(b"a\0b", None);
        assert!(w.err.unwrap().contains("NUL"));
        let long = format!("profile {} {{ }}", "n".repeat(70_000));
        assert!(written(&long).unwrap_err().contains("too long"));
        assert_eq!(written("/p { /x px -> :ns:b, }"), Ok(1));
    }
}
