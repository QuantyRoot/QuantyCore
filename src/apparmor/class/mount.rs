//! `mount`, `remount`, `umount` and `pivot_root` rules: upstream's
//! mount.cc and the grammar helpers that build them.

use super::{add_prefix, conds_upstream, hex, pattern, Head, CLASS_MOUNT, DEFAULT};
use crate::apparmor::ast::{Cond, CondOp, MountKind};
use crate::apparmor::compile::rules::RuleSet;
use crate::apparmor::compile::Support;
use crate::apparmor::model::{Audit, Owner, Prefix};
use crate::apparmor::process::filter_slashes;

pub const MAY_PIVOTROOT: u32 = 1;
pub const MAY_MOUNT: u32 = 2;
pub const MAY_UMOUNT: u32 = 4;
const DUMMY_REMOUNT: u32 = 0x4000_0000;

const RDONLY: u32 = 1 << 0;
const NOSUID: u32 = 1 << 1;
const NODEV: u32 = 1 << 2;
const NOEXEC: u32 = 1 << 3;
const SYNCHRONOUS: u32 = 1 << 4;
const REMOUNT: u32 = 1 << 5;
const MAND: u32 = 1 << 6;
const DIRSYNC: u32 = 1 << 7;
const NOSYMFOLLOW: u32 = 1 << 8;
const NOATIME: u32 = 1 << 10;
const NODIRATIME: u32 = 1 << 11;
const BIND: u32 = 1 << 12;
const MOVE: u32 = 1 << 13;
const REC: u32 = 1 << 14;
const VERBOSE: u32 = 1 << 15;
const ACL: u32 = 1 << 16;
const UNBINDABLE: u32 = 1 << 17;
const PRIVATE: u32 = 1 << 18;
const SLAVE: u32 = 1 << 19;
const SHARED: u32 = 1 << 20;
const RELATIME: u32 = 1 << 21;
const IVERSION: u32 = 1 << 23;
const STRICTATIME: u32 = 1 << 24;
const LAZYTIME: u32 = 1 << 25;
const NOUSER: u32 = 1 << 31;
const RBIND: u32 = BIND | REC;
const RUNBINDABLE: u32 = UNBINDABLE | REC;
const RPRIVATE: u32 = PRIVATE | REC;
const RSLAVE: u32 = SLAVE | REC;
const RSHARED: u32 = SHARED | REC;

const ALL_FLAGS: u32 = RDONLY
    | NOSUID
    | NODEV
    | NOEXEC
    | SYNCHRONOUS
    | REMOUNT
    | MAND
    | DIRSYNC
    | NOSYMFOLLOW
    | NOATIME
    | NODIRATIME
    | BIND
    | RBIND
    | MOVE
    | VERBOSE
    | ACL
    | UNBINDABLE
    | RUNBINDABLE
    | PRIVATE
    | RPRIVATE
    | SLAVE
    | RSLAVE
    | SHARED
    | RSHARED
    | RELATIME
    | IVERSION
    | STRICTATIME
    | LAZYTIME;
const MNT_FLAGS: u32 = NOSUID | NOEXEC | NODEV | NOATIME | NODIRATIME | RELATIME | STRICTATIME;
const BIND_FLAGS: u32 = BIND | RBIND;
const MAKE_CMDS: u32 =
    UNBINDABLE | RUNBINDABLE | PRIVATE | RPRIVATE | SLAVE | RSLAVE | SHARED | RSHARED;
const MAKE_FLAGS: u32 = ALL_FLAGS & !MNT_FLAGS;
const MOVE_FLAGS: u32 = MOVE;
const CMDS: u32 = MOVE | REMOUNT | BIND | RBIND | MAKE_CMDS;
const REMOUNT_FLAGS: u32 = ALL_FLAGS & !MOVE_FLAGS;
const NEW_FLAGS: u32 = ALL_FLAGS & !CMDS;

/// upstream's mnt_opts_table: (keyword, flags set, flags cleared).
const OPTS: &[(&str, u32, u32)] = &[
    ("ro", RDONLY, 0),
    ("r", RDONLY, 0),
    ("read-only", RDONLY, 0),
    ("rw", 0, RDONLY),
    ("w", 0, RDONLY),
    ("suid", 0, NOSUID),
    ("nosuid", NOSUID, 0),
    ("dev", 0, NODEV),
    ("nodev", NODEV, 0),
    ("exec", 0, NOEXEC),
    ("noexec", NOEXEC, 0),
    ("sync", SYNCHRONOUS, 0),
    ("async", 0, SYNCHRONOUS),
    ("remount", REMOUNT, 0),
    ("mand", MAND, 0),
    ("nomand", 0, MAND),
    ("dirsync", DIRSYNC, 0),
    ("symfollow", 0, NOSYMFOLLOW),
    ("nosymfollow", NOSYMFOLLOW, 0),
    ("atime", 0, NOATIME),
    ("noatime", NOATIME, 0),
    ("diratime", 0, NODIRATIME),
    ("nodiratime", NODIRATIME, 0),
    ("bind", BIND, 0),
    ("B", BIND, 0),
    ("move", MOVE, 0),
    ("M", MOVE, 0),
    ("rbind", RBIND, 0),
    ("R", RBIND, 0),
    ("verbose", VERBOSE, 0),
    ("silent", VERBOSE, 0),
    ("loud", 0, VERBOSE),
    ("acl", ACL, 0),
    ("noacl", 0, ACL),
    ("unbindable", UNBINDABLE, 0),
    ("make-unbindable", UNBINDABLE, 0),
    ("runbindable", RUNBINDABLE, 0),
    ("make-runbindable", RUNBINDABLE, 0),
    ("private", PRIVATE, 0),
    ("make-private", PRIVATE, 0),
    ("rprivate", RPRIVATE, 0),
    ("make-rprivate", RPRIVATE, 0),
    ("slave", SLAVE, 0),
    ("make-slave", SLAVE, 0),
    ("rslave", RSLAVE, 0),
    ("make-rslave", RSLAVE, 0),
    ("shared", SHARED, 0),
    ("make-shared", SHARED, 0),
    ("rshared", RSHARED, 0),
    ("make-rshared", RSHARED, 0),
    ("relatime", RELATIME, 0),
    ("norelatime", 0, RELATIME),
    ("iversion", IVERSION, 0),
    ("noiversion", 0, IVERSION),
    ("strictatime", STRICTATIME, 0),
    ("nostrictatime", 0, STRICTATIME),
    ("lazytime", LAZYTIME, 0),
    ("nolazytime", 0, LAZYTIME),
    ("user", 0, NOUSER),
    ("nouser", NOUSER, 0),
];

#[derive(Debug, Clone, Default)]
pub struct Mount {
    pub head: Head,
    pub mnt_point: Option<Vec<u8>>,
    pub device: Option<Vec<u8>>,
    pub trans: Option<Vec<u8>>,
    pub dev_type: Vec<Vec<u8>>,
    pub flagsv: Vec<u32>,
    pub opt_flagsv: Vec<u32>,
}

fn extract_flags(vals: &[Vec<u8>]) -> Result<(u32, u32), String> {
    let (mut flags, mut inv) = (0, 0);
    for v in vals {
        match OPTS.iter().find(|(k, _, _)| k.as_bytes() == &v[..]) {
            Some(&(_, set, clear)) => {
                flags |= set;
                inv |= clear;
            }
            None => {
                return Err(format!(
                    "unsupported mount option value '{}'",
                    String::from_utf8_lossy(v)
                ))
            }
        }
    }
    Ok((flags, inv))
}

fn eq_or_in(c: &Cond) -> Result<(), String> {
    if c.op != CondOp::Eq && c.op != CondOp::In {
        return Err("only \"=\" and 'in' allowed in conditions of mount rules".into());
    }
    Ok(())
}

impl Mount {
    /// upstream's mnt_rule constructor.
    fn build(
        conds: &[Cond],
        device: Option<Vec<u8>>,
        mnt_point: Option<Vec<u8>>,
        mut perms: u32,
    ) -> Result<Mount, String> {
        let mut r = Mount {
            device,
            mnt_point,
            ..Mount::default()
        };
        let mut rest: Vec<&Cond> = Vec::new();
        let mut fstypes: Vec<&Cond> = Vec::new();
        for c in conds_upstream(conds) {
            eq_or_in(c)?;
            if c.name == b"fstype" || c.name == b"vfstype" {
                fstypes.push(c);
            } else {
                rest.push(c);
            }
        }
        for c in fstypes.iter().rev() {
            r.dev_type.extend(c.values.iter().cloned());
        }
        let is_opts = |c: &&Cond| c.name == b"options" || c.name == b"option";
        let mut left: Vec<&Cond> = Vec::new();
        for c in &rest {
            eq_or_in(c)?;
            if is_opts(c) && c.op == CondOp::In {
                let (f, inv) = extract_flags(&c.values)?;
                r.opt_flagsv.push(f | inv);
            } else {
                left.push(c);
            }
        }
        let mut remaining = 0;
        for c in &left {
            eq_or_in(c)?;
            if is_opts(c) && c.op == CondOp::Eq {
                let (mut f, inv) = extract_flags(&c.values)?;
                if perms & DUMMY_REMOUNT != 0 {
                    f |= REMOUNT;
                }
                if f & inv != 0 {
                    return Err("conflicting flags in the rule".into());
                }
                r.flagsv.push(f);
            } else {
                remaining += 1;
            }
        }
        if remaining > 0 {
            return Err("unsupported mount condition".into());
        }
        if r.flagsv.is_empty() && r.opt_flagsv.is_empty() {
            if perms & DUMMY_REMOUNT != 0 {
                r.flagsv.push(REMOUNT);
                r.opt_flagsv.push(REMOUNT_FLAGS & !REMOUNT);
            } else {
                r.flagsv.push(ALL_FLAGS);
                r.opt_flagsv.push(ALL_FLAGS);
            }
        } else if r.flagsv.is_empty() {
            r.flagsv.push(if perms & DUMMY_REMOUNT != 0 {
                REMOUNT
            } else {
                0
            });
        } else if r.opt_flagsv.is_empty() {
            r.opt_flagsv.push(0);
        }
        if perms & DUMMY_REMOUNT != 0 {
            perms = MAY_MOUNT;
        }
        r.head.perms = perms;
        Ok(r)
    }

    /// The rule as written, before its prefix: upstream's do_mnt_rule
    /// and do_pivot_rule.
    pub fn parse(
        kind: MountKind,
        conds: &[Cond],
        source: &Option<Vec<u8>>,
        dest: &Option<(Vec<Cond>, Vec<u8>)>,
        transition: &Option<Vec<u8>>,
    ) -> Result<Mount, String> {
        if kind == MountKind::PivotRoot {
            let mut device = None;
            if let Some(old) = conds_upstream(conds).next() {
                if old.name != b"oldroot" {
                    return Err(format!(
                        "invalid pivotroot conditional '{}'",
                        String::from_utf8_lossy(&old.name)
                    ));
                }
                device = old.values.first().cloned();
            }
            let mut r = Mount::build(&[], device, source.clone(), MAY_PIVOTROOT)?;
            r.trans = transition.clone();
            return Ok(r);
        }
        for c in conds_upstream(conds) {
            let known = [&b"options"[..], b"option", b"fstype", b"vfstype"];
            if !known.contains(&&c.name[..]) {
                return Err(format!(
                    "invalid mount conditional {}",
                    String::from_utf8_lossy(&c.name)
                ));
            }
        }
        match kind {
            MountKind::Mount => {
                let (dst_conds, target) = match dest {
                    Some((c, t)) => (&c[..], Some(t.clone())),
                    None => (&[][..], None),
                };
                if !dst_conds.is_empty() {
                    return Err("mount point conditions not currently supported".into());
                }
                Mount::build(conds, source.clone(), target, MAY_MOUNT)
            }
            MountKind::Remount => Mount::build(conds, None, source.clone(), DUMMY_REMOUNT),
            _ => Mount::build(conds, None, source.clone(), MAY_UMOUNT),
        }
    }

    pub fn new(
        kind: MountKind,
        conds: &[Cond],
        source: &Option<Vec<u8>>,
        dest: &Option<(Vec<Cond>, Vec<u8>)>,
        transition: &Option<Vec<u8>>,
        prefix: Prefix,
    ) -> Result<Mount, String> {
        let mut r = Mount::parse(kind, conds, source, dest, transition)?;
        if prefix.owner != Owner::Unspecified {
            return Err("owner prefix not allowed on mount rules".into());
        }
        r.head.prefix = add_prefix(r.head.prefix, prefix)?;
        Ok(r)
    }

    pub fn expand(
        &mut self,
        f: &mut dyn FnMut(&mut Vec<u8>) -> Result<(), String>,
    ) -> Result<(), String> {
        if let Some(m) = self.mnt_point.as_mut() {
            f(m)?;
            filter_slashes(m);
        }
        if let Some(d) = self.device.as_mut() {
            f(d)?;
            filter_slashes(d);
        }
        if let Some(t) = self.trans.as_mut() {
            f(t)?;
        }
        for v in self.dev_type.iter_mut() {
            f(v)?;
        }
        Ok(())
    }

    fn audit(&self) -> u32 {
        if self.head.prefix.audit == Audit::Force {
            self.head.perms
        } else {
            0
        }
    }

    fn add(&self, set: &mut RuleSet, parts: &[&str]) -> Result<(), String> {
        let p: Vec<&[u8]> = parts.iter().map(|s| s.as_bytes()).collect();
        set.add_vec(
            self.head.prefix.priority,
            self.head.prefix.mode,
            self.head.perms,
            self.audit(),
            &p,
            false,
        )
        .map_err(|_| "Encoding of mount rule failed".to_string())
    }

    fn header(&self, entry: &Option<Vec<u8>>) -> Result<String, String> {
        let mut s = hex(CLASS_MOUNT);
        s.push_str(&entry_pattern(entry)?);
        Ok(s)
    }

    fn device_pattern(&self) -> Result<String, String> {
        if self.device.as_deref() == Some(b"detached") {
            // Matches nothing: a detached mount has no source.
            return Ok(String::new());
        }
        entry_pattern(&self.device)
    }

    fn remount(&self, set: &mut RuleSet, flags: u32, opt: u32) -> Result<(), String> {
        let first = if self.mnt_point.is_some() {
            &self.mnt_point
        } else {
            &self.device
        };
        let mnt = self.header(first)?;
        let f = mnt_flags(flags & REMOUNT_FLAGS, opt & REMOUNT_FLAGS);
        self.add(set, &[&mnt, DEFAULT, DEFAULT, &f])
    }

    fn bind(&self, set: &mut RuleSet, flags: u32, opt: u32, mask: u32) -> Result<(), String> {
        let mnt = self.header(&self.mnt_point)?;
        let dev = self.device_pattern()?;
        let f = mnt_flags(flags & mask, opt & mask);
        self.add(set, &[&mnt, &dev, DEFAULT, &f])
    }

    fn change_type(&self, set: &mut RuleSet, flags: u32, opt: u32) -> Result<(), String> {
        let mut point = &self.mnt_point;
        if flags != 0 && flags != ALL_FLAGS && self.device.is_some() && self.mnt_point.is_some() {
            return Err(
                "source and mount point cannot be used at the same time for propagation type flags"
                    .into(),
            );
        } else if self.device.is_some() && self.mnt_point.is_none() {
            point = &self.device;
        }
        let mnt = self.header(point)?;
        let f = mnt_flags(flags & MAKE_FLAGS, opt & MAKE_FLAGS);
        self.add(set, &[&mnt, DEFAULT, DEFAULT, &f])
    }

    fn new_mount(&self, set: &mut RuleSet, flags: u32, opt: u32) -> Result<(), String> {
        let mnt = self.header(&self.mnt_point)?;
        let dev = self.device_pattern()?;
        let ty = if self.dev_type.is_empty() {
            DEFAULT.to_string()
        } else {
            let mut t = String::from("(");
            for (i, v) in self.dev_type.iter().enumerate() {
                if i > 0 {
                    t.push('|');
                }
                t.push_str(&pattern(v)?);
            }
            t.push(')');
            t
        };
        let f = mnt_flags(flags & NEW_FLAGS, opt & NEW_FLAGS);
        self.add(set, &[&mnt, &dev, &ty, &f])
    }

    /// upstream's gen_flag_rules; returns how many rules it added.
    fn flag_rules(&self, set: &mut RuleSet, flags: u32, opt: u32) -> Result<usize, String> {
        let perms = self.head.perms;
        let no_type = self.dev_type.is_empty();
        if perms & MAY_MOUNT == 0 {
            return Ok(0);
        }
        if flags == 0 || flags == ALL_FLAGS {
            let mut n = 0;
            if self.device.is_none() && no_type {
                self.remount(set, flags, opt)?;
                n += 1;
            }
            if no_type {
                self.bind(set, flags, opt, BIND_FLAGS)?;
                n += 1;
            }
            if (self.device.is_none() || self.mnt_point.is_none()) && no_type {
                self.change_type(set, flags, opt)?;
                n += 1;
            }
            if no_type {
                self.bind(set, flags, opt, MOVE_FLAGS)?;
                n += 1;
            }
            self.new_mount(set, flags, opt)?;
            return Ok(n + 1);
        }
        if flags & REMOUNT != 0 && self.device.is_none() && no_type {
            self.remount(set, flags, opt)?;
        } else if flags & BIND != 0 && no_type {
            self.bind(set, flags, opt, BIND_FLAGS)?;
        } else if flags & MAKE_CMDS != 0
            && (self.device.is_none() || self.mnt_point.is_none())
            && no_type
        {
            self.change_type(set, flags, opt)?;
        } else if flags & MOVE != 0 && no_type {
            self.bind(set, flags, opt, MOVE_FLAGS)?;
        } else if (flags | opt) & !CMDS != 0 {
            self.new_mount(set, flags, opt)?;
        } else {
            return Ok(0);
        }
        Ok(1)
    }

    pub fn gen(&self, set: &mut RuleSet, s: &Support) -> Result<(), String> {
        if !s.mount {
            return Ok(());
        }
        let mut count = 0;
        for &f in &self.flagsv {
            for &o in &self.opt_flagsv {
                count += self.flag_rules(set, f, o)?;
            }
        }
        if self.head.perms & MAY_UMOUNT != 0 {
            let mnt = self.header(&self.mnt_point)?;
            self.add(set, &[&mnt])?;
            count += 1;
        }
        if self.head.perms & MAY_PIVOTROOT != 0 {
            let mnt = self.header(&self.mnt_point)?;
            let dev = entry_pattern(&self.device)?;
            self.add(set, &[&mnt, &dev])?;
            count += 1;
        }
        if count == 0 {
            return Err("Encoding of mount rule failed".into());
        }
        Ok(())
    }
}

/// upstream's convert_entry: a pattern, or anything without NUL.
fn entry_pattern(e: &Option<Vec<u8>>) -> Result<String, String> {
    match e {
        Some(v) => pattern(v),
        None => Ok(DEFAULT.into()),
    }
}

/// upstream's build_mnt_flags: one byte per flag bit, optional where the
/// flag is optional.
fn mnt_flags(flags: u32, opt: u32) -> String {
    if flags == ALL_FLAGS {
        return DEFAULT.into();
    }
    let mut s = String::new();
    for i in 0..32 {
        if opt & (1 << i) != 0 {
            s.push_str(&format!("({}|)", hex(i + 1)));
        } else if flags & (1 << i) != 0 {
            s.push_str(&hex(i + 1));
        }
    }
    if s.is_empty() {
        s.push_str("(\\xfe|)");
    }
    s
}
