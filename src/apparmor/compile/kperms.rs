//! The permission entries of kernels that take a permissions table
//! (`policy/permstable32`): upstream's policy_compat.cc, which maps the
//! accept table encoding into the kernel's `struct aa_perms`.

use super::dfa::Perms;

pub const MAY_EXEC: u32 = 1;
pub const MAY_WRITE: u32 = 2;
pub const MAY_READ: u32 = 4;
pub const MAY_CREATE: u32 = 0x0010;
pub const MAY_DELETE: u32 = 0x0020;
pub const MAY_OPEN: u32 = 0x0040;
pub const MAY_SETATTR: u32 = 0x0100;
pub const MAY_GETATTR: u32 = 0x0200;
pub const MAY_CHMOD: u32 = 0x1000;
pub const MAY_CHOWN: u32 = 0x2000;
pub const MAY_LOCK: u32 = 0x8000;
pub const EXEC_MMAP: u32 = 0x0001_0000;
pub const MAY_LINK: u32 = 0x0004_0000;
pub const CONT_MATCH: u32 = 0x0800_0000;
pub const COMPAT_CONT_MATCH: u32 = CONT_MATCH << 1;
pub const MAY_ONEXEC: u32 = 0x2000_0000;
pub const MAY_CHANGE_PROFILE: u32 = 0x4000_0000;
pub const LINK_SUBSET: u32 = MAY_LOCK;

pub const X_NAME: u32 = 0x0400_0000;
pub const X_TABLE: u32 = 0x0800_0000;
pub const X_UNSAFE: u32 = 0x1000_0000;
pub const X_CHILD: u32 = 0x2000_0000;
pub const X_INHERIT: u32 = 0x4000_0000;
pub const X_UNCONFINED: u32 = 0x8000_0000;

/// The kernel's `struct aa_perms`, in the order the policy writes it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct AaPerms {
    pub allow: u32,
    pub deny: u32,
    pub subtree: u32,
    pub cond: u32,
    pub kill: u32,
    pub complain: u32,
    pub prompt: u32,
    pub audit: u32,
    pub quiet: u32,
    pub hide: u32,
    pub xindex: u32,
    pub tag: u32,
    pub label: u32,
}

fn map_xindex(mask: u32) -> u32 {
    let old = (mask >> 10) & 0xf;
    let mut index = 0;
    if mask & 0x100 != 0 {
        index |= X_UNSAFE;
    }
    if mask & 0x200 != 0 {
        index |= X_INHERIT;
    }
    if mask & 0x80 != 0 {
        index |= X_UNCONFINED;
    }
    match old {
        0 => {}
        1 => index |= X_UNCONFINED,
        2 => index |= X_NAME,
        3 => index |= X_NAME | X_CHILD,
        n => index |= X_TABLE | (n - 4),
    }
    index
}

fn map_old(old: u32) -> u32 {
    let mut p = old & 0xf;
    if old & MAY_READ != 0 {
        p |= MAY_GETATTR | MAY_OPEN;
    }
    if old & MAY_WRITE != 0 {
        p |= MAY_SETATTR | MAY_CREATE | MAY_DELETE | MAY_CHMOD | MAY_CHOWN | MAY_OPEN;
    }
    if old & 0x10 != 0 {
        p |= MAY_LINK;
    }
    if old & 0x20 != 0 {
        p |= MAY_LOCK | LINK_SUBSET;
    }
    if old & 0x40 != 0 {
        p |= EXEC_MMAP;
    }
    p
}

fn file_allow_extra(p: &mut AaPerms, accept1: u32) {
    p.allow |= MAY_GETATTR;
    if accept1 & 0x8000_0000 != 0 {
        p.allow |= MAY_CHANGE_PROFILE;
    }
    if accept1 & 0x4000_0000 != 0 {
        p.allow |= MAY_ONEXEC;
    }
}

fn user_allow(a: u32) -> u32 {
    (a & 0x7f) | (a & 0x8000_0000)
}

fn other_allow(a: u32) -> u32 {
    ((a >> 14) & 0x7f) | (a & 0x8000_0000)
}

fn map_other(x: u32) -> u32 {
    ((x & 0x3) << 8) | ((x & 0x1c) << 18) | ((x & 0x60) << 19)
}

impl Perms {
    /// The file automaton's two entries for a state, owner and other.
    pub fn file_entries(&self) -> [AaPerms; 2] {
        let (a1, a2) = self.accept_pair();
        let a3 = self.prompt;
        let mut user = AaPerms {
            allow: map_old(user_allow(a1)),
            prompt: map_old(user_allow(a3)),
            audit: map_old(a2 & 0x7f),
            quiet: map_old((a2 >> 7) & 0x7f),
            xindex: map_xindex(a1 & 0x3fff),
            ..AaPerms::default()
        };
        file_allow_extra(&mut user, a1);
        user.prompt &= !(user.allow | user.deny);
        let mut other = AaPerms {
            allow: map_old(other_allow(a1)),
            prompt: map_old(other_allow(a3)),
            audit: map_old((a2 >> 14) & 0x7f),
            quiet: map_old(((a2 >> 7) >> 14) & 0x7f),
            xindex: map_xindex((a1 >> 14) & 0x3fff),
            ..AaPerms::default()
        };
        file_allow_extra(&mut other, a1);
        other.prompt &= !(other.allow | other.deny);
        [user, other]
    }

    /// A policy automaton's entry for a state.
    pub fn policy_entry(&self) -> AaPerms {
        let (a1, a2) = self.accept_pair();
        let a3 = self.prompt;
        let mut p = AaPerms {
            allow: user_allow(a1),
            prompt: user_allow(a3),
            audit: a2 & 0x7f,
            quiet: (a2 >> 7) & 0x7f,
            ..AaPerms::default()
        };
        if a1 & COMPAT_CONT_MATCH != 0 {
            p.allow |= CONT_MATCH;
        }
        p.allow |= map_other(other_allow(a1));
        p.allow |= MAY_LOCK;
        p.prompt |= map_other(other_allow(a3));
        p.audit |= map_other((a2 >> 14) & 0x7f);
        p.quiet |= map_other(((a2 >> 7) >> 14) & 0x7f);
        p
    }
}
