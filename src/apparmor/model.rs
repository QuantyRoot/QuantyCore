//! Profiles as the compiler sees them: names resolved, prefixes applied,
//! permissions as bit masks. This is the shape upstream's parser builds
//! during parsing, and the bit layout is the one the kernel reads.

use std::collections::{BTreeMap, VecDeque};

use super::ast;
use super::source::Span;

pub(crate) mod perm {
    pub const MAY_EXEC: u32 = 1 << 0;
    pub const MAY_WRITE: u32 = 1 << 1;
    pub const MAY_READ: u32 = 1 << 2;
    pub const MAY_APPEND: u32 = 1 << 3;
    pub const OLD_MAY_LINK: u32 = 1 << 4;
    pub const OLD_MAY_LOCK: u32 = 1 << 5;
    pub const OLD_EXEC_MMAP: u32 = 1 << 6;
    pub const EXEC_PUX: u32 = 1 << 7;
    pub const EXEC_UNSAFE: u32 = 1 << 8;
    pub const EXEC_INHERIT: u32 = 1 << 9;
    pub const EXEC_MOD_0: u32 = 1 << 10;
    pub const EXEC_MOD_1: u32 = 1 << 11;
    pub const EXEC_MOD_2: u32 = 1 << 12;
    pub const EXEC_MOD_3: u32 = 1 << 13;

    pub const USER_SHIFT: u32 = 0;
    pub const OTHER_SHIFT: u32 = 14;

    pub const BASE_PERMS: u32 = MAY_EXEC
        | MAY_WRITE
        | MAY_READ
        | MAY_APPEND
        | OLD_MAY_LINK
        | OLD_MAY_LOCK
        | EXEC_PUX
        | OLD_EXEC_MMAP
        | EXEC_UNSAFE
        | EXEC_INHERIT
        | EXEC_MOD_0
        | EXEC_MOD_1
        | EXEC_MOD_2
        | EXEC_MOD_3;
    pub const USER_PERMS: u32 = BASE_PERMS << USER_SHIFT;
    pub const OTHER_PERMS: u32 = BASE_PERMS << OTHER_SHIFT;
    pub const FILE_PERMS: u32 = USER_PERMS | OTHER_PERMS;

    pub const CHANGE_HAT: u32 = 1 << 30;
    pub const ONEXEC: u32 = 1 << 30;
    pub const CHANGE_PROFILE: u32 = 1 << 31;
    pub const SHARED_PERMS: u32 = CHANGE_HAT | CHANGE_PROFILE;

    pub const EXEC_MODIFIERS: u32 = EXEC_MOD_0 | EXEC_MOD_1 | EXEC_MOD_2 | EXEC_MOD_3;
    pub const EXEC_COUNT: usize = 16;
    pub const USER_EXEC_MODIFIERS: u32 = EXEC_MODIFIERS << USER_SHIFT;
    pub const OTHER_EXEC_MODIFIERS: u32 = EXEC_MODIFIERS << OTHER_SHIFT;
    pub const ALL_EXEC_MODIFIERS: u32 = USER_EXEC_MODIFIERS | OTHER_EXEC_MODIFIERS;
    pub const EXEC_TYPE: u32 = EXEC_UNSAFE | EXEC_INHERIT | EXEC_PUX | EXEC_MODIFIERS;
    pub const EXEC_UNCONFINED: u32 = EXEC_MOD_0;
    pub const EXEC_PROFILE: u32 = EXEC_MOD_1;
    pub const EXEC_LOCAL: u32 = EXEC_MOD_0 | EXEC_MOD_1;

    pub const USER_EXEC: u32 = MAY_EXEC << USER_SHIFT;
    pub const OTHER_EXEC: u32 = MAY_EXEC << OTHER_SHIFT;
    pub const EXEC_BITS: u32 = USER_EXEC | OTHER_EXEC;
    pub const ALL_EXEC_UNSAFE: u32 = (EXEC_UNSAFE << USER_SHIFT) | (EXEC_UNSAFE << OTHER_SHIFT);
    pub const USER_EXEC_TYPE: u32 = EXEC_TYPE << USER_SHIFT;
    pub const OTHER_EXEC_TYPE: u32 = EXEC_TYPE << OTHER_SHIFT;
    pub const ALL_EXEC_TYPE: u32 = USER_EXEC_TYPE | OTHER_EXEC_TYPE;
    pub const LINK_BITS: u32 = (OLD_MAY_LINK << USER_SHIFT) | (OLD_MAY_LINK << OTHER_SHIFT);

    pub const fn shift(mode: u32, by: u32) -> u32 {
        ((mode & BASE_PERMS) << by) | (mode & !FILE_PERMS)
    }

    /// Two permission sets name the same exec transition wherever both
    /// allow exec, for the user and the other half separately.
    pub const fn x_consistent(a: u32, b: u32) -> bool {
        if (a & USER_EXEC) != 0
            && (b & USER_EXEC) != 0
            && (a & USER_EXEC_TYPE) != (b & USER_EXEC_TYPE)
        {
            return false;
        }
        if (a & OTHER_EXEC) != 0
            && (b & OTHER_EXEC) != 0
            && (a & OTHER_EXEC_TYPE) != (b & OTHER_EXEC_TYPE)
        {
            return false;
        }
        true
    }
}

pub const MIN_POLICY_PRIORITY: i32 = -1000;
pub const MAX_POLICY_PRIORITY: i32 = 1000;
pub const MIN_INTERNAL_PRIORITY: i32 = MIN_POLICY_PRIORITY - 1;
pub const MAX_INTERNAL_PRIORITY: i32 = MAX_POLICY_PRIORITY + 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Audit {
    #[default]
    Unspecified,
    Force,
    Quiet,
}

pub use ast::{Owner, RuleMode};

/// A rule's prefix after the grammar: priority checked, everything else
/// as written.
#[derive(Debug, Clone, Copy, Default)]
pub struct Prefix {
    pub priority: i32,
    pub audit: Audit,
    pub mode: RuleMode,
    pub owner: Owner,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub enum Mode {
    #[default]
    Unspecified = 0,
    Enforce = 1,
    Complain = 2,
    Kill = 3,
    Unconfined = 4,
    Prompt = 5,
    DefaultAllow = 6,
}

impl Mode {
    pub(crate) fn from_name(s: &[u8]) -> Option<Mode> {
        Some(match s {
            b"enforce" => Mode::Enforce,
            b"complain" => Mode::Complain,
            b"kill" => Mode::Kill,
            b"unconfined" => Mode::Unconfined,
            b"prompt" => Mode::Prompt,
            b"default_allow" => Mode::DefaultAllow,
            _ => return None,
        })
    }

    pub(crate) fn name(self) -> &'static str {
        match self {
            Mode::Unspecified => "",
            Mode::Enforce => "enforce",
            Mode::Complain => "complain",
            Mode::Kill => "kill",
            Mode::Unconfined => "unconfined",
            Mode::Prompt => "prompt",
            Mode::DefaultAllow => "default_allow",
        }
    }
}

pub(crate) mod path_flag {
    pub const CHROOT_REL: u32 = 0x1;
    pub const NS_REL: u32 = 0x2;
    pub const CHROOT_NSATTACH: u32 = 0x4;
    pub const CHROOT_NO_ATTACH: u32 = 0x8;
    pub const MEDIATE_DELETED: u32 = 0x10;
    pub const DELEGATE_DELETED: u32 = 0x20;
    pub const ATTACH: u32 = 0x40;
    pub const NO_ATTACH: u32 = 0x80;
    pub const IPC_ATTACH: u32 = 0x100;
}

pub(crate) const FLAG_HAT: u32 = 1;
pub(crate) const FLAG_DEBUG1: u32 = 2;
pub(crate) const FLAG_INTERRUPTIBLE: u32 = 8;

#[derive(Debug, Clone, Default)]
pub struct Flags {
    pub flags: u32,
    pub mode: Mode,
    pub audit: bool,
    pub path: u32,
    pub disconnected_path: Option<Vec<u8>>,
    pub disconnected_ipc: Option<Vec<u8>>,
    pub signal: u32,
    pub error: u32,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Caps {
    pub allow: u64,
    pub audit: u64,
    pub deny: u64,
    pub quiet: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Rlimits {
    pub specified: u32,
    pub limits: [u64; super::tables::RLIMIT_COUNT],
}

/// A file, link or change_profile rule, which upstream keeps in one
/// list apart from the other rule kinds.
#[derive(Debug, Clone)]
pub struct Entry {
    pub name: Vec<u8>,
    /// The link target, or the exec condition of a change_profile rule.
    pub link_name: Option<Vec<u8>>,
    /// A named exec transition target, until it moves to the exec table.
    pub nt_name: Option<Vec<u8>>,
    pub perms: u32,
    pub audit: Audit,
    pub mode: RuleMode,
    pub priority: i32,
    pub subset: bool,
    pub alias_ignore: bool,
    pub span: Span,
}

impl Entry {
    pub(crate) fn new(name: Vec<u8>, perms: u32, link_name: Option<Vec<u8>>, span: Span) -> Entry {
        Entry {
            name,
            link_name,
            nt_name: None,
            perms,
            audit: Audit::Unspecified,
            mode: RuleMode::Unspecified,
            priority: 0,
            subset: false,
            alias_ignore: false,
            span,
        }
    }
}

/// The rule kinds compiled into the policy automaton. Each is filled in
/// by its own module.
#[derive(Debug, Clone)]
pub enum PolicyRule {
    /// Parsed and kept for the stage that builds it.
    Pending {
        rule: ast::Rule,
        prefix: Prefix,
        span: Span,
    },
}

#[derive(Debug, Clone)]
pub struct Profile {
    pub ns: Option<Vec<u8>>,
    pub name: Vec<u8>,
    pub attachment: Option<Vec<u8>>,
    pub altnames: Vec<Vec<u8>>,
    pub xattrs: Option<ast::CondList>,
    pub identities: Vec<Vec<u8>>,
    pub flags: Flags,
    pub caps: Caps,
    pub rlimits: Rlimits,
    /// In upstream's list order: each new entry goes to the front.
    pub entries: VecDeque<Entry>,
    pub rules: Vec<PolicyRule>,
    /// Hats and child profiles, ordered by namespace then name.
    pub hats: BTreeMap<(Option<Vec<u8>>, Vec<u8>), Profile>,
    pub exec_table: [Option<Vec<u8>>; perm::EXEC_COUNT],
    pub uses_prompt: bool,
    pub span: Span,
    /// Filled in by the compiler.
    pub xmatch: Option<(super::compile::dfa::Dfa, usize)>,
    pub file_dfa: Option<super::compile::dfa::Dfa>,
}

impl Profile {
    pub(crate) fn empty(span: Span) -> Profile {
        Profile {
            ns: None,
            name: Vec::new(),
            attachment: None,
            altnames: Vec::new(),
            xattrs: None,
            identities: Vec::new(),
            flags: Flags::default(),
            caps: Caps::default(),
            rlimits: Rlimits::default(),
            entries: VecDeque::new(),
            rules: Vec::new(),
            hats: BTreeMap::new(),
            exec_table: Default::default(),
            uses_prompt: false,
            span,
            xmatch: None,
            file_dfa: None,
        }
    }

    pub(crate) fn is_hat(&self) -> bool {
        self.flags.flags & FLAG_HAT != 0
    }

    pub(crate) fn add_entry(&mut self, e: Entry) {
        if e.mode == RuleMode::Prompt {
            self.uses_prompt = true;
        }
        self.entries.push_front(e);
    }
}

/// Everything a file defines once its preamble is evaluated.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    /// Top level profiles, ordered by namespace then name.
    pub profiles: BTreeMap<(Option<Vec<u8>>, Vec<u8>), Profile>,
    pub aliases: Vec<(Vec<u8>, Vec<u8>)>,
}
