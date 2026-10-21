//! The syntax tree of a profile file, as written: nothing is evaluated,
//! expanded or checked beyond the grammar. Every node keeps the position
//! it came from so that later stages can report errors there.

use super::lexer::T;
use super::source::Span;

#[derive(Debug, Clone, Default)]
pub struct File {
    pub preamble: Vec<Preamble>,
    pub profiles: Vec<Profile>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AssignOp {
    /// `=`
    Set,
    /// `+=`
    Add,
    /// `?=`
    SetIfUnset,
    /// `:=`
    Override,
}

#[derive(Debug, Clone)]
pub enum Preamble {
    Alias {
        from: Vec<u8>,
        to: Vec<u8>,
        span: Span,
    },
    SetVar {
        name: Vec<u8>,
        op: AssignOp,
        values: Vec<Vec<u8>>,
        span: Span,
    },
    BoolVar {
        name: Vec<u8>,
        op: AssignOp,
        expr: Expr,
        span: Span,
    },
    Abi(Abi),
}

#[derive(Debug, Clone)]
pub struct Abi {
    pub name: Vec<u8>,
    /// `abi <name>` searches the include path; `abi "name"` does not.
    pub search: bool,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileKeyword {
    None,
    Profile,
    Hat,
}

#[derive(Debug, Clone)]
pub struct Profile {
    pub keyword: ProfileKeyword,
    pub name: Vec<u8>,
    pub attachment: Option<Vec<u8>>,
    pub xattrs: Option<CondList>,
    pub identities: Vec<Vec<u8>>,
    pub flags: Vec<Vec<u8>>,
    pub body: Vec<Item>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub enum Item {
    Abi(Abi),
    Rule {
        prefix: Prefix,
        rule: Rule,
        span: Span,
    },
    Block {
        prefix: Prefix,
        items: Vec<Item>,
        span: Span,
    },
    /// `^name { }` or `hat name { }`
    Hat(Profile),
    /// `profile name { }` inside a profile
    Child(Profile),
    If(If),
    Rlimit {
        resource: Vec<u8>,
        value: Vec<u8>,
        unit: Option<Vec<u8>>,
        span: Span,
    },
}

#[derive(Debug, Clone)]
pub struct If {
    pub cond: Expr,
    pub then: Vec<Item>,
    pub otherwise: Option<Else>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub enum Else {
    Block(Vec<Item>),
    If(Box<If>),
}

// An `else if` chain is a list of any length held as nested boxes; the
// default drop would recurse once per branch.
impl Drop for If {
    fn drop(&mut self) {
        let mut next = self.otherwise.take();
        while let Some(Else::If(mut inner)) = next {
            next = inner.otherwise.take();
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RuleMode {
    #[default]
    Unspecified,
    Allow,
    Deny,
    Prompt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Owner {
    #[default]
    Unspecified,
    Owner,
    Other,
}

#[derive(Debug, Clone, Default)]
pub struct Prefix {
    pub priority: Option<(Vec<u8>, Span)>,
    pub audit: bool,
    pub mode: RuleMode,
    pub owner: Owner,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecMode {
    Empty,
    Unsafe,
    Safe,
}

/// A permission word as it reached the grammar: the token kind matters,
/// since `read` as a keyword and `read` as a list value are read
/// differently by some rule kinds.
#[derive(Debug, Clone)]
pub struct PermWord {
    pub t: T,
    pub text: Vec<u8>,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CondOp {
    /// `name` alone
    Bare,
    /// `name=value` or `name=(values)`
    Eq,
    /// `name:=value` or `name:=(values)`
    Set,
    /// `name in (values)`
    In,
}

#[derive(Debug, Clone)]
pub struct Cond {
    pub name: Vec<u8>,
    pub op: CondOp,
    /// Whether the values were given in parentheses.
    pub list: bool,
    pub values: Vec<Vec<u8>>,
    pub span: Span,
}

#[derive(Debug, Clone)]
pub struct CondList {
    pub name: Vec<u8>,
    pub conds: Vec<Cond>,
    pub span: Span,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MountKind {
    Mount,
    Remount,
    Umount,
    PivotRoot,
}

#[derive(Debug, Clone)]
pub enum Rule {
    /// `file,` alone
    FileAll,
    File {
        leading_file: bool,
        exec_mode: ExecMode,
        path: Vec<u8>,
        perms: Vec<u8>,
        /// `rw /path,` rather than `/path rw,`
        perms_first: bool,
        subset: bool,
        target: Option<Vec<u8>>,
    },
    Link {
        subset: bool,
        from: Vec<u8>,
        to: Vec<u8>,
    },
    Network {
        perms: Option<Vec<PermWord>>,
        words: Vec<Vec<u8>>,
        conds: Vec<Cond>,
        peer: Option<CondList>,
    },
    Unix {
        perms: Option<Vec<PermWord>>,
        conds: Vec<Cond>,
        peer: Option<CondList>,
    },
    Dbus {
        perms: Option<Vec<PermWord>>,
        conds: Vec<Cond>,
        peer: Option<CondList>,
    },
    Signal {
        perms: Option<Vec<PermWord>>,
        conds: Vec<Cond>,
    },
    Ptrace {
        perms: Option<Vec<PermWord>>,
        conds: Vec<Cond>,
    },
    Userns {
        perms: Option<Vec<PermWord>>,
        conds: Vec<Cond>,
    },
    Mqueue {
        perms: Option<Vec<PermWord>>,
        conds: Vec<Cond>,
        name: Option<Vec<u8>>,
    },
    IoUring {
        perms: Option<Vec<PermWord>>,
        conds: Vec<Cond>,
        list: Option<CondList>,
    },
    Mount {
        kind: MountKind,
        conds: Vec<Cond>,
        source: Option<Vec<u8>>,
        /// `-> [conds] target` of a mount rule
        dest: Option<(Vec<Cond>, Vec<u8>)>,
        /// `-> profile` of a pivot_root rule
        transition: Option<Vec<u8>>,
    },
    All,
    ChangeProfile {
        exec_mode: ExecMode,
        exec: Option<Vec<u8>>,
        target: Option<Vec<u8>>,
    },
    Capability {
        names: Vec<(Vec<u8>, Span)>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Ne,
    In,
    Gt,
    Ge,
    Lt,
    Le,
}

/// An identifier or a set variable in an expression.
#[derive(Debug, Clone)]
pub struct Operand {
    pub text: Vec<u8>,
    pub is_var: bool,
    pub span: Span,
}

#[derive(Debug, Clone)]
/// A condition. Chains of `or` and `and` are kept flat and repeated
/// `not` is folded, so only parentheses nest, and those are bounded.
pub enum Expr {
    Or(Vec<Expr>),
    And(Vec<Expr>),
    Not(Box<Expr>),
    BoolVar(Vec<u8>, Span),
    Defined(Vec<u8>, Span),
    Cmp(CmpOp, Operand, Operand),
    Value(Operand),
}
