//! The tokens of the profile language.
//!
//! Upstream's lexer is a flex scanner whose start conditions change with
//! the tokens it returns, so the same word is a keyword in one rule and a
//! value in another. The rule table below keeps upstream's rules, their
//! order and their start conditions, because that order decides ties and
//! therefore what a profile means. The token stream depends on nothing
//! the grammar does, with one exception that the parser drives: which
//! includes have already been read in the current profile block.

use std::collections::HashSet;
use std::sync::OnceLock;

use super::scan::{RuleSpec, Scanner, Scratch};
use super::source::{Error, Opened, Resolver, Sources, Span};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum T {
    Id,
    CondId,
    CondListId,
    Caret,
    /// `{`, and also the word `open`, which upstream maps to the same
    /// token.
    Open,
    Close,
    Mode,
    EndOfRule,
    Equals,
    Arrow,
    AddAssign,
    CondAssign,
    OverrideAssign,
    Le,
    SetVar,
    BoolVar,
    Value,
    If,
    Else,
    Not,
    Defined,
    ChangeProfile,
    Network,
    Unix,
    Create,
    Shutdown,
    Accept,
    Connect,
    Listen,
    SetOpt,
    GetOpt,
    SetAttr,
    GetAttr,
    Hat,
    Unsafe,
    Safe,
    Colon,
    Link,
    Owner,
    Other,
    Subset,
    Audit,
    Deny,
    Allow,
    Prompt,
    Profile,
    Set,
    Alias,
    Ptrace,
    OpenParen,
    CloseParen,
    File,
    Mount,
    Remount,
    Umount,
    PivotRoot,
    In,
    Dbus,
    Signal,
    Send,
    Receive,
    Bind,
    Read,
    Write,
    Eavesdrop,
    Peer,
    Trace,
    TracedBy,
    ReadBy,
    Abi,
    Userns,
    Mqueue,
    Delete,
    IoUring,
    OverrideCreds,
    Sqpoll,
    All,
    Priority,
    And,
    Or,
    EqOp,
    NeOp,
    InOp,
    Gt,
    Ge,
    Lt,
    Rlimit,
    Capability,
    Flags,
    Identities,
    Plus,
    Eof,
}

#[derive(Clone, Debug)]
pub struct Token {
    pub t: T,
    pub text: Vec<u8>,
    pub span: Span,
}

// Start conditions, numbered as in upstream's list.
const INITIAL: u8 = 0;
const SUB_ID: u8 = 1;
const SUB_ID_WS: u8 = 2;
const SUB_VALUE: u8 = 3;
const IDENTITY_VALUE: u8 = 4;
const EXTCOND_MODE: u8 = 5;
const EXTCONDLIST_MODE: u8 = 6;
const NETWORK_MODE: u8 = 7;
const LIST_VAL_MODE: u8 = 8;
const LIST_COND_MODE: u8 = 9;
const LIST_COND_VAL: u8 = 10;
const LIST_COND_PAREN_VAL: u8 = 11;
const ASSIGN_MODE: u8 = 12;
const RLIMIT_MODE: u8 = 13;
const MOUNT_MODE: u8 = 14;
const DBUS_MODE: u8 = 15;
const SIGNAL_MODE: u8 = 16;
const PTRACE_MODE: u8 = 17;
const UNIX_MODE: u8 = 18;
const CHANGE_PROFILE_MODE: u8 = 19;
const INCLUDE: u8 = 20;
const INCLUDE_EXISTS: u8 = 21;
const ABI_MODE: u8 = 22;
const USERNS_MODE: u8 = 23;
const MQUEUE_MODE: u8 = 24;
const IOURING_MODE: u8 = 25;
const INTEGER_MODE: u8 = 26;
const EXPR_MODE: u8 = 27;
const ASSIGN_EXPR_MODE: u8 = 28;
const ASSIGN_EXPR_START: u8 = 29;
const NSTATES: usize = 30;

#[derive(Clone, Copy)]
enum Op {
    Stay,
    Push(u8),
    Pop,
    Begin(u8),
}

#[derive(Clone, Copy)]
enum Pay {
    None,
    /// Quotes removed and escapes resolved, upstream's `processid`.
    Id,
    /// The matched text as it is.
    Raw,
}

#[derive(Clone, Copy)]
enum Act {
    Ignore,
    Tok(Op, T, Pay),
    Only(Op),
    IncludeName,
    StartInclude { exists: bool },
    Identities,
    EndOfRule,
    Keyword,
    RlimitWord,
    TrailingComma,
    Unexpected,
}

const DEFS: &[(&str, &str)] = &[
    ("CARET", "\"^\""),
    ("OPEN_BRACE", "\\{"),
    ("CLOSE_BRACE", "\\}"),
    ("SLASH", "\\/"),
    ("COLON", ":"),
    ("AMPERSAND", "&"),
    ("END_OF_RULE", "[,]"),
    ("RANGE", "-"),
    ("PLUS", "\\+"),
    (
        "MODE_CHARS",
        "([RrWwaLlMmkXx])|(([Pp]|[Cc])[Xx])|(([Pp]|[Cc])?([IiUu])[Xx])",
    ),
    ("MODES", "{MODE_CHARS}+"),
    ("WS", "[[:blank:]]"),
    ("NUMBER", "[[:digit:]]+"),
    ("ID_CHARS", "[^ \\t\\r\\n\"!,]"),
    (
        "ID_FIRST",
        "{ID_CHARS}|(,{ID_CHARS}|\\\\[ ]|\\\\\\t|\\\\\\\"|\\\\!|\\\\,|\\\\#)",
    ),
    ("IDENTITY_CHAR", "[^ \\t\\r\\n\"!,{}\\\\=]"),
    (
        "ID",
        "{ID_CHARS}|(,{ID_CHARS}|\\\\[ ]|\\\\\\t|\\\\\\\"|\\\\!|\\\\,)",
    ),
    ("IDS", "{ID_FIRST}{ID}*"),
    (
        "INC_ID",
        "[^ \\t\\r\\n\"!,<>]|(,[^ \\t\\r\\n\"!,<>]|\\\\[ ]|\\\\\\t|\\\\\\\"|\\\\!|\\\\,)",
    ),
    ("INC_IDS", "{INC_ID}+"),
    ("POST_VAR_ID_CHARS", "[^ \\t\\n\"!,]{-}[=\\+?]"),
    (
        "POST_VAR_ID",
        "{POST_VAR_ID_CHARS}|(,{POST_VAR_ID_CHARS}|\\\\[ ]|\\\\\\t|\\\\\\\"|\\\\!|\\\\,|\\\\\\(|\\\\\\)|[^ \\t\\n\"!,=\\+]\\?)",
    ),
    (
        "LIST_VALUE_ID_CHARS",
        "([^ \\t\\n\"!,]{-}[()]|\\\\[ ]|\\\\\\t|\\\\\\\"|\\\\!|\\\\,|\\\\\\(|\\\\\\))",
    ),
    ("LIST_VALUE_QUOTED_ID_CHARS", "[^\\0\"]|\\\\\\\""),
    ("LIST_VALUE_ID", "{LIST_VALUE_ID_CHARS}+"),
    (
        "QUOTED_LIST_VALUE_ID",
        "\\\"{LIST_VALUE_QUOTED_ID_CHARS}+\\\"",
    ),
    ("ID_CHARS_NOEQCOLON", "[^ \\t\\n\"!,]{-}[=:)]"),
    ("ID_CHARS_NOEQ", "[^ \\t\\n\"!,]{-}[=)]"),
    ("LEADING_ID_CHARS_NOEQCOLON", "[^ \\t\\n\"!,]{-}[=()+&:]"),
    ("LEADING_ID_CHARS_NOEQ", "[^ \\t\\n\"!,]{-}[=()+&]"),
    (
        "ID_NOASSIGN",
        "({ID_CHARS_NOEQCOLON}|[:]{ID_CHARS_NOEQ}|(,{ID_CHARS_NOEQCOLON}))",
    ),
    (
        "LEADING_ID_NOASSIGN",
        "({LEADING_ID_CHARS_NOEQCOLON}|[:]{LEADING_ID_CHARS_NOEQ})",
    ),
    ("IDS_NOASSIGN", "{LEADING_ID_NOASSIGN}{ID_NOASSIGN}*"),
    ("ALLOWED_QUOTED_ID", "[^\\0\"]|\\\\\\\""),
    ("QUOTED_ID", "\\\"{ALLOWED_QUOTED_ID}*\\\""),
    ("INTEGER", "[+-]?{NUMBER}"),
    ("HAT", "hat{WS}*"),
    ("PROFILE", "profile{WS}*"),
    ("KEYWORD", "[[:alpha:]_]+"),
    ("VARIABLE_NAME", "[[:alpha:]][[:alnum:]_]*"),
    ("SET_VAR_PREFIX", "@"),
    (
        "SET_VARIABLE",
        "{SET_VAR_PREFIX}(\\{{VARIABLE_NAME}\\}|{VARIABLE_NAME})",
    ),
    ("BOOL_VARIABLE", "$(\\{{VARIABLE_NAME}\\}|{VARIABLE_NAME})"),
    (
        "LABEL",
        "(\\/|{SET_VARIABLE}{POST_VAR_ID}|{COLON}[^=]|{AMPERSAND}){ID}*",
    ),
    (
        "QUOTED_LABEL",
        "\\\"(\\/|{SET_VAR_PREFIX}|{COLON}|{AMPERSAND})([^\\0\"]|\\\\\\\")*\\\"",
    ),
    ("OPEN_PAREN", "\\("),
    ("CLOSE_PAREN", "\\)"),
    ("COMMA", "\\,"),
    ("EQUALS", "="),
    ("ADD_ASSIGN", "\\+="),
    ("COND_ASSIGN", "\\?="),
    ("OVERRIDE_ASSIGN", ":="),
    (
        "ASSIGNMENTS",
        "({EQUALS}|{ADD_ASSIGN}|{COND_ASSIGN}|{OVERRIDE_ASSIGN})",
    ),
    ("ARROW", "->"),
    ("LT_EQUAL", "<="),
    ("LT", "<"),
    ("GT_EQUAL", ">="),
    ("GT", ">"),
    ("EQ_OP", "=="),
    ("NE_OP", "!="),
    ("IN_OP", "in"),
];

fn rules() -> Vec<RuleSpec<Act>> {
    use Act::*;
    use Op::*;
    const ALL_WS: &[u8] = &[
        INITIAL,
        SUB_ID_WS,
        IDENTITY_VALUE,
        INCLUDE,
        INCLUDE_EXISTS,
        LIST_VAL_MODE,
        EXTCOND_MODE,
        LIST_COND_VAL,
        LIST_COND_PAREN_VAL,
        LIST_COND_MODE,
        EXTCONDLIST_MODE,
        ASSIGN_MODE,
        NETWORK_MODE,
        CHANGE_PROFILE_MODE,
        RLIMIT_MODE,
        MOUNT_MODE,
        DBUS_MODE,
        SIGNAL_MODE,
        PTRACE_MODE,
        UNIX_MODE,
        ABI_MODE,
        USERNS_MODE,
        MQUEUE_MODE,
        IOURING_MODE,
        INTEGER_MODE,
        EXPR_MODE,
        ASSIGN_EXPR_MODE,
        ASSIGN_EXPR_START,
    ];
    const COND_MODES: &[u8] = &[
        INITIAL,
        MOUNT_MODE,
        DBUS_MODE,
        SIGNAL_MODE,
        PTRACE_MODE,
        UNIX_MODE,
        MQUEUE_MODE,
        NETWORK_MODE,
    ];
    const NEWLINE: &[u8] = &[
        INITIAL,
        SUB_ID_WS,
        INCLUDE,
        INCLUDE_EXISTS,
        LIST_VAL_MODE,
        EXTCOND_MODE,
        LIST_COND_VAL,
        LIST_COND_PAREN_VAL,
        LIST_COND_MODE,
        EXTCONDLIST_MODE,
        NETWORK_MODE,
        CHANGE_PROFILE_MODE,
        RLIMIT_MODE,
        MOUNT_MODE,
        DBUS_MODE,
        SIGNAL_MODE,
        PTRACE_MODE,
        UNIX_MODE,
        ABI_MODE,
        USERNS_MODE,
        MQUEUE_MODE,
        IOURING_MODE,
        EXPR_MODE,
        ASSIGN_EXPR_MODE,
        ASSIGN_EXPR_START,
    ];
    const UNEXPECTED: &[u8] = &[
        INITIAL,
        SUB_ID,
        SUB_ID_WS,
        SUB_VALUE,
        LIST_VAL_MODE,
        EXTCOND_MODE,
        LIST_COND_VAL,
        LIST_COND_PAREN_VAL,
        LIST_COND_MODE,
        EXTCONDLIST_MODE,
        ASSIGN_MODE,
        NETWORK_MODE,
        CHANGE_PROFILE_MODE,
        MOUNT_MODE,
        DBUS_MODE,
        SIGNAL_MODE,
        PTRACE_MODE,
        UNIX_MODE,
        RLIMIT_MODE,
        INCLUDE,
        INCLUDE_EXISTS,
        ABI_MODE,
        USERNS_MODE,
        MQUEUE_MODE,
        IOURING_MODE,
        EXPR_MODE,
        ASSIGN_EXPR_MODE,
        ASSIGN_EXPR_START,
    ];
    const RULE_MODES: &[u8] = &[
        DBUS_MODE,
        SIGNAL_MODE,
        PTRACE_MODE,
        UNIX_MODE,
        MQUEUE_MODE,
        NETWORK_MODE,
    ];
    const ID_MODES: &[u8] = &[
        MOUNT_MODE,
        DBUS_MODE,
        SIGNAL_MODE,
        PTRACE_MODE,
        UNIX_MODE,
        MQUEUE_MODE,
        IOURING_MODE,
        NETWORK_MODE,
    ];
    const EOR: &[u8] = &[
        INITIAL,
        NETWORK_MODE,
        RLIMIT_MODE,
        CHANGE_PROFILE_MODE,
        MOUNT_MODE,
        DBUS_MODE,
        SIGNAL_MODE,
        PTRACE_MODE,
        UNIX_MODE,
        ABI_MODE,
        USERNS_MODE,
        MQUEUE_MODE,
        IOURING_MODE,
    ];
    const EXPRS: &[u8] = &[EXPR_MODE, ASSIGN_EXPR_MODE];
    const I: &[u8] = &[INITIAL];

    let r = |states: &'static [u8], pattern: &'static str, action: Act| RuleSpec {
        states,
        pattern,
        trailing: None,
        action,
    };
    let tc = |states: &'static [u8], pattern: &'static str, trailing: &'static str, action: Act| {
        RuleSpec {
            states,
            pattern,
            trailing: Some(trailing),
            action,
        }
    };

    vec![
        r(ALL_WS, "{WS}+", Ignore),
        r(
            &[INCLUDE, INCLUDE_EXISTS, ABI_MODE],
            "(\\<((([^\"\\>\\t\\r\\n])+)|{QUOTED_ID})\\>|{QUOTED_ID}|({INC_IDS}))",
            IncludeName,
        ),
        tc(
            &[
                INITIAL,
                MOUNT_MODE,
                DBUS_MODE,
                SIGNAL_MODE,
                PTRACE_MODE,
                UNIX_MODE,
                MQUEUE_MODE,
                NETWORK_MODE,
                IDENTITY_VALUE,
            ],
            "identities",
            "{WS}*=",
            Identities,
        ),
        tc(
            COND_MODES,
            "(peer|xattrs)",
            "{WS}*={WS}*\\(",
            Tok(Push(EXTCONDLIST_MODE), T::CondListId, Pay::Id),
        ),
        tc(
            COND_MODES,
            "priority",
            "{WS}*=",
            Tok(Push(INTEGER_MODE), T::Priority, Pay::None),
        ),
        tc(
            COND_MODES,
            "flags",
            "{WS}*=",
            Tok(Push(EXTCOND_MODE), T::Flags, Pay::None),
        ),
        tc(
            COND_MODES,
            "{VARIABLE_NAME}",
            "{WS}*=",
            Tok(Push(EXTCOND_MODE), T::CondId, Pay::Id),
        ),
        tc(
            COND_MODES,
            "{VARIABLE_NAME}",
            "{WS}+in{WS}*\\(",
            Tok(Push(EXTCOND_MODE), T::CondId, Pay::Id),
        ),
        r(
            &[SUB_ID, SUB_ID_WS],
            "({IDS}|{QUOTED_ID})",
            Tok(Pop, T::Id, Pay::Id),
        ),
        r(
            &[SUB_VALUE],
            "({IDS}|{QUOTED_ID})",
            Tok(Pop, T::Value, Pay::Id),
        ),
        r(
            &[IDENTITY_VALUE],
            "({IDENTITY_CHAR}+|{QUOTED_ID})",
            Tok(Pop, T::Value, Pay::Id),
        ),
        r(
            &[LIST_VAL_MODE],
            "{CLOSE_PAREN}",
            Tok(Pop, T::CloseParen, Pay::None),
        ),
        r(&[LIST_VAL_MODE], "{COMMA}", Ignore),
        r(
            &[LIST_VAL_MODE],
            "({LIST_VALUE_ID}|{QUOTED_ID})",
            Tok(Stay, T::Value, Pay::Id),
        ),
        tc(
            &[EXTCOND_MODE],
            "{EQUALS}{WS}*",
            "[^(\\n]{-}{WS}",
            Tok(Begin(SUB_VALUE), T::Equals, Pay::None),
        ),
        r(&[EXTCOND_MODE], "{EQUALS}", Tok(Stay, T::Equals, Pay::None)),
        tc(
            &[EXTCOND_MODE],
            "{OVERRIDE_ASSIGN}{WS}*",
            "[^(\\n]{-}{WS}",
            Tok(Begin(SUB_VALUE), T::OverrideAssign, Pay::None),
        ),
        r(
            &[EXTCOND_MODE],
            "{OVERRIDE_ASSIGN}",
            Tok(Stay, T::OverrideAssign, Pay::None),
        ),
        r(
            &[EXTCOND_MODE],
            "{OPEN_PAREN}",
            Tok(Begin(LIST_VAL_MODE), T::OpenParen, Pay::None),
        ),
        r(&[EXTCOND_MODE], "in", Tok(Stay, T::In, Pay::None)),
        r(
            &[LIST_COND_VAL],
            "({LIST_VALUE_ID}|{QUOTED_LIST_VALUE_ID})",
            Tok(Pop, T::Value, Pay::Id),
        ),
        r(&[LIST_COND_PAREN_VAL], "{CLOSE_PAREN}", Only(Pop)),
        r(
            &[LIST_COND_PAREN_VAL],
            "({LIST_VALUE_ID}|{QUOTED_LIST_VALUE_ID})",
            Tok(Stay, T::Value, Pay::Id),
        ),
        r(
            &[LIST_COND_MODE],
            "{CLOSE_PAREN}",
            Tok(Pop, T::CloseParen, Pay::None),
        ),
        r(&[LIST_COND_MODE], "{COMMA}", Ignore),
        r(
            &[LIST_COND_MODE],
            "{IDS_NOASSIGN}",
            Tok(Stay, T::CondId, Pay::Id),
        ),
        r(
            &[LIST_COND_MODE],
            "{EQUALS}{WS}*{OPEN_PAREN}",
            Tok(Push(LIST_COND_PAREN_VAL), T::Equals, Pay::None),
        ),
        r(
            &[LIST_COND_MODE],
            "{EQUALS}",
            Tok(Push(LIST_COND_VAL), T::Equals, Pay::None),
        ),
        r(
            &[LIST_COND_MODE],
            "{OVERRIDE_ASSIGN}{WS}*{OPEN_PAREN}",
            Tok(Push(LIST_COND_PAREN_VAL), T::OverrideAssign, Pay::None),
        ),
        r(
            &[LIST_COND_MODE],
            "{OVERRIDE_ASSIGN}",
            Tok(Push(LIST_COND_VAL), T::OverrideAssign, Pay::None),
        ),
        r(
            &[EXTCONDLIST_MODE],
            "{EQUALS}",
            Tok(Stay, T::Equals, Pay::None),
        ),
        r(
            &[EXTCONDLIST_MODE],
            "{OPEN_PAREN}",
            Tok(Begin(LIST_COND_MODE), T::OpenParen, Pay::None),
        ),
        r(
            &[ASSIGN_MODE],
            "({IDS}|{QUOTED_ID})",
            Tok(Stay, T::Value, Pay::Id),
        ),
        r(&[ASSIGN_MODE], "{END_OF_RULE}", TrailingComma),
        r(&[ASSIGN_MODE], "#.*\\r?\\n", Only(Pop)),
        r(&[ASSIGN_MODE], "\\\\\\n", Ignore),
        r(&[ASSIGN_MODE], "\\r?\\n", Only(Pop)),
        r(
            &[CHANGE_PROFILE_MODE],
            "safe",
            Tok(Stay, T::Safe, Pay::None),
        ),
        r(
            &[CHANGE_PROFILE_MODE],
            "unsafe",
            Tok(Stay, T::Unsafe, Pay::None),
        ),
        r(
            &[CHANGE_PROFILE_MODE],
            "{ARROW}",
            Tok(Push(SUB_ID_WS), T::Arrow, Pay::None),
        ),
        r(
            &[CHANGE_PROFILE_MODE],
            "({IDS}|{QUOTED_ID})",
            Tok(Stay, T::Id, Pay::Id),
        ),
        r(&[RLIMIT_MODE], "-?{NUMBER}", Tok(Stay, T::Value, Pay::Raw)),
        r(&[RLIMIT_MODE], "{KEYWORD}", RlimitWord),
        r(&[RLIMIT_MODE], "{LT_EQUAL}", Tok(Stay, T::Le, Pay::None)),
        r(
            &[UNIX_MODE, NETWORK_MODE],
            "listen",
            Tok(Stay, T::Listen, Pay::None),
        ),
        r(
            &[UNIX_MODE, NETWORK_MODE],
            "accept",
            Tok(Stay, T::Accept, Pay::None),
        ),
        r(
            &[UNIX_MODE, NETWORK_MODE],
            "connect",
            Tok(Stay, T::Connect, Pay::None),
        ),
        r(
            &[UNIX_MODE, NETWORK_MODE],
            "getopt",
            Tok(Stay, T::GetOpt, Pay::None),
        ),
        r(
            &[UNIX_MODE, NETWORK_MODE],
            "setopt",
            Tok(Stay, T::SetOpt, Pay::None),
        ),
        r(
            &[UNIX_MODE, NETWORK_MODE],
            "shutdown",
            Tok(Stay, T::Shutdown, Pay::None),
        ),
        r(
            &[UNIX_MODE, USERNS_MODE, MQUEUE_MODE, NETWORK_MODE],
            "create",
            Tok(Stay, T::Create, Pay::None),
        ),
        r(&[MQUEUE_MODE], "open", Tok(Stay, T::Open, Pay::None)),
        r(&[MQUEUE_MODE], "delete", Tok(Stay, T::Delete, Pay::None)),
        r(
            &[UNIX_MODE, MQUEUE_MODE, NETWORK_MODE],
            "getattr",
            Tok(Stay, T::GetAttr, Pay::None),
        ),
        r(
            &[UNIX_MODE, MQUEUE_MODE, NETWORK_MODE],
            "setattr",
            Tok(Stay, T::SetAttr, Pay::None),
        ),
        r(
            &[DBUS_MODE, UNIX_MODE, NETWORK_MODE],
            "bind",
            Tok(Stay, T::Bind, Pay::None),
        ),
        r(
            &[DBUS_MODE],
            "eavesdrop",
            Tok(Stay, T::Eavesdrop, Pay::None),
        ),
        r(
            &[DBUS_MODE, SIGNAL_MODE, UNIX_MODE, NETWORK_MODE],
            "send",
            Tok(Stay, T::Send, Pay::None),
        ),
        r(
            &[DBUS_MODE, SIGNAL_MODE, UNIX_MODE, NETWORK_MODE],
            "receive",
            Tok(Stay, T::Receive, Pay::None),
        ),
        r(&[PTRACE_MODE], "trace", Tok(Stay, T::Trace, Pay::None)),
        r(&[PTRACE_MODE], "readby", Tok(Stay, T::ReadBy, Pay::None)),
        r(
            &[PTRACE_MODE],
            "tracedby",
            Tok(Stay, T::TracedBy, Pay::None),
        ),
        r(RULE_MODES, "read", Tok(Stay, T::Read, Pay::None)),
        r(RULE_MODES, "write", Tok(Stay, T::Write, Pay::None)),
        r(
            RULE_MODES,
            "{OPEN_PAREN}",
            Tok(Push(LIST_VAL_MODE), T::OpenParen, Pay::None),
        ),
        tc(
            RULE_MODES,
            "(r|w|rw|wr)",
            "([[:space:],])",
            Tok(Stay, T::Mode, Pay::Raw),
        ),
        r(&[MOUNT_MODE], "{ARROW}", Tok(Stay, T::Arrow, Pay::None)),
        r(
            &[IOURING_MODE],
            "override_creds",
            Tok(Stay, T::OverrideCreds, Pay::None),
        ),
        r(&[IOURING_MODE], "sqpoll", Tok(Stay, T::Sqpoll, Pay::None)),
        r(
            ID_MODES,
            "({IDS_NOASSIGN}|{LABEL}|{QUOTED_ID})",
            Tok(Stay, T::Id, Pay::Id),
        ),
        r(&[INTEGER_MODE], "{EQUALS}", Tok(Stay, T::Equals, Pay::None)),
        r(&[INTEGER_MODE], "{INTEGER}", Tok(Pop, T::Value, Pay::Raw)),
        tc(
            I,
            "{BOOL_VARIABLE}",
            "{WS}*{ASSIGNMENTS}",
            Tok(Push(ASSIGN_EXPR_START), T::BoolVar, Pay::Raw),
        ),
        r(
            &[INITIAL, EXPR_MODE, ASSIGN_EXPR_MODE],
            "{SET_VARIABLE}",
            Tok(Stay, T::SetVar, Pay::Raw),
        ),
        r(
            &[INITIAL, EXPR_MODE, ASSIGN_EXPR_MODE],
            "{BOOL_VARIABLE}",
            Tok(Stay, T::BoolVar, Pay::Raw),
        ),
        r(&[EXPR_MODE], "{OPEN_BRACE}", Tok(Pop, T::Open, Pay::None)),
        r(&[ASSIGN_EXPR_MODE], "{END_OF_RULE}", TrailingComma),
        r(&[ASSIGN_EXPR_MODE], "#.*\\r?\\n", Only(Pop)),
        r(&[ASSIGN_EXPR_MODE], "\\\\\\n", Ignore),
        r(&[ASSIGN_EXPR_MODE], "\\r?\\n", Only(Pop)),
        r(EXPRS, "{OPEN_PAREN}", Tok(Stay, T::OpenParen, Pay::None)),
        r(EXPRS, "{CLOSE_PAREN}", Tok(Stay, T::CloseParen, Pay::None)),
        r(EXPRS, "and", Tok(Stay, T::And, Pay::None)),
        r(EXPRS, "or", Tok(Stay, T::Or, Pay::None)),
        r(EXPRS, "not", Tok(Stay, T::Not, Pay::None)),
        r(EXPRS, "defined", Tok(Stay, T::Defined, Pay::None)),
        r(EXPRS, "{EQ_OP}", Tok(Stay, T::EqOp, Pay::None)),
        r(EXPRS, "{NE_OP}", Tok(Stay, T::NeOp, Pay::None)),
        r(EXPRS, "{IN_OP}", Tok(Stay, T::InOp, Pay::None)),
        r(EXPRS, "{GT}", Tok(Stay, T::Gt, Pay::None)),
        r(EXPRS, "{GT_EQUAL}", Tok(Stay, T::Ge, Pay::None)),
        r(EXPRS, "{LT}", Tok(Stay, T::Lt, Pay::None)),
        r(EXPRS, "{LT_EQUAL}", Tok(Stay, T::Le, Pay::None)),
        r(
            EXPRS,
            "({IDS_NOASSIGN}|{LABEL}|{QUOTED_ID})",
            Tok(Stay, T::Id, Pay::Id),
        ),
        r(
            &[ASSIGN_EXPR_START],
            "{EQUALS}",
            Tok(Begin(ASSIGN_EXPR_MODE), T::Equals, Pay::None),
        ),
        r(
            &[ASSIGN_EXPR_START],
            "{ADD_ASSIGN}",
            Tok(Begin(ASSIGN_EXPR_MODE), T::AddAssign, Pay::None),
        ),
        r(
            &[ASSIGN_EXPR_START],
            "{COND_ASSIGN}",
            Tok(Begin(ASSIGN_EXPR_MODE), T::CondAssign, Pay::None),
        ),
        r(
            &[ASSIGN_EXPR_START],
            "{OVERRIDE_ASSIGN}",
            Tok(Begin(ASSIGN_EXPR_MODE), T::OverrideAssign, Pay::None),
        ),
        tc(
            I,
            "#include{WS}+if{WS}+exists",
            "{WS}.*\\r?\\n",
            StartInclude { exists: true },
        ),
        tc(
            I,
            "include{WS}+if{WS}+exists",
            "{WS}",
            StartInclude { exists: true },
        ),
        tc(I, "#include", ".*\\r?\\n", StartInclude { exists: false }),
        tc(I, "include", "{WS}", StartInclude { exists: false }),
        tc(
            I,
            "all",
            "({WS}|[^[:alnum:]_])",
            Tok(Stay, T::All, Pay::None),
        ),
        r(I, "#.*\\r?\\n", Ignore),
        r(I, "{CARET}", Tok(Push(SUB_ID), T::Caret, Pay::None)),
        r(I, "{ARROW}", Tok(Push(SUB_ID_WS), T::Arrow, Pay::None)),
        r(I, "{EQUALS}", Tok(Push(ASSIGN_MODE), T::Equals, Pay::None)),
        r(I, "{PLUS}", Tok(Push(IDENTITY_VALUE), T::Plus, Pay::None)),
        r(
            I,
            "{ADD_ASSIGN}",
            Tok(Push(ASSIGN_MODE), T::AddAssign, Pay::None),
        ),
        r(
            I,
            "{COND_ASSIGN}",
            Tok(Push(ASSIGN_MODE), T::CondAssign, Pay::None),
        ),
        r(
            I,
            "{OVERRIDE_ASSIGN}",
            Tok(Push(ASSIGN_MODE), T::OverrideAssign, Pay::None),
        ),
        r(I, "{OPEN_BRACE}", Tok(Stay, T::Open, Pay::None)),
        r(I, "{CLOSE_BRACE}", Tok(Stay, T::Close, Pay::None)),
        r(I, "({LABEL}|{QUOTED_LABEL})", Tok(Stay, T::Id, Pay::Id)),
        tc(
            I,
            "({MODES})",
            "([[:space:],])",
            Tok(Stay, T::Mode, Pay::Raw),
        ),
        r(I, "{HAT}", Tok(Push(SUB_ID), T::Hat, Pay::None)),
        r(I, "{PROFILE}", Tok(Push(SUB_ID), T::Profile, Pay::None)),
        r(I, "{COLON}", Tok(Stay, T::Colon, Pay::None)),
        r(
            I,
            "{OPEN_PAREN}",
            Tok(Push(LIST_VAL_MODE), T::OpenParen, Pay::None),
        ),
        r(I, "{VARIABLE_NAME}", Keyword),
        r(EOR, "{END_OF_RULE}", EndOfRule),
        r(NEWLINE, "\\r?\\n", Ignore),
        r(UNEXPECTED, "(.|\\n)", Unexpected),
    ]
}

fn keyword(word: &[u8]) -> Option<(T, u8)> {
    let t = match word {
        b"network" => return Some((T::Network, NETWORK_MODE)),
        b"unix" => return Some((T::Unix, UNIX_MODE)),
        b"change_profile" => return Some((T::ChangeProfile, CHANGE_PROFILE_MODE)),
        b"rlimit" => return Some((T::Rlimit, RLIMIT_MODE)),
        b"mount" => return Some((T::Mount, MOUNT_MODE)),
        b"remount" => return Some((T::Remount, MOUNT_MODE)),
        b"umount" | b"unmount" => return Some((T::Umount, MOUNT_MODE)),
        b"dbus" => return Some((T::Dbus, DBUS_MODE)),
        b"signal" => return Some((T::Signal, SIGNAL_MODE)),
        b"ptrace" => return Some((T::Ptrace, PTRACE_MODE)),
        b"abi" => return Some((T::Abi, ABI_MODE)),
        b"userns" => return Some((T::Userns, USERNS_MODE)),
        b"mqueue" => return Some((T::Mqueue, MQUEUE_MODE)),
        b"if" => return Some((T::If, EXPR_MODE)),
        b"capability" => T::Capability,
        b"else" => T::Else,
        b"not" => T::Not,
        b"defined" => T::Defined,
        b"unsafe" => T::Unsafe,
        b"safe" => T::Safe,
        b"link" => T::Link,
        b"owner" | b"user" => T::Owner,
        b"other" => T::Other,
        b"subset" => T::Subset,
        b"audit" => T::Audit,
        b"deny" => T::Deny,
        b"allow" => T::Allow,
        b"prompt" => T::Prompt,
        b"set" => T::Set,
        b"alias" | b"rewrite" => T::Alias,
        b"file" => T::File,
        b"pivot_root" => T::PivotRoot,
        b"in" => T::In,
        b"send" => T::Send,
        b"receive" => T::Receive,
        b"bind" => T::Bind,
        b"read" => T::Read,
        b"write" => T::Write,
        b"eavesdrop" => T::Eavesdrop,
        b"peer" => T::Peer,
        b"trace" => T::Trace,
        b"tracedby" => T::TracedBy,
        b"readby" => T::ReadBy,
        b"delete" => T::Delete,
        b"open" => T::Open,
        b"io_uring" => T::IoUring,
        b"override_creds" => T::OverrideCreds,
        b"sqpoll" => T::Sqpoll,
        b"all" => T::All,
        b"priority" => T::Priority,
        b"and" => T::And,
        b"or" => T::Or,
        _ => return None,
    };
    Some((t, INITIAL))
}

fn scanner() -> &'static Scanner<Act> {
    static S: OnceLock<Scanner<Act>> = OnceLock::new();
    S.get_or_init(|| Scanner::build(NSTATES, DEFS, rules()))
}

/// Upstream's escape sequences: octal, `\d` decimal, `\x` hex, the C
/// letters, `\\` and `\"`. A sequence that means a pattern character is
/// kept escaped for the pattern compiler, and one that means NUL is kept
/// as written. Anything else leaves the backslash in place.
pub(crate) fn unescape(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut i = 0;
    while i < s.len() {
        if s[i] == b'\\' && i + 1 < s.len() {
            if let Some((c, end)) = escape_seq(s, i + 1) {
                if c == 0 {
                    out.extend_from_slice(&s[i..end]);
                } else if b"*?[]{}^,\\".contains(&c) {
                    out.push(b'\\');
                    out.push(c);
                } else {
                    out.push(c);
                }
                i = end;
                continue;
            }
        }
        out.push(s[i]);
        i += 1;
    }
    out
}

/// Reads at most `max` digits of `base`, stopping before the value would
/// exceed 255.
fn digits(s: &[u8], mut i: usize, base: u32, max: usize) -> (u32, usize) {
    let mut val = 0u32;
    let mut n = 0;
    while n < max && i < s.len() {
        let Some(d) = (s[i] as char).to_digit(base) else {
            break;
        };
        let next = val * base + d;
        if next > 255 {
            break;
        }
        val = next;
        i += 1;
        n += 1;
    }
    (val, n)
}

pub(crate) fn escape_seq(s: &[u8], i: usize) -> Option<(u8, usize)> {
    let c = s[i];
    if (b'0'..=b'7').contains(&c) {
        let (v, n) = digits(s, i, 8, 3);
        return Some((v as u8, i + n));
    }
    let numeric = |base, max| {
        let (v, n) = digits(s, i + 1, base, max);
        (n > 0).then_some((v as u8, i + 1 + n))
    };
    match c {
        b'\\' => Some((b'\\', i + 1)),
        b'"' => Some((b'"', i + 1)),
        b'd' => numeric(10, 3),
        b'x' => numeric(16, 2),
        b'a' => Some((7, i + 1)),
        b'e' => Some((0x1b, i + 1)),
        b'f' => Some((0x0c, i + 1)),
        b'n' => Some((b'\n', i + 1)),
        b'r' => Some((b'\r', i + 1)),
        b't' => Some((b'\t', i + 1)),
        _ => None,
    }
}

/// Upstream's `processid`: quotes stripped when the token is quoted,
/// escapes resolved either way.
pub(crate) fn process_id(s: &[u8]) -> Vec<u8> {
    if s.len() >= 2 && s[0] == b'"' && s[s.len() - 1] == b'"' {
        unescape(&s[1..s.len() - 1])
    } else {
        unescape(s)
    }
}

/// Includes may nest this deep. Upstream has no limit beyond running out
/// of file descriptors; a cycle through differently spelled paths would
/// otherwise never end.
pub const MAX_INCLUDE_DEPTH: usize = 64;
/// All files of one parse together, includes counted.
pub const MAX_TOTAL_BYTES: usize = 64 << 20;
pub const MAX_FILES: usize = 20_000;

struct Buf {
    file: u32,
    pos: usize,
}

pub(crate) struct Lexer<'r> {
    resolver: &'r mut dyn Resolver,
    pub(crate) sources: Sources,
    bufs: Vec<Buf>,
    cond: u8,
    stack: Vec<u8>,
    caches: Vec<HashSet<Vec<u8>>>,
    scratch: Scratch,
}

/// Names upstream skips when including a directory: dot files, README,
/// and leftovers of package managers and editors.
fn ignored_in_dir(name: &[u8]) -> bool {
    const SUFFIXES: &[&[u8]] = &[
        b".dpkg-new",
        b".dpkg-old",
        b".dpkg-dist",
        b".dpkg-bak",
        b".dpkg-remove",
        b".pacsave",
        b".pacnew",
        b".rpmnew",
        b".rpmsave",
        b".orig",
        b".rej",
        b"~",
    ];
    name.is_empty()
        || name[0] == b'.'
        || name == b"README"
        || SUFFIXES.iter().any(|s| name.ends_with(s))
}

fn trim(s: &[u8]) -> &[u8] {
    let start = s
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(s.len());
    let end = s
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map_or(start, |e| e + 1);
    &s[start..end.max(start)]
}

impl<'r> Lexer<'r> {
    pub(crate) fn new(resolver: &'r mut dyn Resolver, name: &str, text: Vec<u8>) -> Lexer<'r> {
        let mut sources = Sources::default();
        let file = sources.add(name.to_string(), text);
        Lexer {
            resolver,
            sources,
            bufs: vec![Buf { file, pos: 0 }],
            cond: INITIAL,
            stack: Vec::new(),
            caches: vec![HashSet::new()],
            scratch: scanner().scratch(),
        }
    }

    /// A profile block starts with a fresh record of what was included,
    /// and the enclosing block's record comes back when it ends.
    pub(crate) fn enter_block(&mut self) {
        self.caches.push(HashSet::new());
    }

    pub(crate) fn leave_block(&mut self) {
        if self.caches.len() > 1 {
            self.caches.pop();
        }
    }

    fn error(&self, span: Span, msg: impl Into<String>) -> Error {
        self.sources.error_at(span, msg)
    }

    fn push(&mut self, to: u8, span: Span) -> Result<(), Error> {
        if self.stack.len() > MAX_TOTAL_BYTES {
            return Err(self.error(span, "lexer state stack overflow"));
        }
        self.stack.push(self.cond);
        self.cond = to;
        Ok(())
    }

    fn pop(&mut self, span: Span) -> Result<(), Error> {
        match self.stack.pop() {
            Some(c) => {
                self.cond = c;
                Ok(())
            }
            None => Err(self.error(span, "start-condition stack underflow")),
        }
    }

    fn apply(&mut self, op: Op, span: Span) -> Result<(), Error> {
        match op {
            Op::Stay => Ok(()),
            Op::Push(s) => self.push(s, span),
            Op::Pop => self.pop(span),
            Op::Begin(s) => {
                self.cond = s;
                Ok(())
            }
        }
    }

    fn open_buffer(&mut self, name: &[u8], text: Vec<u8>, span: Span) -> Result<(), Error> {
        if self.bufs.len() >= MAX_INCLUDE_DEPTH {
            return Err(self.error(span, "includes nested too deeply"));
        }
        if self.sources.len() >= MAX_FILES
            || self.sources.total_bytes() + text.len() > MAX_TOTAL_BYTES
        {
            return Err(self.error(span, "too much included text"));
        }
        let file = self
            .sources
            .add(String::from_utf8_lossy(name).into_owned(), text);
        self.bufs.push(Buf { file, pos: 0 });
        Ok(())
    }

    fn cached(&self, path: &[u8]) -> bool {
        self.caches.last().is_some_and(|c| c.contains(path))
    }

    fn remember(&mut self, path: Vec<u8>) {
        if let Some(c) = self.caches.last_mut() {
            c.insert(path);
        }
    }

    fn include(
        &mut self,
        name: &[u8],
        search: bool,
        exists: bool,
        span: Span,
    ) -> Result<(), Error> {
        let mut found: Option<(Vec<u8>, Opened)> = None;
        if search {
            let dirs: Vec<Vec<u8>> = self.resolver.search_path().to_vec();
            for dir in dirs {
                let mut full = dir;
                full.push(b'/');
                full.extend_from_slice(name);
                if self.cached(&full) {
                    return Ok(());
                }
                match self.resolver.open(&full) {
                    Opened::NotFound => continue,
                    o => {
                        self.remember(full.clone());
                        found = Some((full, o));
                        break;
                    }
                }
            }
        } else if self.cached(name) {
            return Ok(());
        } else {
            match self.resolver.open(name) {
                Opened::NotFound => {}
                o => {
                    self.remember(name.to_vec());
                    found = Some((name.to_vec(), o));
                }
            }
        }
        let Some((full, opened)) = found else {
            if exists {
                return Ok(());
            }
            return Err(self.error(
                span,
                format!("Could not open '{}'", String::from_utf8_lossy(name)),
            ));
        };
        match opened {
            Opened::NotFound => unreachable!(),
            Opened::File(text) => self.open_buffer(&full, text, span),
            Opened::Dir(mut names) => {
                names.sort();
                for entry in names {
                    if ignored_in_dir(&entry) {
                        continue;
                    }
                    let mut path = full.clone();
                    path.push(b'/');
                    path.extend_from_slice(&entry);
                    if self.cached(&path) {
                        continue;
                    }
                    match self.resolver.open(&path) {
                        Opened::File(text) => {
                            self.remember(path.clone());
                            self.open_buffer(&path, text, span)?;
                        }
                        Opened::Dir(_) => {}
                        Opened::NotFound => {
                            return Err(self.error(
                                span,
                                format!(
                                    "Could not open '{}' in '{}'",
                                    String::from_utf8_lossy(&path),
                                    String::from_utf8_lossy(name)
                                ),
                            ))
                        }
                    }
                }
                Ok(())
            }
        }
    }

    pub(crate) fn next(&mut self) -> Result<Token, Error> {
        loop {
            let Some(top) = self.bufs.last() else {
                return Ok(Token {
                    t: T::Eof,
                    text: Vec::new(),
                    span: Span::default(),
                });
            };
            let (file, pos) = (top.file, top.pos);
            let span = Span {
                file,
                offset: pos as u32,
            };
            let text = self.sources.text(file);
            if pos >= text.len() {
                self.bufs.pop();
                if self.bufs.is_empty() {
                    return Ok(Token {
                        t: T::Eof,
                        text: Vec::new(),
                        span,
                    });
                }
                continue;
            }
            let rest = &text[pos..];
            let Some(m) = scanner().next(self.cond, rest, &mut self.scratch) else {
                return Err(self.error(span, "flex scanner jammed"));
            };
            let act = *m.action;
            let len = m.len;
            let matched = rest[..len].to_vec();
            if let Some(b) = self.bufs.last_mut() {
                b.pos += len;
            }
            let tok = |t: T, text: Vec<u8>| Token { t, text, span };
            match act {
                Act::Ignore => {}
                Act::Only(op) => self.apply(op, span)?,
                Act::Tok(op, t, pay) => {
                    self.apply(op, span)?;
                    let text = match pay {
                        Pay::None => matched,
                        Pay::Id => process_id(&matched),
                        Pay::Raw => matched,
                    };
                    return Ok(tok(t, text));
                }
                Act::Identities => {
                    if self.cond == IDENTITY_VALUE {
                        self.cond = EXTCOND_MODE;
                    } else {
                        self.push(EXTCOND_MODE, span)?;
                    }
                    return Ok(tok(T::Identities, process_id(&matched)));
                }
                Act::StartInclude { exists } => {
                    self.push(if exists { INCLUDE_EXISTS } else { INCLUDE }, span)?;
                }
                Act::IncludeName => {
                    let lt = matched[0] == b'<';
                    let inner = if lt {
                        &matched[1..matched.len() - 1]
                    } else {
                        &matched[..]
                    };
                    let name = process_id(trim(inner));
                    if self.cond == ABI_MODE {
                        return Ok(tok(if lt { T::Id } else { T::Value }, name));
                    }
                    let exists = self.cond == INCLUDE_EXISTS;
                    self.include(&name, lt, exists, span)?;
                    self.pop(span)?;
                }
                Act::EndOfRule => {
                    if self.cond != INITIAL {
                        self.pop(span)?;
                    }
                    return Ok(tok(T::EndOfRule, matched));
                }
                Act::Keyword => match keyword(&matched) {
                    None => return Ok(tok(T::Id, unescape(&matched))),
                    Some((t, state)) => {
                        self.push(state, span)?;
                        return Ok(tok(t, matched));
                    }
                },
                Act::RlimitWord => {
                    let t = if matched == b"infinity" {
                        T::Value
                    } else {
                        T::Id
                    };
                    return Ok(tok(t, matched));
                }
                Act::TrailingComma => {
                    return Err(
                        self.error(span, "Variable declarations do not accept trailing commas")
                    )
                }
                Act::Unexpected => {
                    return Err(self.error(
                        span,
                        format!(
                            "Lexer found unexpected character: '{}' (0x{:x})",
                            String::from_utf8_lossy(&matched).escape_debug(),
                            matched[0]
                        ),
                    ))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apparmor::source::MemResolver;

    fn lex(src: &str) -> Result<Vec<(T, String)>, Error> {
        let mut r = MemResolver::default();
        let mut l = Lexer::new(&mut r, "t", src.as_bytes().to_vec());
        let mut out = Vec::new();
        loop {
            let t = l.next()?;
            if t.t == T::Eof {
                return Ok(out);
            }
            out.push((t.t, String::from_utf8_lossy(&t.text).into_owned()));
        }
    }

    fn kinds(src: &str) -> Vec<T> {
        lex(src).unwrap().into_iter().map(|(t, _)| t).collect()
    }

    #[test]
    fn a_profile_with_file_and_network_rules() {
        use T::*;
        assert_eq!(
            kinds("profile foo /usr/bin/foo {\n  /etc/** r,\n  network inet stream,\n}\n"),
            vec![Profile, Id, Id, Open, Id, Mode, EndOfRule, Network, Id, Id, EndOfRule, Close]
        );
    }

    #[test]
    fn the_same_word_is_a_keyword_or_a_value_depending_on_the_rule() {
        assert_eq!(
            kinds("signal send,"),
            vec![T::Signal, T::Send, T::EndOfRule]
        );
        assert_eq!(kinds("ptrace send,"), vec![T::Ptrace, T::Id, T::EndOfRule]);
        assert_eq!(kinds("open"), vec![T::Open]);
    }

    #[test]
    fn modes_need_a_following_space_or_comma() {
        assert_eq!(kinds("/a rw,"), vec![T::Id, T::Mode, T::EndOfRule]);
        assert_eq!(kinds("/a rwz,")[1], T::Id);
    }

    #[test]
    fn quoted_ids_lose_their_quotes_and_escapes_resolve() {
        let t = lex("\"/a b\\x41\\*\" r,").unwrap();
        assert_eq!(t[0], (T::Id, "/a bA\\*".into()));
        assert_eq!(unescape(b"\\101\\777"), b"A\\?7".to_vec());
        assert_eq!(unescape(b"\\0\\q"), b"\\0\\q".to_vec());
    }

    #[test]
    fn assignment_values_end_at_the_line() {
        let t = lex("@{HOME} = /home/ /root/\n").unwrap();
        assert_eq!(
            t,
            vec![
                (T::SetVar, "@{HOME}".into()),
                (T::Equals, "=".into()),
                (T::Value, "/home/".into()),
                (T::Value, "/root/".into())
            ]
        );
        assert!(lex("@{A} = /a,\n").is_err());
    }

    #[test]
    fn a_comment_without_a_newline_at_the_end_is_an_error() {
        assert!(lex("# hello\n").unwrap().is_empty());
        assert!(lex("# hello").is_err());
    }

    #[test]
    fn includes_splice_text_once_per_block() {
        let mut r = MemResolver {
            search: vec![b"/d".to_vec()],
            files: vec![(b"/d/a".to_vec(), b"/x r,\n".to_vec())],
        };
        let mut l = Lexer::new(&mut r, "t", b"include <a>\ninclude <a>\n/y w,\n".to_vec());
        let mut ids = Vec::new();
        loop {
            let t = l.next().unwrap();
            if t.t == T::Eof {
                break;
            }
            if t.t == T::Id {
                ids.push(String::from_utf8(t.text).unwrap());
            }
        }
        assert_eq!(ids, vec!["/x", "/y"]);
    }

    #[test]
    fn missing_include_fails_unless_if_exists() {
        assert!(lex("include <nope>\n").is_err());
        assert!(lex("include if exists <nope>\n").unwrap().is_empty());
    }
}
