//! The grammar of profile files, recursive descent.
//!
//! It accepts the language of upstream's bison grammar, which has no
//! conflicts, so a parser that follows its productions accepts the same
//! files. Checks that upstream makes inside grammar actions but that are
//! not about structure (permission strings, names, values) are left to
//! the semantic pass, so that this stage is only the grammar.
//!
//! One thing here is not only grammar: upstream records which includes it
//! has read per profile block, and the record is swapped right after a
//! profile's `{` and right after its `}`, before the next token is read.
//! The parser tells the lexer at exactly those two points, and never looks
//! further ahead there.

use super::ast::*;
use super::lexer::{Lexer, Token, T};
use super::source::{Error, Resolver, Sources, Span};

/// Profiles, blocks and conditionals nest at most this deep. Upstream's
/// bison stack gives out at a few thousand levels; its own test suite
/// nests a hundred.
pub const MAX_NESTING: usize = 1024;

/// Parentheses in a condition nest at most this deep. Expressions are
/// parsed by recursion, so this bounds the stack.
pub const MAX_EXPR_NESTING: usize = 128;

pub struct Parsed {
    pub file: File,
    pub sources: Sources,
}

pub fn parse(resolver: &mut dyn Resolver, name: &str, text: Vec<u8>) -> Result<Parsed, Error> {
    let mut p = Parser {
        lx: Lexer::new(resolver, name, text),
        ahead: None,
        depth: 0,
    };
    match p.file() {
        Ok(file) => Ok(Parsed {
            file,
            sources: p.lx.sources,
        }),
        Err(e) => Err(e),
    }
}

enum Frame {
    Profile(Profile),
    Block {
        prefix: Prefix,
        span: Span,
        items: Vec<Item>,
    },
    /// The open block of an `if` or `else if`, after the branches of the
    /// same chain that are already closed.
    Then {
        chain: Vec<(Expr, Span, Vec<Item>)>,
        cond: Expr,
        span: Span,
        items: Vec<Item>,
    },
    Else {
        chain: Vec<(Expr, Span, Vec<Item>)>,
        items: Vec<Item>,
    },
}

impl Frame {
    fn items(&mut self) -> &mut Vec<Item> {
        match self {
            Frame::Profile(p) => &mut p.body,
            Frame::Block { items, .. } | Frame::Then { items, .. } | Frame::Else { items, .. } => {
                items
            }
        }
    }
}

fn build_if(chain: Vec<(Expr, Span, Vec<Item>)>, last: Option<Vec<Item>>) -> If {
    let mut otherwise = last.map(Else::Block);
    let mut built = None;
    for (cond, span, then) in chain.into_iter().rev() {
        if let Some(inner) = built.take() {
            otherwise = Some(Else::If(Box::new(inner)));
        }
        built = Some(If {
            cond,
            then,
            otherwise: otherwise.take(),
            span,
        });
    }
    built.expect("an if chain has a first branch")
}

struct Parser<'r> {
    lx: Lexer<'r>,
    ahead: Option<Token>,
    depth: usize,
}

fn describe(t: T) -> String {
    format!("{t:?}")
}

impl Parser<'_> {
    fn peek(&mut self) -> Result<T, Error> {
        if self.ahead.is_none() {
            self.ahead = Some(self.lx.next()?);
        }
        Ok(self.ahead.as_ref().map(|t| t.t).unwrap_or(T::Eof))
    }

    fn bump(&mut self) -> Result<Token, Error> {
        self.peek()?;
        Ok(self.ahead.take().expect("peeked"))
    }

    fn at(&mut self, t: T) -> Result<bool, Error> {
        Ok(self.peek()? == t)
    }

    fn eat(&mut self, t: T) -> Result<Option<Token>, Error> {
        if self.peek()? == t {
            Ok(Some(self.bump()?))
        } else {
            Ok(None)
        }
    }

    fn unexpected(&mut self, expecting: &str) -> Error {
        let (t, span, text) = match &self.ahead {
            Some(tok) => (tok.t, tok.span, tok.text.clone()),
            None => (T::Eof, Span::default(), Vec::new()),
        };
        let what = if t == T::Eof {
            "end of input".to_string()
        } else {
            format!("{} '{}'", describe(t), String::from_utf8_lossy(&text))
        };
        self.lx.sources.error_at(
            span,
            format!("syntax error, unexpected {what}, expecting {expecting}"),
        )
    }

    fn expect(&mut self, t: T) -> Result<Token, Error> {
        if self.peek()? == t {
            self.bump()
        } else {
            Err(self.unexpected(&describe(t)))
        }
    }

    fn enter_expr(&mut self) -> Result<(), Error> {
        self.depth += 1;
        if self.depth > MAX_EXPR_NESTING {
            let span = self.ahead.as_ref().map(|t| t.span).unwrap_or_default();
            return Err(self
                .lx
                .sources
                .error_at(span, "expression nested too deeply"));
        }
        Ok(())
    }

    fn leave_expr(&mut self) {
        self.depth -= 1;
    }

    fn file(&mut self) -> Result<File, Error> {
        let mut f = File::default();
        loop {
            match self.peek()? {
                T::Alias => {
                    let span = self.bump()?.span;
                    let from = self.expect(T::Id)?.text;
                    self.expect(T::Arrow)?;
                    let to = self.expect(T::Id)?.text;
                    self.expect(T::EndOfRule)?;
                    f.preamble.push(Preamble::Alias { from, to, span });
                }
                T::SetVar => {
                    let tok = self.bump()?;
                    let op = self.assign_op()?;
                    let mut values = vec![self.expect(T::Value)?.text];
                    while self.at(T::Value)? {
                        values.push(self.bump()?.text);
                    }
                    f.preamble.push(Preamble::SetVar {
                        name: tok.text,
                        op,
                        values,
                        span: tok.span,
                    });
                }
                T::BoolVar => {
                    let tok = self.bump()?;
                    let op = self.assign_op()?;
                    let expr = self.expr()?;
                    f.preamble.push(Preamble::BoolVar {
                        name: tok.text,
                        op,
                        expr,
                        span: tok.span,
                    });
                }
                T::Abi => f.preamble.push(Preamble::Abi(self.abi()?)),
                _ => break,
            }
        }
        self.body(&mut f.profiles)?;
        Ok(f)
    }

    fn assign_op(&mut self) -> Result<AssignOp, Error> {
        let op = match self.peek()? {
            T::Equals => AssignOp::Set,
            T::AddAssign => AssignOp::Add,
            T::CondAssign => AssignOp::SetIfUnset,
            T::OverrideAssign => AssignOp::Override,
            _ => return Err(self.unexpected("an assignment")),
        };
        self.bump()?;
        Ok(op)
    }

    fn abi(&mut self) -> Result<Abi, Error> {
        let span = self.expect(T::Abi)?.span;
        let (name, search) = match self.peek()? {
            T::Id => (self.bump()?.text, true),
            T::Value => (self.bump()?.text, false),
            _ => return Err(self.unexpected("an abi name")),
        };
        self.expect(T::EndOfRule)?;
        Ok(Abi { name, search, span })
    }

    /// Everything up to and including a profile's `{`.
    fn profile_head(&mut self, keyword: ProfileKeyword) -> Result<Profile, Error> {
        let name_tok = self.expect(T::Id)?;
        let attachment = match self.peek()? {
            T::Id | T::SetVar => Some(self.bump()?.text),
            _ => None,
        };
        let xattrs = if self.at(T::CondListId)? {
            Some(self.cond_list()?)
        } else {
            None
        };
        let mut identities = Vec::new();
        while self.eat(T::Plus)?.is_some() {
            self.expect(T::Identities)?;
            self.expect(T::Equals)?;
            self.expect(T::OpenParen)?;
            identities.push(self.expect(T::Value)?.text);
            while self.at(T::Value)? {
                identities.push(self.bump()?.text);
            }
            self.expect(T::CloseParen)?;
        }
        let mut flags = Vec::new();
        let has_flags = match self.peek()? {
            T::Flags => {
                self.bump()?;
                self.expect(T::Equals)?;
                true
            }
            T::OpenParen => true,
            _ => false,
        };
        if has_flags {
            self.expect(T::OpenParen)?;
            flags.push(self.expect(T::Value)?.text);
            while self.at(T::Value)? {
                flags.push(self.bump()?.text);
            }
            self.expect(T::CloseParen)?;
        }
        self.expect(T::Open)?;
        self.lx.enter_block();
        Ok(Profile {
            keyword,
            name: name_tok.text,
            attachment,
            xattrs,
            identities,
            flags,
            body: Vec::new(),
            span: name_tok.span,
        })
    }

    fn push_frame(&mut self, stack: &mut Vec<Frame>, f: Frame) -> Result<(), Error> {
        if stack.len() >= MAX_NESTING {
            let span = self.ahead.as_ref().map(|t| t.span).unwrap_or_default();
            return Err(self.lx.sources.error_at(span, "nested too deeply"));
        }
        stack.push(f);
        Ok(())
    }

    /// The profiles of a file and everything in them. Nesting is kept on
    /// an explicit stack, so input decides heap use, never stack depth.
    fn body(&mut self, profiles: &mut Vec<Profile>) -> Result<(), Error> {
        let mut stack: Vec<Frame> = Vec::new();
        loop {
            let t = self.peek()?;
            if stack.is_empty() {
                let keyword = match t {
                    T::Eof => return Ok(()),
                    T::Profile => {
                        self.bump()?;
                        ProfileKeyword::Profile
                    }
                    T::Caret | T::Hat => {
                        self.bump()?;
                        ProfileKeyword::Hat
                    }
                    T::Id => ProfileKeyword::None,
                    _ => return Err(self.unexpected("a profile")),
                };
                let head = self.profile_head(keyword)?;
                self.push_frame(&mut stack, Frame::Profile(head))?;
                continue;
            }
            if t == T::Close {
                self.bump()?;
                let item = match stack.pop().expect("nonempty") {
                    Frame::Profile(p) => {
                        self.lx.leave_block();
                        if stack.is_empty() {
                            profiles.push(p);
                            continue;
                        }
                        if p.keyword == ProfileKeyword::Hat {
                            Item::Hat(p)
                        } else {
                            Item::Child(p)
                        }
                    }
                    Frame::Block {
                        prefix,
                        span,
                        items,
                    } => Item::Block {
                        prefix,
                        items,
                        span,
                    },
                    Frame::Then {
                        mut chain,
                        cond,
                        span,
                        items,
                    } => {
                        chain.push((cond, span, items));
                        if self.eat(T::Else)?.is_some() {
                            if self.at(T::If)? {
                                let span = self.bump()?.span;
                                let cond = self.expr()?;
                                self.expect(T::Open)?;
                                self.push_frame(
                                    &mut stack,
                                    Frame::Then {
                                        chain,
                                        cond,
                                        span,
                                        items: Vec::new(),
                                    },
                                )?;
                            } else {
                                self.expect(T::Open)?;
                                self.push_frame(
                                    &mut stack,
                                    Frame::Else {
                                        chain,
                                        items: Vec::new(),
                                    },
                                )?;
                            }
                            continue;
                        }
                        Item::If(build_if(chain, None))
                    }
                    Frame::Else { chain, items } => Item::If(build_if(chain, Some(items))),
                };
                stack.last_mut().expect("parent").items().push(item);
                continue;
            }
            match t {
                T::Abi => {
                    let a = self.abi()?;
                    stack.last_mut().expect("frame").items().push(Item::Abi(a));
                }
                T::Caret | T::Hat | T::Profile => {
                    self.bump()?;
                    let keyword = if t == T::Profile {
                        ProfileKeyword::Profile
                    } else {
                        ProfileKeyword::Hat
                    };
                    let head = self.profile_head(keyword)?;
                    self.push_frame(&mut stack, Frame::Profile(head))?;
                }
                T::If => {
                    let span = self.bump()?.span;
                    let cond = self.expr()?;
                    self.expect(T::Open)?;
                    self.push_frame(
                        &mut stack,
                        Frame::Then {
                            chain: Vec::new(),
                            cond,
                            span,
                            items: Vec::new(),
                        },
                    )?;
                }
                T::Set => {
                    let r = self.rlimit()?;
                    stack.last_mut().expect("frame").items().push(r);
                }
                T::Eof => return Err(self.unexpected("a rule or '}'")),
                _ => {
                    let span = self.ahead.as_ref().map(|t| t.span).unwrap_or_default();
                    let prefix = self.prefix()?;
                    if self.eat(T::Open)?.is_some() {
                        self.push_frame(
                            &mut stack,
                            Frame::Block {
                                prefix,
                                span,
                                items: Vec::new(),
                            },
                        )?;
                    } else {
                        let rule = self.rule()?;
                        stack.last_mut().expect("frame").items().push(Item::Rule {
                            prefix,
                            rule,
                            span,
                        });
                    }
                }
            }
        }
    }

    fn rlimit(&mut self) -> Result<Item, Error> {
        let span = self.expect(T::Set)?.span;
        self.expect(T::Rlimit)?;
        let resource = self.expect(T::Id)?.text;
        self.expect(T::Le)?;
        let value = self.expect(T::Value)?.text;
        let unit = match self.eat(T::Id)? {
            Some(t) => Some(t.text),
            None => None,
        };
        self.expect(T::EndOfRule)?;
        Ok(Item::Rlimit {
            resource,
            value,
            unit,
            span,
        })
    }

    fn prefix(&mut self) -> Result<Prefix, Error> {
        let mut p = Prefix::default();
        if let Some(t) = self.eat(T::Priority)? {
            self.expect(T::Equals)?;
            let v = self.expect(T::Value)?.text;
            p.priority = Some((v, t.span));
        }
        if self.eat(T::Audit)?.is_some() {
            p.audit = true;
        }
        p.mode = match self.peek()? {
            T::Allow => RuleMode::Allow,
            T::Deny => RuleMode::Deny,
            T::Prompt => RuleMode::Prompt,
            _ => RuleMode::Unspecified,
        };
        if p.mode != RuleMode::Unspecified {
            self.bump()?;
        }
        p.owner = match self.peek()? {
            T::Owner => Owner::Owner,
            T::Other => Owner::Other,
            _ => Owner::Unspecified,
        };
        if p.owner != Owner::Unspecified {
            self.bump()?;
        }
        Ok(p)
    }

    /// Kept out of the recursion through blocks and profiles, so that the
    /// recursive frames stay small.
    #[inline(never)]
    fn rule(&mut self) -> Result<Rule, Error> {
        let rule = match self.peek()? {
            T::Network => self.network()?,
            T::Unix => {
                self.bump()?;
                let perms = self.opt_perms(net_perm)?;
                let conds = self.opt_conds()?;
                let peer = self.opt_cond_list()?;
                self.expect(T::EndOfRule)?;
                Rule::Unix { perms, conds, peer }
            }
            T::Dbus => {
                self.bump()?;
                let perms = self.opt_perms(dbus_perm)?;
                let conds = self.opt_conds()?;
                let peer = self.opt_cond_list()?;
                self.expect(T::EndOfRule)?;
                Rule::Dbus { perms, conds, peer }
            }
            T::Signal => {
                self.bump()?;
                let perms = self.opt_perms(signal_perm)?;
                let conds = self.opt_conds()?;
                self.expect(T::EndOfRule)?;
                Rule::Signal { perms, conds }
            }
            T::Ptrace => {
                self.bump()?;
                let perms = self.opt_perms(ptrace_perm)?;
                let conds = self.opt_conds()?;
                self.expect(T::EndOfRule)?;
                Rule::Ptrace { perms, conds }
            }
            T::Userns => {
                self.bump()?;
                let perms = self.opt_perms(userns_perm)?;
                let conds = self.opt_conds()?;
                self.expect(T::EndOfRule)?;
                Rule::Userns { perms, conds }
            }
            T::Mqueue => {
                self.bump()?;
                let perms = self.opt_perms(mqueue_perm)?;
                let conds = self.opt_conds()?;
                let name = match self.eat(T::Id)? {
                    Some(t) => Some(t.text),
                    None => None,
                };
                self.expect(T::EndOfRule)?;
                Rule::Mqueue { perms, conds, name }
            }
            T::IoUring => {
                self.bump()?;
                let perms = self.opt_perms(io_uring_perm)?;
                let conds = self.opt_conds()?;
                let list = self.opt_cond_list()?;
                self.expect(T::EndOfRule)?;
                Rule::IoUring { perms, conds, list }
            }
            T::All => {
                self.bump()?;
                self.expect(T::EndOfRule)?;
                Rule::All
            }
            T::Mount | T::Remount | T::Umount | T::PivotRoot => self.mount()?,
            T::ChangeProfile => {
                self.bump()?;
                let exec_mode = self.exec_mode()?;
                let exec = match self.eat(T::Id)? {
                    Some(t) => Some(t.text),
                    None => None,
                };
                let target = self.opt_transition()?;
                self.expect(T::EndOfRule)?;
                Rule::ChangeProfile {
                    exec_mode,
                    exec,
                    target,
                }
            }
            T::Capability => {
                self.bump()?;
                let mut names = Vec::new();
                while let Some(t) = self.eat(T::Id)? {
                    names.push((t.text, t.span));
                }
                self.expect(T::EndOfRule)?;
                Rule::Capability { names }
            }
            T::Link => {
                self.bump()?;
                let subset = self.opt_subset()?;
                let from = self.id_or_var()?;
                self.expect(T::Arrow)?;
                let to = self.id_or_var()?;
                self.expect(T::EndOfRule)?;
                Rule::Link { subset, from, to }
            }
            _ => self.file_rule()?,
        };
        Ok(rule)
    }

    fn exec_mode(&mut self) -> Result<ExecMode, Error> {
        Ok(match self.peek()? {
            T::Unsafe => {
                self.bump()?;
                ExecMode::Unsafe
            }
            T::Safe => {
                self.bump()?;
                ExecMode::Safe
            }
            _ => ExecMode::Empty,
        })
    }

    fn opt_subset(&mut self) -> Result<bool, Error> {
        Ok(match self.peek()? {
            T::Subset | T::Le => {
                self.bump()?;
                true
            }
            _ => false,
        })
    }

    fn id_or_var(&mut self) -> Result<Vec<u8>, Error> {
        match self.peek()? {
            T::Id | T::SetVar => Ok(self.bump()?.text),
            _ => Err(self.unexpected("a name or variable")),
        }
    }

    fn opt_transition(&mut self) -> Result<Option<Vec<u8>>, Error> {
        if self.eat(T::Arrow)?.is_some() {
            Ok(Some(self.id_or_var()?))
        } else {
            Ok(None)
        }
    }

    fn file_rule(&mut self) -> Result<Rule, Error> {
        let leading_file = if self.at(T::File)? {
            self.bump()?;
            if self.eat(T::EndOfRule)?.is_some() {
                return Ok(Rule::FileAll);
            }
            true
        } else {
            false
        };
        let exec_mode = self.exec_mode()?;
        match self.peek()? {
            T::Id | T::SetVar => {
                let path = self.bump()?.text;
                let perms = self.expect(T::Mode)?.text;
                if matches!(self.peek()?, T::Id | T::SetVar) {
                    return Err(self.unexpected("',' (missing an end of line character?)"));
                }
                let target = self.opt_transition()?;
                self.expect(T::EndOfRule)?;
                Ok(Rule::File {
                    leading_file,
                    exec_mode,
                    path,
                    perms,
                    perms_first: false,
                    subset: false,
                    target,
                })
            }
            T::Mode => {
                let perms = self.bump()?.text;
                let subset = self.opt_subset()?;
                let path = self.id_or_var()?;
                let target = self.opt_transition()?;
                self.expect(T::EndOfRule)?;
                Ok(Rule::File {
                    leading_file,
                    exec_mode,
                    path,
                    perms,
                    perms_first: true,
                    subset,
                    target,
                })
            }
            _ => Err(self.unexpected("a rule")),
        }
    }

    fn network(&mut self) -> Result<Rule, Error> {
        self.expect(T::Network)?;
        let perms = self.opt_perms(net_perm)?;
        let mut words = Vec::new();
        while words.len() < 2 && self.at(T::Id)? {
            words.push(self.bump()?.text);
        }
        let conds = self.opt_conds()?;
        let peer = self.opt_cond_list()?;
        self.expect(T::EndOfRule)?;
        Ok(Rule::Network {
            perms,
            words,
            conds,
            peer,
        })
    }

    fn mount(&mut self) -> Result<Rule, Error> {
        let kind = match self.bump()?.t {
            T::Mount => MountKind::Mount,
            T::Remount => MountKind::Remount,
            T::Umount => MountKind::Umount,
            _ => MountKind::PivotRoot,
        };
        let conds = self.opt_conds()?;
        let source = match self.eat(T::Id)? {
            Some(t) => Some(t.text),
            None => None,
        };
        let mut dest = None;
        let mut transition = None;
        match kind {
            MountKind::Mount => {
                if self.eat(T::Arrow)?.is_some() {
                    let dconds = self.opt_conds()?;
                    let target = self.expect(T::Id)?.text;
                    dest = Some((dconds, target));
                }
            }
            MountKind::PivotRoot => transition = self.opt_transition()?,
            _ => {}
        }
        self.expect(T::EndOfRule)?;
        Ok(Rule::Mount {
            kind,
            conds,
            source,
            dest,
            transition,
        })
    }

    /// One permission, or a parenthesised list. `accept` says which
    /// tokens the rule kind takes as a permission.
    fn opt_perms(&mut self, accept: fn(T) -> bool) -> Result<Option<Vec<PermWord>>, Error> {
        let t = self.peek()?;
        if t == T::OpenParen {
            self.bump()?;
            let mut out = Vec::new();
            loop {
                let t = self.peek()?;
                if t == T::CloseParen {
                    self.bump()?;
                    return Ok(Some(out));
                }
                if !accept(t) {
                    return Err(self.unexpected("a permission or ')'"));
                }
                let tok = self.bump()?;
                out.push(PermWord {
                    t: tok.t,
                    text: tok.text,
                    span: tok.span,
                });
            }
        }
        if accept(t) {
            let tok = self.bump()?;
            return Ok(Some(vec![PermWord {
                t: tok.t,
                text: tok.text,
                span: tok.span,
            }]));
        }
        Ok(None)
    }

    fn opt_conds(&mut self) -> Result<Vec<Cond>, Error> {
        let mut out = Vec::new();
        while self.at(T::CondId)? {
            out.push(self.cond()?);
        }
        Ok(out)
    }

    fn cond(&mut self) -> Result<Cond, Error> {
        let tok = self.expect(T::CondId)?;
        let op = match self.peek()? {
            T::Equals => CondOp::Eq,
            T::OverrideAssign => CondOp::Set,
            T::In => CondOp::In,
            _ => {
                return Ok(Cond {
                    name: tok.text,
                    op: CondOp::Bare,
                    list: false,
                    values: Vec::new(),
                    span: tok.span,
                })
            }
        };
        self.bump()?;
        let (list, values) = if op == CondOp::In || self.at(T::OpenParen)? {
            self.expect(T::OpenParen)?;
            let mut v = vec![self.expect(T::Value)?.text];
            while self.at(T::Value)? {
                v.push(self.bump()?.text);
            }
            self.expect(T::CloseParen)?;
            (true, v)
        } else {
            (false, vec![self.expect(T::Value)?.text])
        };
        Ok(Cond {
            name: tok.text,
            op,
            list,
            values,
            span: tok.span,
        })
    }

    fn cond_list(&mut self) -> Result<CondList, Error> {
        let tok = self.expect(T::CondListId)?;
        self.expect(T::Equals)?;
        self.expect(T::OpenParen)?;
        let conds = self.opt_conds()?;
        self.expect(T::CloseParen)?;
        Ok(CondList {
            name: tok.text,
            conds,
            span: tok.span,
        })
    }

    fn opt_cond_list(&mut self) -> Result<Option<CondList>, Error> {
        if self.at(T::CondListId)? {
            Ok(Some(self.cond_list()?))
        } else {
            Ok(None)
        }
    }

    fn expr(&mut self) -> Result<Expr, Error> {
        self.enter_expr()?;
        let mut terms = vec![self.term()?];
        while self.eat(T::Or)?.is_some() {
            terms.push(self.term()?);
        }
        self.leave_expr();
        Ok(if terms.len() == 1 {
            terms.pop().unwrap_or(Expr::Or(Vec::new()))
        } else {
            Expr::Or(terms)
        })
    }

    fn term(&mut self) -> Result<Expr, Error> {
        let mut factors = vec![self.not_factor()?];
        while self.eat(T::And)?.is_some() {
            factors.push(self.not_factor()?);
        }
        Ok(if factors.len() == 1 {
            factors.pop().unwrap_or(Expr::And(Vec::new()))
        } else {
            Expr::And(factors)
        })
    }

    fn not_factor(&mut self) -> Result<Expr, Error> {
        let mut nots = 0usize;
        while self.eat(T::Not)?.is_some() {
            nots += 1;
        }
        // An even number of nots evaluates the operand all the same, so
        // only the parity is kept.
        let e = self.factor()?;
        Ok(if nots % 2 == 1 {
            Expr::Not(Box::new(e))
        } else {
            e
        })
    }

    fn factor(&mut self) -> Result<Expr, Error> {
        match self.peek()? {
            T::BoolVar => {
                let t = self.bump()?;
                Ok(Expr::BoolVar(t.text, t.span))
            }
            T::Defined => {
                self.bump()?;
                match self.peek()? {
                    T::SetVar | T::BoolVar => {
                        let t = self.bump()?;
                        Ok(Expr::Defined(t.text, t.span))
                    }
                    _ => Err(self.unexpected("a variable")),
                }
            }
            T::OpenParen => {
                self.bump()?;
                let e = self.expr()?;
                self.expect(T::CloseParen)?;
                Ok(e)
            }
            T::Id | T::SetVar => {
                let t = self.bump()?;
                let lhs = Operand {
                    is_var: t.t == T::SetVar,
                    text: t.text,
                    span: t.span,
                };
                let op = match self.peek()? {
                    T::EqOp => CmpOp::Eq,
                    T::NeOp => CmpOp::Ne,
                    T::InOp => CmpOp::In,
                    T::Gt => CmpOp::Gt,
                    T::Ge => CmpOp::Ge,
                    T::Lt => CmpOp::Lt,
                    T::Le => CmpOp::Le,
                    _ => return Ok(Expr::Value(lhs)),
                };
                self.bump()?;
                let t = match self.peek()? {
                    T::Id | T::SetVar => self.bump()?,
                    _ => return Err(self.unexpected("a name or variable")),
                };
                let rhs = Operand {
                    is_var: t.t == T::SetVar,
                    text: t.text,
                    span: t.span,
                };
                Ok(Expr::Cmp(op, lhs, rhs))
            }
            _ => Err(self.unexpected("an expression")),
        }
    }
}

fn net_perm(t: T) -> bool {
    matches!(
        t,
        T::Value
            | T::Create
            | T::Bind
            | T::Listen
            | T::Accept
            | T::Connect
            | T::Shutdown
            | T::GetAttr
            | T::SetAttr
            | T::GetOpt
            | T::SetOpt
            | T::Send
            | T::Receive
            | T::Read
            | T::Write
            | T::Mode
    )
}

fn dbus_perm(t: T) -> bool {
    matches!(
        t,
        T::Value | T::Bind | T::Send | T::Receive | T::Read | T::Write | T::Eavesdrop | T::Mode
    )
}

fn signal_perm(t: T) -> bool {
    matches!(
        t,
        T::Value | T::Send | T::Receive | T::Read | T::Write | T::Mode
    )
}

fn ptrace_perm(t: T) -> bool {
    matches!(
        t,
        T::Value | T::Trace | T::TracedBy | T::Read | T::Write | T::ReadBy | T::Mode
    )
}

fn userns_perm(t: T) -> bool {
    matches!(t, T::Value | T::Create)
}

fn mqueue_perm(t: T) -> bool {
    matches!(
        t,
        T::Value
            | T::Create
            | T::Open
            | T::Delete
            | T::GetAttr
            | T::SetAttr
            | T::Write
            | T::Read
            | T::Mode
    )
}

fn io_uring_perm(t: T) -> bool {
    matches!(t, T::Value | T::OverrideCreds | T::Sqpoll)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apparmor::source::MemResolver;

    fn p(src: &str) -> Result<File, Error> {
        let mut r = MemResolver::default();
        parse(&mut r, "t", src.as_bytes().to_vec()).map(|p| p.file)
    }

    #[test]
    fn profiles_rules_and_hats() {
        let f = p(
            "@{X}=/a /b\nprofile foo /usr/bin/foo flags=(complain) {\n  \
                   /etc/** r,\n  deny owner /tmp/x w,\n  capability net_raw chown,\n  \
                   ^hat {\n    /x r,\n  }\n  network inet stream,\n}\n",
        )
        .unwrap();
        assert_eq!(f.preamble.len(), 1);
        let prof = &f.profiles[0];
        assert_eq!(prof.name, b"foo");
        assert_eq!(prof.attachment.as_deref(), Some(&b"/usr/bin/foo"[..]));
        assert_eq!(prof.flags, vec![b"complain".to_vec()]);
        assert_eq!(prof.body.len(), 5);
        assert!(matches!(prof.body[3], Item::Hat(_)));
    }

    #[test]
    fn mqueue_open_is_the_open_brace_token() {
        assert!(p("profile a { mqueue open, }").is_ok());
        assert!(p("profile a open mqueue, }").is_ok());
    }

    #[test]
    fn prefixes_have_a_fixed_order() {
        assert!(p("/a { audit deny /x r, }").is_ok());
        assert!(p("/a { deny audit /x r, }").is_err());
    }

    #[test]
    fn conditionals_nest_and_chain() {
        let f =
            p("$a = true\n/a { if $a { /x r, } else if defined @{b} { /y r, } else { } }").unwrap();
        assert!(matches!(f.profiles[0].body[0], Item::If(_)));
        let cond = |src: &str| {
            let f = p(&format!("/a {{ if {src} {{ }} }}")).unwrap();
            match &f.profiles[0].body[0] {
                Item::If(i) => i.cond.clone(),
                _ => unreachable!("an if"),
            }
        };
        assert!(matches!(cond("not not $a"), Expr::BoolVar(..)));
        assert!(matches!(cond("not not not $a"), Expr::Not(_)));
        assert!(matches!(cond("$a and $b and $c"), Expr::And(v) if v.len() == 3));
        assert!(matches!(cond("$a or $b and $c or $d"), Expr::Or(v) if v.len() == 3));
    }

    #[test]
    fn nesting_is_bounded_by_the_heap_not_the_stack() {
        let deep = |n: usize| format!("/a {{{}{}}}", " {".repeat(n), " }".repeat(n));
        assert!(p(&deep(MAX_NESTING - 1)).is_ok());
        let e = p(&deep(MAX_NESTING)).unwrap_err();
        assert!(e.message.contains("nested too deeply"), "{e}");
        let parens = format!("$a = {}true{}\n", "(".repeat(200), ")".repeat(200));
        assert!(p(&parens)
            .unwrap_err()
            .message
            .contains("nested too deeply"));
    }
}
