//! The regular expression notation between the profile language and the
//! automaton: what [`super::aare`] produces and what the rule kinds build
//! by hand. Its grammar is upstream's libapparmor_re parse.y, which has
//! no conflicts; this is a recursive descent parser for the same
//! language. `?`, `{`, `}` and `$` are ordinary characters here.
//!
//! Concatenation and alternation are n-ary, so the depth of a tree is the
//! nesting of parentheses, not the length of a path.

use crate::apparmor::lexer::escape_seq;

/// A set of byte values.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct ByteSet(pub [u64; 4]);

impl ByteSet {
    pub fn insert(&mut self, b: u8) {
        self.0[(b >> 6) as usize] |= 1 << (b & 63);
    }

    pub fn contains(&self, b: u8) -> bool {
        self.0[(b >> 6) as usize] & (1 << (b & 63)) != 0
    }

    pub fn all() -> ByteSet {
        ByteSet([u64::MAX; 4])
    }

    pub fn complement(self) -> ByteSet {
        ByteSet([!self.0[0], !self.0[1], !self.0[2], !self.0[3]])
    }

    pub fn single(b: u8) -> ByteSet {
        let mut s = ByteSet::default();
        s.insert(b);
        s
    }
}

/// How a byte position was written. The kinds match the same bytes when
/// their sets are equal, but upstream treats them differently when it
/// decides whether a rule is exact and how long its shortest match is.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum SetKind {
    Char,
    Set,
    NotSet,
    Any,
}

/// What a position of the expression matches.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Sym {
    Bytes {
        set: ByteSet,
        kind: SetKind,
    },
    /// The out of band transition that separates the path from xattr
    /// values; no input byte matches it.
    Oob,
}

#[derive(Clone, Debug)]
pub enum Node {
    Eps,
    Sym(Sym),
    Cat(Vec<Node>),
    Alt(Vec<Node>),
    Star(Box<Node>),
    Plus(Box<Node>),
    /// The end of a rule, carrying the index of its permissions.
    Accept(u32),
}

impl Node {
    pub fn byte(b: u8) -> Node {
        Node::Sym(Sym::Bytes {
            set: ByteSet::single(b),
            kind: SetKind::Char,
        })
    }

    pub fn cat(mut v: Vec<Node>) -> Node {
        match v.len() {
            0 => Node::Eps,
            1 => v.pop().unwrap(),
            _ => Node::Cat(v),
        }
    }

    /// Whether the expression has no wildcard: no star, plus, `.` or
    /// negated class. Upstream lets such rules decide exec modifiers over
    /// rules with wildcards.
    pub fn is_exact(&self) -> bool {
        match self {
            Node::Eps | Node::Accept(_) | Node::Sym(Sym::Oob) => true,
            Node::Sym(Sym::Bytes { kind, .. }) => matches!(kind, SetKind::Char | SetKind::Set),
            Node::Cat(v) | Node::Alt(v) => v.iter().all(Node::is_exact),
            Node::Star(_) | Node::Plus(_) => false,
        }
    }
}

impl Node {
    /// Upstream's min_match_len, quirks kept: `.`, stars and accept
    /// nodes count zero, and a negated class counts as if it contained
    /// the out of band symbol, so nothing after it in a concatenation
    /// counts. The kernel uses this length to choose between profiles
    /// whose attachments match the same path.
    pub fn min_match_len(&self) -> usize {
        match self {
            Node::Eps | Node::Accept(_) | Node::Star(_) => 0,
            Node::Sym(Sym::Oob) => 0,
            Node::Sym(Sym::Bytes { kind, .. }) => match kind {
                SetKind::Any => 0,
                _ => 1,
            },
            Node::Plus(c) => c.min_match_len(),
            Node::Alt(v) => v.iter().map(Node::min_match_len).min().unwrap_or(0),
            Node::Cat(v) => {
                let mut len = 0;
                for c in v {
                    len += c.min_match_len();
                    if c.contains_oob() {
                        break;
                    }
                }
                len
            }
        }
    }

    fn contains_oob(&self) -> bool {
        match self {
            Node::Sym(Sym::Oob) => true,
            Node::Sym(Sym::Bytes { kind, .. }) => *kind == SetKind::NotSet,
            Node::Star(c) | Node::Plus(c) => c.contains_oob(),
            Node::Cat(v) | Node::Alt(v) => v.iter().any(Node::contains_oob),
            Node::Eps | Node::Accept(_) => false,
        }
    }
}

/// Parentheses nest at most this deep. What the profile language can
/// produce is bounded at 49 by its alternation limit.
pub const MAX_DEPTH: usize = 256;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Tok {
    Char(u8),
    Special(u8),
    End,
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
    tok: Tok,
    depth: usize,
}

impl Parser<'_> {
    fn lex(&mut self) {
        let Some(&c) = self.s.get(self.i) else {
            self.tok = Tok::End;
            return;
        };
        self.i += 1;
        self.tok = match c {
            b'*' | b'+' | b'.' | b'|' | b'^' | b'-' | b'[' | b']' | b'(' | b')' => Tok::Special(c),
            b'\\' => {
                if self.i < self.s.len() && b"*+.|^$-[](){}".contains(&self.s[self.i]) {
                    let v = self.s[self.i];
                    self.i += 1;
                    Tok::Char(v)
                } else if self.i < self.s.len() {
                    match escape_seq(self.s, self.i) {
                        Some((v, end)) => {
                            self.i = end;
                            Tok::Char(v)
                        }
                        None => Tok::Char(b'\\'),
                    }
                } else {
                    Tok::Char(b'\\')
                }
            }
            _ => Tok::Char(c),
        };
    }

    fn regex(&mut self) -> Result<Node, ()> {
        if matches!(self.tok, Tok::End | Tok::Special(b')')) {
            return Ok(Node::Eps);
        }
        self.expr()
    }

    fn expr(&mut self) -> Result<Node, ()> {
        let mut alts = Vec::new();
        if self.tok == Tok::Special(b'|') {
            alts.push(Node::Eps);
        } else {
            alts.push(self.terms()?);
        }
        while self.tok == Tok::Special(b'|') {
            self.lex();
            if self.starts_term() {
                alts.push(self.terms()?);
            } else {
                alts.push(Node::Eps);
            }
        }
        Ok(if alts.len() == 1 {
            alts.pop().unwrap()
        } else {
            Node::Alt(alts)
        })
    }

    fn starts_term(&self) -> bool {
        matches!(
            self.tok,
            Tok::Char(_)
                | Tok::Special(b'.')
                | Tok::Special(b'^')
                | Tok::Special(b'-')
                | Tok::Special(b']')
                | Tok::Special(b'[')
                | Tok::Special(b'(')
        )
    }

    fn terms(&mut self) -> Result<Node, ()> {
        let mut items = Vec::new();
        if !self.starts_term() {
            return Err(());
        }
        while self.starts_term() {
            let t = self.term()?;
            let q = match self.tok {
                Tok::Special(b'*') => {
                    self.lex();
                    Node::Star(Box::new(t))
                }
                Tok::Special(b'+') => {
                    self.lex();
                    Node::Plus(Box::new(t))
                }
                _ => t,
            };
            items.push(q);
        }
        Ok(Node::cat(items))
    }

    fn term(&mut self) -> Result<Node, ()> {
        match self.tok {
            Tok::Special(b'.') => {
                self.lex();
                Ok(Node::Sym(Sym::Bytes {
                    set: ByteSet::all(),
                    kind: SetKind::Any,
                }))
            }
            Tok::Char(c) | Tok::Special(c @ (b'^' | b'-' | b']')) => {
                self.lex();
                Ok(Node::byte(c))
            }
            Tok::Special(b'[') => {
                self.lex();
                if self.tok == Tok::Special(b'^') {
                    self.lex();
                    let set = if self.tok == Tok::Special(b'^') {
                        self.lex();
                        let mut s = self.cset_chars(ByteSet::default())?;
                        s.insert(b'^');
                        s
                    } else {
                        self.charset()?
                    };
                    self.close_class()?;
                    Ok(Node::Sym(Sym::Bytes {
                        set: set.complement(),
                        kind: SetKind::NotSet,
                    }))
                } else {
                    let set = self.charset()?;
                    self.close_class()?;
                    Ok(Node::Sym(Sym::Bytes {
                        set,
                        kind: SetKind::Set,
                    }))
                }
            }
            Tok::Special(b'(') => {
                self.depth += 1;
                if self.depth > MAX_DEPTH {
                    return Err(());
                }
                self.lex();
                let r = self.regex()?;
                if self.tok != Tok::Special(b')') {
                    return Err(());
                }
                self.lex();
                self.depth -= 1;
                Ok(r)
            }
            _ => Err(()),
        }
    }

    fn close_class(&mut self) -> Result<(), ()> {
        if self.tok != Tok::Special(b']') {
            return Err(());
        }
        self.lex();
        Ok(())
    }

    /// A character that may stand anywhere in a class.
    fn cset_char(&self) -> Option<u8> {
        match self.tok {
            Tok::Char(c) => Some(c),
            Tok::Special(c @ (b'[' | b'*' | b'+' | b'.' | b'|' | b'(' | b')')) => Some(c),
            _ => None,
        }
    }

    fn cset_char_n(&self) -> Option<u8> {
        match self.tok {
            Tok::Special(b'^') => Some(b'^'),
            _ => self.cset_char(),
        }
    }

    fn charset(&mut self) -> Result<ByteSet, ()> {
        let first = match self.tok {
            Tok::Special(c @ (b']' | b'-')) => c,
            _ => self.cset_char().ok_or(())?,
        };
        self.lex();
        let mut set = ByteSet::default();
        if self.tok == Tok::Special(b'-') {
            self.lex();
            let hi = self.cset_char_n().ok_or(())?;
            self.lex();
            range(&mut set, first, hi);
        } else {
            set.insert(first);
        }
        self.cset_chars(set)
    }

    fn cset_chars(&mut self, mut set: ByteSet) -> Result<ByteSet, ()> {
        loop {
            if self.tok == Tok::Special(b']') {
                return Ok(set);
            }
            let c = self.cset_char_n().ok_or(())?;
            self.lex();
            if self.tok == Tok::Special(b'-') {
                self.lex();
                let hi = self.cset_char_n().ok_or(())?;
                self.lex();
                range(&mut set, c, hi);
            } else {
                set.insert(c);
            }
        }
    }
}

fn range(set: &mut ByteSet, a: u8, b: u8) {
    let (lo, hi) = if a > b { (b, a) } else { (a, b) };
    for c in lo..=hi {
        set.insert(c);
    }
}

/// An expression did not parse.
#[derive(Debug, PartialEq, Eq)]
pub struct BadExpr;

/// Parses one expression. An error carries no detail, as upstream's has
/// none either: the rule it came from is what gets reported.
pub fn parse(s: &[u8]) -> Result<Node, BadExpr> {
    let mut p = Parser {
        s,
        i: 0,
        tok: Tok::End,
        depth: 0,
    };
    p.lex();
    let n = p.regex().map_err(|()| BadExpr)?;
    if p.tok != Tok::End {
        return Err(BadExpr);
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_of(n: &Node) -> ByteSet {
        match n {
            Node::Sym(Sym::Bytes { set, .. }) => *set,
            other => panic!("not a set: {other:?}"),
        }
    }

    #[test]
    fn classes_ranges_and_negation() {
        let s = set_of(&parse(b"[a-c]").unwrap());
        assert!(s.contains(b'a') && s.contains(b'c') && !s.contains(b'd'));
        let s = set_of(&parse(b"[^/\\x00]").unwrap());
        assert!(!s.contains(b'/') && !s.contains(0) && s.contains(b'a'));
        let s = set_of(&parse(b"[]a]").unwrap());
        assert!(s.contains(b']') && s.contains(b'a'));
        let s = set_of(&parse(b"[^^]").unwrap());
        assert!(!s.contains(b'^') && s.contains(b'a'));
        let s = set_of(&parse(b"[c-a]").unwrap());
        assert!(s.contains(b'b'));
    }

    #[test]
    fn what_the_grammar_refuses() {
        for bad in [&b"[a-]"[..], b"[]", b"a**", b"(a", b"a)", b"[^^-x]", b"*"] {
            assert!(parse(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
        for good in [&b""[..], b"|a", b"a|", b"a||b", b"()", b"a{1}$?"] {
            assert!(parse(good).is_ok(), "{}", String::from_utf8_lossy(good));
        }
    }

    #[test]
    fn exactness() {
        assert!(parse(b"/bin/[ab]").unwrap().is_exact());
        assert!(!parse(b"/bin/[^ab]").unwrap().is_exact());
        assert!(!parse(b"/bin/a*").unwrap().is_exact());
        assert!(!parse(b"/bin/.").unwrap().is_exact());
    }

    #[test]
    fn long_literals_stay_shallow() {
        let long = vec![b'a'; 100_000];
        match parse(&long).unwrap() {
            Node::Cat(v) => assert_eq!(v.len(), 100_000),
            _ => panic!(),
        }
    }
}
