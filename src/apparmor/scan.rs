//! A small scanner generator with the matching rules of flex, which is
//! what upstream's lexer is written in.
//!
//! The profile language is defined by that lexer more than by any
//! document: which rule wins decides what a profile means. flex takes the
//! longest match among the rules active in the current start condition,
//! the earlier rule on a tie, and counts trailing context (`r/s`) towards
//! the length while handing only `r` to the action. This module does the
//! same over patterns written in flex's own notation, so the lexer's rule
//! table can be read against upstream's line by line.
//!
//! Matching is a breadth first simulation of a Thompson automaton, so the
//! cost of one token is linear in the bytes looked at, whatever the input.

use std::collections::HashMap;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct Class([u64; 4]);

impl Class {
    const EMPTY: Class = Class([0; 4]);

    fn single(b: u8) -> Class {
        let mut c = Class::EMPTY;
        c.insert(b);
        c
    }

    fn insert(&mut self, b: u8) {
        self.0[(b >> 6) as usize] |= 1 << (b & 63);
    }

    pub(crate) fn contains(&self, b: u8) -> bool {
        self.0[(b >> 6) as usize] & (1 << (b & 63)) != 0
    }

    fn negate(self) -> Class {
        Class([!self.0[0], !self.0[1], !self.0[2], !self.0[3]])
    }

    fn minus(self, other: Class) -> Class {
        Class([
            self.0[0] & !other.0[0],
            self.0[1] & !other.0[1],
            self.0[2] & !other.0[2],
            self.0[3] & !other.0[3],
        ])
    }

    fn union(self, other: Class) -> Class {
        Class([
            self.0[0] | other.0[0],
            self.0[1] | other.0[1],
            self.0[2] | other.0[2],
            self.0[3] | other.0[3],
        ])
    }

    fn from_fn(f: impl Fn(u8) -> bool) -> Class {
        let mut c = Class::EMPTY;
        for b in 0..=255u8 {
            if f(b) {
                c.insert(b);
            }
        }
        c
    }
}

#[derive(Clone)]
enum Node {
    Class(Class),
    Cat(Vec<Node>),
    Alt(Vec<Node>),
    Star(Box<Node>),
    Plus(Box<Node>),
    Opt(Box<Node>),
}

/// Parses flex pattern notation. Definitions are referred to as `{name}`
/// and are parenthesised on expansion, as flex does outside lex
/// compatibility mode. The patterns are part of this crate, never input,
/// so a malformed one is a bug and panics when the tables are built.
struct PatternParser<'a> {
    s: &'a [u8],
    i: usize,
    defs: &'a HashMap<&'static str, Node>,
}

impl PatternParser<'_> {
    fn parse(src: &str, defs: &HashMap<&'static str, Node>) -> Node {
        let mut p = PatternParser {
            s: src.as_bytes(),
            i: 0,
            defs,
        };
        let n = p.alt();
        assert!(p.i == p.s.len(), "trailing pattern text in {src:?}");
        n
    }

    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn alt(&mut self) -> Node {
        let mut alts = vec![self.cat()];
        while self.peek() == Some(b'|') {
            self.i += 1;
            alts.push(self.cat());
        }
        if alts.len() == 1 {
            alts.pop().unwrap()
        } else {
            Node::Alt(alts)
        }
    }

    fn cat(&mut self) -> Node {
        let mut items = Vec::new();
        while let Some(c) = self.peek() {
            if c == b'|' || c == b')' {
                break;
            }
            let mut atom = self.atom();
            while let Some(op) = self.peek() {
                atom = match op {
                    b'*' => Node::Star(Box::new(atom)),
                    b'+' => Node::Plus(Box::new(atom)),
                    b'?' => Node::Opt(Box::new(atom)),
                    _ => break,
                };
                self.i += 1;
            }
            items.push(atom);
        }
        if items.len() == 1 {
            items.pop().unwrap()
        } else {
            Node::Cat(items)
        }
    }

    fn escape(&mut self) -> u8 {
        let c = self.s[self.i];
        self.i += 1;
        match c {
            b'n' => b'\n',
            b't' => b'\t',
            b'r' => b'\r',
            b'0' => 0,
            other => other,
        }
    }

    fn atom(&mut self) -> Node {
        let c = self.s[self.i];
        self.i += 1;
        match c {
            b'(' => {
                let n = self.alt();
                assert_eq!(self.peek(), Some(b')'));
                self.i += 1;
                n
            }
            b'[' => {
                let mut cls = self.class();
                while self.s[self.i..].starts_with(b"{-}") {
                    self.i += 3;
                    let rhs = match self.atom() {
                        Node::Class(c) => c,
                        _ => panic!("{{-}} needs a character class"),
                    };
                    cls = cls.minus(rhs);
                }
                Node::Class(cls)
            }
            b'{' => {
                let end = self.s[self.i..].iter().position(|&b| b == b'}').unwrap();
                let name = std::str::from_utf8(&self.s[self.i..self.i + end]).unwrap();
                self.i += end + 1;
                self.defs
                    .get(name)
                    .unwrap_or_else(|| panic!("undefined pattern {name}"))
                    .clone()
            }
            b'"' => {
                let mut items = Vec::new();
                while self.s[self.i] != b'"' {
                    let b = if self.s[self.i] == b'\\' {
                        self.i += 1;
                        self.escape()
                    } else {
                        self.i += 1;
                        self.s[self.i - 1]
                    };
                    items.push(Node::Class(Class::single(b)));
                }
                self.i += 1;
                Node::Cat(items)
            }
            b'.' => Node::Class(Class::single(b'\n').negate()),
            b'\\' => Node::Class(Class::single(self.escape())),
            other => Node::Class(Class::single(other)),
        }
    }

    /// Called after the opening bracket; consumes the closing one.
    fn class(&mut self) -> Class {
        let negated = self.peek() == Some(b'^');
        if negated {
            self.i += 1;
        }
        let mut cls = Class::EMPTY;
        let mut first = true;
        loop {
            let c = self.s[self.i];
            if c == b']' && !first {
                self.i += 1;
                break;
            }
            first = false;
            if self.s[self.i..].starts_with(b"[:") {
                let end = self.s[self.i..]
                    .windows(2)
                    .position(|w| w == b":]")
                    .unwrap();
                let name = &self.s[self.i + 2..self.i + end];
                self.i += end + 2;
                cls = cls.union(posix(name));
                continue;
            }
            self.i += 1;
            let lo = if c == b'\\' { self.escape() } else { c };
            if self.peek() == Some(b'-') && self.s.get(self.i + 1) != Some(&b']') {
                self.i += 1;
                let c2 = self.s[self.i];
                self.i += 1;
                let hi = if c2 == b'\\' { self.escape() } else { c2 };
                for b in lo..=hi {
                    cls.insert(b);
                }
            } else {
                cls.insert(lo);
            }
        }
        if negated {
            cls.negate()
        } else {
            cls
        }
    }
}

/// flex builds its tables in the C locale, so the POSIX classes are ASCII.
fn posix(name: &[u8]) -> Class {
    match name {
        b"alpha" => Class::from_fn(|b| b.is_ascii_alphabetic()),
        b"alnum" => Class::from_fn(|b| b.is_ascii_alphanumeric()),
        b"digit" => Class::from_fn(|b| b.is_ascii_digit()),
        b"blank" => Class::from_fn(|b| b == b' ' || b == b'\t'),
        b"space" => Class::from_fn(|b| matches!(b, b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r')),
        _ => panic!("unknown POSIX class {:?}", String::from_utf8_lossy(name)),
    }
}

#[derive(Clone, Copy)]
enum St {
    Byte(u16, u32),
    Split(u32, u32),
    Match(u32),
}

const HOLE: u32 = u32::MAX;

/// One automaton for all rules. Each rule's pattern ends in its own match
/// state; rules with trailing context also keep `r` and `s` on their own
/// so the split point can be found after the winner is known.
pub(crate) struct Nfa {
    states: Vec<St>,
    classes: Vec<Class>,
}

struct Frag {
    start: u32,
    holes: Vec<usize>,
}

impl Nfa {
    fn new() -> Nfa {
        Nfa {
            states: Vec::new(),
            classes: Vec::new(),
        }
    }

    fn push(&mut self, s: St) -> u32 {
        self.states.push(s);
        (self.states.len() - 1) as u32
    }

    fn class_index(&mut self, c: Class) -> u16 {
        if let Some(i) = self.classes.iter().position(|&x| x == c) {
            return i as u16;
        }
        self.classes.push(c);
        (self.classes.len() - 1) as u16
    }

    fn patch(&mut self, holes: &[usize], to: u32) {
        for &h in holes {
            match &mut self.states[h] {
                St::Byte(_, n) => *n = to,
                St::Split(a, b) => {
                    if *a == HOLE {
                        *a = to;
                    } else {
                        *b = to;
                    }
                }
                St::Match(_) => unreachable!(),
            }
        }
    }

    fn compile(&mut self, n: &Node) -> Frag {
        match n {
            Node::Class(c) => {
                let ci = self.class_index(*c);
                let s = self.push(St::Byte(ci, HOLE));
                Frag {
                    start: s,
                    holes: vec![s as usize],
                }
            }
            Node::Cat(items) => {
                let mut iter = items.iter();
                let mut f = match iter.next() {
                    Some(first) => self.compile(first),
                    None => {
                        let s = self.push(St::Split(HOLE, HOLE));
                        return Frag {
                            start: s,
                            holes: vec![s as usize, s as usize],
                        };
                    }
                };
                for it in iter {
                    let g = self.compile(it);
                    self.patch(&f.holes, g.start);
                    f.holes = g.holes;
                }
                f
            }
            Node::Alt(alts) => {
                let mut f = self.compile(&alts[0]);
                for a in &alts[1..] {
                    let g = self.compile(a);
                    let s = self.push(St::Split(f.start, g.start));
                    f.holes.extend(g.holes);
                    f.start = s;
                }
                f
            }
            Node::Star(inner) => {
                let s = self.push(St::Split(HOLE, HOLE));
                let g = self.compile(inner);
                self.states[s as usize] = St::Split(g.start, HOLE);
                self.patch(&g.holes, s);
                Frag {
                    start: s,
                    holes: vec![s as usize],
                }
            }
            Node::Plus(inner) => {
                let g = self.compile(inner);
                let s = self.push(St::Split(g.start, HOLE));
                self.patch(&g.holes, s);
                Frag {
                    start: g.start,
                    holes: vec![s as usize],
                }
            }
            Node::Opt(inner) => {
                let g = self.compile(inner);
                let s = self.push(St::Split(g.start, HOLE));
                let mut holes = g.holes;
                holes.push(s as usize);
                Frag { start: s, holes }
            }
        }
    }

    fn add_rule(&mut self, n: &Node, rule: u32) -> u32 {
        let f = self.compile(n);
        let m = self.push(St::Match(rule));
        self.patch(&f.holes, m);
        f.start
    }
}

/// Reusable sets of automaton states, cleared in constant time.
struct StateSet {
    dense: Vec<u32>,
    gen: Vec<u32>,
    stamp: u32,
}

impl StateSet {
    fn new(n: usize) -> StateSet {
        StateSet {
            dense: Vec::with_capacity(n),
            gen: vec![0; n],
            stamp: 1,
        }
    }

    fn clear(&mut self) {
        self.dense.clear();
        self.stamp = self.stamp.wrapping_add(1);
        if self.stamp == 0 {
            self.gen.iter_mut().for_each(|g| *g = 0);
            self.stamp = 1;
        }
    }

    fn insert(&mut self, s: u32) -> bool {
        if self.gen[s as usize] == self.stamp {
            return false;
        }
        self.gen[s as usize] = self.stamp;
        self.dense.push(s);
        true
    }
}

fn closure(nfa: &Nfa, set: &mut StateSet, stack: &mut Vec<u32>, start: u32) {
    stack.push(start);
    while let Some(s) = stack.pop() {
        if !set.insert(s) {
            continue;
        }
        if let St::Split(a, b) = nfa.states[s as usize] {
            stack.push(b);
            stack.push(a);
        }
    }
}

/// Returns every length at which `start` matches a prefix of `input`,
/// shortest first.
fn match_lengths(nfa: &Nfa, start: u32, input: &[u8], scratch: &mut Scratch) -> Vec<usize> {
    let mut out = Vec::new();
    let (cur, next, stack) = (&mut scratch.a, &mut scratch.b, &mut scratch.stack);
    cur.clear();
    closure(nfa, cur, stack, start);
    let mut pos = 0;
    loop {
        if cur
            .dense
            .iter()
            .any(|&s| matches!(nfa.states[s as usize], St::Match(_)))
        {
            out.push(pos);
        }
        if pos == input.len() || cur.dense.is_empty() {
            break;
        }
        let b = input[pos];
        next.clear();
        for &s in &cur.dense {
            if let St::Byte(c, n) = nfa.states[s as usize] {
                if nfa.classes[c as usize].contains(b) {
                    closure(nfa, next, stack, n);
                }
            }
        }
        std::mem::swap(cur, next);
        pos += 1;
    }
    out
}

pub(crate) struct Scratch {
    a: StateSet,
    b: StateSet,
    stack: Vec<u32>,
}

/// A rule as written in the lexer: the start conditions it is active in,
/// its pattern, and optional trailing context.
pub(crate) struct RuleSpec<A> {
    pub states: &'static [u8],
    pub pattern: &'static str,
    pub trailing: Option<&'static str>,
    pub action: A,
}

struct Rule<A> {
    action: A,
    /// For trailing context, the starts of `r` and `s` compiled alone.
    split: Option<(u32, u32)>,
}

pub(crate) struct Scanner<A> {
    nfa: Nfa,
    rules: Vec<Rule<A>>,
    /// Start states of every rule active in each start condition.
    starts: Vec<Vec<u32>>,
}

pub(crate) struct Matched<'a, A> {
    pub action: &'a A,
    /// Bytes handed to the action, without trailing context.
    pub len: usize,
}

impl<A> Scanner<A> {
    pub(crate) fn build(
        nstates: usize,
        defs: &[(&'static str, &'static str)],
        specs: Vec<RuleSpec<A>>,
    ) -> Scanner<A> {
        let mut table: HashMap<&'static str, Node> = HashMap::new();
        for (name, pat) in defs {
            let n = PatternParser::parse(pat, &table);
            table.insert(name, n);
        }
        let mut nfa = Nfa::new();
        let mut rules = Vec::new();
        let mut starts = vec![Vec::new(); nstates];
        for (i, spec) in specs.into_iter().enumerate() {
            let r = PatternParser::parse(spec.pattern, &table);
            let (whole, split) = match spec.trailing {
                None => (r, None),
                Some(t) => {
                    let s = PatternParser::parse(t, &table);
                    let rs = nfa.add_rule(&r, u32::MAX);
                    let ss = nfa.add_rule(&s, u32::MAX);
                    (Node::Cat(vec![r, s]), Some((rs, ss)))
                }
            };
            let start = nfa.add_rule(&whole, i as u32);
            for &st in spec.states {
                starts[st as usize].push(start);
            }
            rules.push(Rule {
                action: spec.action,
                split,
            });
        }
        Scanner { nfa, rules, starts }
    }

    pub(crate) fn scratch(&self) -> Scratch {
        let n = self.nfa.states.len();
        Scratch {
            a: StateSet::new(n),
            b: StateSet::new(n),
            stack: Vec::new(),
        }
    }

    /// The rule flex would pick at the start of `input` in start condition
    /// `cond`, or None when no rule matches a nonempty prefix.
    pub(crate) fn next<'a>(
        &'a self,
        cond: u8,
        input: &[u8],
        scratch: &mut Scratch,
    ) -> Option<Matched<'a, A>> {
        let nfa = &self.nfa;
        let (cur, next, stack) = (&mut scratch.a, &mut scratch.b, &mut scratch.stack);
        cur.clear();
        for &s in &self.starts[cond as usize] {
            closure(nfa, cur, stack, s);
        }
        let mut best: Option<(usize, u32)> = None;
        let mut pos = 0;
        loop {
            if pos > 0 {
                let mut here: Option<u32> = None;
                for &s in &cur.dense {
                    if let St::Match(r) = nfa.states[s as usize] {
                        if r != u32::MAX && here.is_none_or(|h| r < h) {
                            here = Some(r);
                        }
                    }
                }
                if let Some(r) = here {
                    best = Some((pos, r));
                }
            }
            if pos == input.len() || cur.dense.is_empty() {
                break;
            }
            let b = input[pos];
            next.clear();
            for &s in &cur.dense {
                if let St::Byte(c, n) = nfa.states[s as usize] {
                    if nfa.classes[c as usize].contains(b) {
                        closure(nfa, next, stack, n);
                    }
                }
            }
            std::mem::swap(cur, next);
            pos += 1;
        }
        let (total, r) = best?;
        let rule = &self.rules[r as usize];
        let len = match rule.split {
            None => total,
            Some((rs, ss)) => {
                let ends = match_lengths(nfa, rs, &input[..total], scratch);
                ends.into_iter()
                    .rev()
                    .find(|&e| {
                        e > 0
                            && match_lengths(nfa, ss, &input[e..total], scratch).last()
                                == Some(&(total - e))
                    })
                    .expect("trailing context split")
            }
        };
        Some(Matched {
            action: &rule.action,
            len,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scanner(specs: Vec<(&'static str, Option<&'static str>, u8)>) -> Scanner<u8> {
        Scanner::build(
            1,
            &[("D", "[[:digit:]]"), ("W", "[[:blank:]]")],
            specs
                .into_iter()
                .map(|(p, t, a)| RuleSpec {
                    states: &[0],
                    pattern: p,
                    trailing: t,
                    action: a,
                })
                .collect(),
        )
    }

    fn run(s: &Scanner<u8>, input: &str) -> Option<(u8, usize)> {
        let mut sc = s.scratch();
        s.next(0, input.as_bytes(), &mut sc)
            .map(|m| (*m.action, m.len))
    }

    #[test]
    fn longest_match_wins_then_earliest_rule() {
        let s = scanner(vec![
            ("in", None, 1),
            ("[a-z]+", None, 2),
            ("{D}+", None, 3),
        ]);
        assert_eq!(run(&s, "in "), Some((1, 2)));
        assert_eq!(run(&s, "inside"), Some((2, 6)));
        assert_eq!(run(&s, "42x"), Some((3, 2)));
        assert_eq!(run(&s, "!"), None);
    }

    #[test]
    fn trailing_context_counts_for_length_but_is_not_consumed() {
        let s = scanner(vec![
            ("[a-z]+", Some("{W}*="), 1),
            ("[a-z]+{W}*=={W}*", None, 2),
        ]);
        assert_eq!(run(&s, "abc  = 1"), Some((1, 3)));
        assert_eq!(run(&s, "abc == 1"), Some((2, 7)));
    }

    #[test]
    fn classes_negation_difference_and_quotes() {
        let s = scanner(vec![
            ("[^ \\t\\n\"]{-}[=]+", None, 1),
            ("\"a\\\"b\"", None, 2),
            (".", None, 3),
        ]);
        assert_eq!(run(&s, "ab=c"), Some((1, 2)));
        assert_eq!(run(&s, "a\"bc"), Some((2, 3)));
        assert_eq!(run(&s, "=x"), Some((3, 1)));
        assert_eq!(run(&s, "\n"), None);
    }

    #[test]
    fn long_input_is_linear() {
        let s = scanner(vec![("a*b", None, 1), ("a", None, 2)]);
        let input = "a".repeat(1 << 20);
        let t = std::time::Instant::now();
        assert_eq!(run(&s, &input), Some((2, 1)));
        assert!(t.elapsed().as_secs() < 5);
    }
}
