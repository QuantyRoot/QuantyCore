//! The expression tree the automaton is built from, and upstream's
//! simplification of it.
//!
//! Upstream factors each permission group's alternation before building
//! the automaton (expr-tree.cc, simplify_tree): `ab|ac` becomes `a(b|c)`
//! and `ba|ca` becomes `(b|c)a`. The language is the same, but the subset
//! construction then tracks one position where it would have tracked one
//! per rule, and without it ordinary profiles with many `**` rules grow
//! millions of intermediate states. The steps here are upstream's, on
//! the same binary tree shape, so that what explodes upstream explodes
//! here and nothing else does.
//!
//! The tree lives in an arena so that no step recurses on its depth:
//! factoring a long list of paths builds a trie whose depth is the
//! length of a path.

use super::dfa::DfaError;
use super::regex::{Node, SetKind, Sym};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Eps,
    Sym(Sym),
    /// The end of a rule group; one node per group, shared wherever the
    /// group ends, as upstream shares its accept node.
    Accept(u32),
    Star,
    Plus,
    Cat,
    Alt,
}

#[derive(Clone, Copy, Debug)]
pub struct TNode {
    pub kind: Kind,
    pub child: [u32; 2],
}

/// The one epsilon node; upstream compares it by address.
pub const EPS: u32 = 0;

pub struct Tree {
    pub nodes: Vec<TNode>,
    accepts: Vec<(u32, u32)>,
    /// Work left for simplification before it gives up.
    budget: u64,
}

impl Tree {
    pub fn new(budget: u64) -> Tree {
        Tree {
            nodes: vec![TNode {
                kind: Kind::Eps,
                child: [0, 0],
            }],
            accepts: Vec::new(),
            budget,
        }
    }

    pub fn kind(&self, n: u32) -> Kind {
        self.nodes[n as usize].kind
    }

    pub fn c(&self, n: u32, dir: usize) -> u32 {
        self.nodes[n as usize].child[dir]
    }

    fn set(&mut self, n: u32, dir: usize, to: u32) {
        self.nodes[n as usize].child[dir] = to;
    }

    fn push(&mut self, kind: Kind, a: u32, b: u32) -> u32 {
        self.nodes.push(TNode {
            kind,
            child: [a, b],
        });
        (self.nodes.len() - 1) as u32
    }

    pub fn cat(&mut self, a: u32, b: u32) -> u32 {
        self.push(Kind::Cat, a, b)
    }

    pub fn alt(&mut self, a: u32, b: u32) -> u32 {
        self.push(Kind::Alt, a, b)
    }

    pub fn accept(&mut self, id: u32) -> u32 {
        if let Some(&(_, n)) = self.accepts.iter().find(|(a, _)| *a == id) {
            return n;
        }
        let n = self.push(Kind::Accept(id), 0, 0);
        self.accepts.push((id, n));
        n
    }

    /// Adds a parsed expression in the shape upstream's grammar gives
    /// it: concatenations and alternations nest to the left.
    pub fn add(&mut self, n: &Node) -> u32 {
        match n {
            Node::Eps => EPS,
            Node::Sym(s) => self.push(Kind::Sym(*s), 0, 0),
            Node::Accept(a) => self.accept(*a),
            Node::Star(c) => {
                let c = self.add(c);
                self.push(Kind::Star, c, 0)
            }
            Node::Plus(c) => {
                let c = self.add(c);
                self.push(Kind::Plus, c, 0)
            }
            Node::Cat(v) | Node::Alt(v) => {
                let kind = if matches!(n, Node::Cat(_)) {
                    Kind::Cat
                } else {
                    Kind::Alt
                };
                let mut acc: Option<u32> = None;
                for c in v {
                    let c = self.add(c);
                    acc = Some(match acc {
                        None => c,
                        Some(a) => self.push(kind, a, c),
                    });
                }
                acc.unwrap_or(EPS)
            }
        }
    }

    fn is(&self, n: u32, k: Kind) -> bool {
        self.kind(n) == k
    }

    fn two_child(&self, n: u32) -> bool {
        matches!(self.kind(n), Kind::Cat | Kind::Alt)
    }

    fn spend(&mut self, n: u64) -> Result<(), DfaError> {
        self.budget = self.budget.checked_sub(n).ok_or(DfaError::TooLarge)?;
        Ok(())
    }

    /// Structural equality, upstream's eq: accept nodes by identity,
    /// everything else by kind and content.
    fn eq(&mut self, a: u32, b: u32) -> Result<bool, DfaError> {
        let mut stack = vec![(a, b)];
        while let Some((x, y)) = stack.pop() {
            self.spend(1)?;
            if x == y {
                continue;
            }
            let (kx, ky) = (self.kind(x), self.kind(y));
            match (kx, ky) {
                (Kind::Eps, Kind::Eps) => {}
                (Kind::Sym(s), Kind::Sym(t)) => {
                    if s != t {
                        return Ok(false);
                    }
                }
                (Kind::Star, Kind::Star) | (Kind::Plus, Kind::Plus) => {
                    stack.push((self.c(x, 0), self.c(y, 0)))
                }
                (Kind::Cat, Kind::Cat) | (Kind::Alt, Kind::Alt) => {
                    stack.push((self.c(x, 1), self.c(y, 1)));
                    stack.push((self.c(x, 0), self.c(y, 0)));
                }
                _ => return Ok(false),
            }
        }
        Ok(true)
    }

    fn eps_pair(&self, t: u32) -> u32 {
        if self.two_child(t) && self.c(t, 0) == EPS && self.c(t, 1) == EPS {
            EPS
        } else {
            t
        }
    }

    fn rotate(&mut self, t: u32, dir: usize) {
        let left = self.c(t, dir);
        self.set(t, dir, self.c(left, dir));
        self.set(left, dir, self.c(left, 1 - dir));
        self.set(left, 1 - dir, self.c(t, 1 - dir));
        let l = self.eps_pair(left);
        self.set(t, 1 - dir, l);
    }

    fn normalize_eps(&mut self, t: u32, dir: usize) -> bool {
        if self.c(t, dir) == EPS && self.c(t, 1 - dir) != EPS {
            let c = self.eps_pair(self.c(t, 1 - dir));
            self.set(t, 1 - dir, EPS);
            self.set(t, dir, c);
            return true;
        }
        false
    }

    /// Upstream's normalize: for `dir` 0, `(a|b)|c` becomes `a|(b|c)`,
    /// `(ab)c` becomes `a(bc)` and `E|a` becomes `a|E`; `dir` 1 mirrors.
    fn normalize(&mut self, root: u32, dir: usize) -> Result<(), DfaError> {
        let mut stack = vec![root];
        while let Some(t) = stack.pop() {
            self.spend(1)?;
            match self.kind(t) {
                Kind::Cat | Kind::Alt => {
                    let k = self.kind(t);
                    loop {
                        self.spend(1)?;
                        if self.normalize_eps(t, dir) {
                            continue;
                        }
                        let d = self.c(t, dir);
                        if self.is(d, k) {
                            self.rotate(t, dir);
                        } else if k == Kind::Alt
                            && is_charset(self.kind(d))
                            && is_char(self.kind(self.c(t, 1 - dir)))
                        {
                            let o = self.c(t, 1 - dir);
                            self.set(t, dir, o);
                            self.set(t, 1 - dir, d);
                        } else {
                            break;
                        }
                    }
                    stack.push(self.c(t, 1 - dir));
                    stack.push(self.c(t, dir));
                }
                Kind::Star | Kind::Plus => stack.push(self.c(t, 0)),
                _ => {}
            }
        }
        Ok(())
    }

    fn basic_alt_factor(&mut self, t: u32, dir: usize) -> Result<u32, DfaError> {
        let nd = 1 - dir;
        if !self.is(t, Kind::Alt) {
            return Ok(t);
        }
        let (l, r) = (self.c(t, dir), self.c(t, nd));
        if self.eq(l, r)? {
            return Ok(l);
        }
        if self.is(l, Kind::Cat)
            && self.is(r, Kind::Cat)
            && self.eq(self.c(l, dir), self.c(r, dir))?
        {
            self.set(t, dir, self.c(l, nd));
            self.set(t, nd, self.c(r, nd));
            self.set(l, nd, t);
            return Ok(l);
        }
        if self.is(r, Kind::Cat) && self.eq(l, self.c(r, dir))? {
            self.set(t, dir, self.c(r, nd));
            self.set(t, nd, EPS);
            self.set(r, nd, t);
            return Ok(r);
        }
        if self.is(l, Kind::Cat) && self.eq(self.c(l, dir), r)? {
            self.set(t, dir, self.c(l, nd));
            self.set(t, nd, EPS);
            self.set(l, nd, t);
            return Ok(l);
        }
        Ok(t)
    }

    fn basic_simplify(&mut self, t: u32, dir: usize) -> Result<u32, DfaError> {
        if self.is(t, Kind::Cat) && self.c(t, 1 - dir) == EPS {
            return Ok(self.c(t, dir));
        }
        self.basic_alt_factor(t, dir)
    }

    /// Upstream's simplify_tree_base, children first, without recursion.
    fn simplify_base(
        &mut self,
        root: u32,
        dir: usize,
        modified: &mut bool,
    ) -> Result<u32, DfaError> {
        const ROOT: u32 = u32::MAX;
        // (node, parent, slot, children done)
        let mut stack = vec![(root, ROOT, 0usize, false)];
        let mut result = root;
        while let Some((t, parent, slot, done)) = stack.pop() {
            self.spend(1)?;
            if !done {
                if matches!(self.kind(t), Kind::Sym(_) | Kind::Accept(_) | Kind::Eps) {
                    continue;
                }
                stack.push((t, parent, slot, true));
                if self.two_child(t) {
                    stack.push((self.c(t, 1), t, 1, false));
                }
                stack.push((self.c(t, 0), t, 0, false));
                continue;
            }
            let s = self.simplify_node(t, dir, modified)?;
            if s != t {
                if parent == ROOT {
                    result = s;
                } else {
                    self.set(parent, slot, s);
                }
                *modified = true;
            }
        }
        Ok(result)
    }

    fn simplify_node(
        &mut self,
        mut t: u32,
        dir: usize,
        modified: &mut bool,
    ) -> Result<u32, DfaError> {
        let nd = 1 - dir;
        let mut first = true;
        loop {
            if !first {
                *modified = true;
            }
            first = false;
            self.spend(1)?;
            let tmp = self.basic_simplify(t, dir)?;
            if tmp != t {
                t = tmp;
                continue;
            }
            if !self.is(t, Kind::Alt) || !self.is(self.c(t, nd), Kind::Alt) {
                break;
            }
            // a | (a | b) -> (a | b); upstream's `continue` here is in
            // the inner loop, so the walk goes on from where it was.
            let mut p = t;
            let mut i = self.c(t, nd);
            while self.is(i, Kind::Alt) {
                self.spend(1)?;
                if self.eq(self.c(t, dir), self.c(i, dir))? {
                    t = self.c(t, nd);
                }
                p = i;
                i = self.c(i, nd);
            }
            if self.eq(self.c(t, dir), self.c(p, nd))? {
                t = self.c(t, nd);
                continue;
            }
            // Factor the front: ab | (ac | ...) -> a(b|c) | (...).
            let mut count = 0;
            let mut subject = self.c(t, dir);
            let mut a = if self.is(subject, Kind::Cat) {
                self.c(subject, dir)
            } else {
                subject
            };
            let mut pp = t;
            p = t;
            i = self.c(t, nd);
            while self.is(i, Kind::Alt) {
                self.spend(1)?;
                let id = self.c(i, dir);
                let hit =
                    (self.is(id, Kind::Cat) && self.eq(a, self.c(id, dir))?) || self.eq(a, id)?;
                if hit {
                    self.set(p, nd, self.c(i, nd));
                    self.set(i, nd, subject);
                    subject = self.basic_simplify(i, dir)?;
                    a = if self.is(subject, Kind::Cat) {
                        self.c(subject, dir)
                    } else {
                        subject
                    };
                    i = self.c(p, nd);
                    count += 1;
                } else {
                    pp = p;
                    p = i;
                    i = self.c(i, nd);
                }
            }
            let hit = (self.is(i, Kind::Cat) && self.eq(a, self.c(i, dir))?) || self.eq(a, i)?;
            if hit {
                count += 1;
                if t == p {
                    self.set(t, dir, subject);
                    t = self.basic_simplify(t, dir)?;
                } else {
                    self.set(t, dir, self.c(p, dir));
                    self.set(p, dir, subject);
                    let s = self.basic_simplify(p, dir)?;
                    self.set(pp, nd, s);
                }
            } else {
                self.set(t, dir, i);
                self.set(p, nd, subject);
            }
            if count == 0 {
                break;
            }
        }
        Ok(t)
    }

    /// Upstream's simplify_tree with its default options: right
    /// normalization and factoring until nothing changes, then left.
    pub fn simplify(&mut self, mut t: u32) -> Result<u32, DfaError> {
        for dir in [1usize, 0] {
            loop {
                let mut modified = false;
                self.normalize(t, dir)?;
                t = self.simplify_base(t, dir, &mut modified)?;
                if !modified {
                    break;
                }
            }
        }
        Ok(t)
    }

    /// Upstream's min_match_len, quirks kept: `.`, stars and accept
    /// nodes count zero, a negated class counts as if it contained the
    /// out of band symbol, and nothing right of a node that contains it
    /// counts. Saturates instead of overflowing.
    pub fn min_match_len(&self, root: u32) -> usize {
        // Post order: (node, children done).
        let mut stack = vec![(root, false)];
        let mut vals: Vec<(usize, bool)> = Vec::new();
        while let Some((t, done)) = stack.pop() {
            let k = self.kind(t);
            if !done {
                match k {
                    Kind::Cat | Kind::Alt => {
                        stack.push((t, true));
                        stack.push((self.c(t, 1), false));
                        stack.push((self.c(t, 0), false));
                    }
                    Kind::Star | Kind::Plus => {
                        stack.push((t, true));
                        stack.push((self.c(t, 0), false));
                    }
                    Kind::Eps | Kind::Accept(_) => vals.push((0, false)),
                    Kind::Sym(Sym::Oob) => vals.push((0, true)),
                    Kind::Sym(Sym::Bytes { kind, .. }) => vals.push(match kind {
                        SetKind::Any => (0, false),
                        SetKind::NotSet => (1, true),
                        _ => (1, false),
                    }),
                }
                continue;
            }
            match k {
                Kind::Cat | Kind::Alt => {
                    let (r, ro) = vals.pop().unwrap_or((0, false));
                    let (l, lo) = vals.pop().unwrap_or((0, false));
                    let len = if k == Kind::Alt {
                        l.min(r)
                    } else if lo {
                        l
                    } else {
                        l.saturating_add(r)
                    };
                    vals.push((len, lo || ro));
                }
                Kind::Star => {
                    let (_, o) = vals.pop().unwrap_or((0, false));
                    vals.push((0, o));
                }
                _ => {}
            }
        }
        vals.pop().map(|v| v.0).unwrap_or(0)
    }
}

fn is_char(k: Kind) -> bool {
    matches!(
        k,
        Kind::Sym(Sym::Oob)
            | Kind::Sym(Sym::Bytes {
                kind: SetKind::Char,
                ..
            })
    )
}

fn is_charset(k: Kind) -> bool {
    matches!(
        k,
        Kind::Sym(Sym::Bytes {
            kind: SetKind::Set,
            ..
        })
    )
}

#[cfg(test)]
mod tests {
    use super::super::regex::parse;
    use super::*;

    fn tree_of(res: &[&str]) -> (Tree, u32) {
        let mut t = Tree::new(1 << 30);
        let mut acc = None;
        for r in res {
            let n = t.add(&parse(r.as_bytes()).unwrap());
            acc = Some(match acc {
                None => n,
                Some(a) => t.alt(a, n),
            });
        }
        let root = acc.unwrap();
        (t, root)
    }

    fn leaves(t: &Tree, root: u32) -> usize {
        let mut stack = vec![root];
        let mut n = 0;
        while let Some(x) = stack.pop() {
            match t.kind(x) {
                Kind::Sym(_) => n += 1,
                Kind::Cat | Kind::Alt => {
                    stack.push(t.c(x, 0));
                    stack.push(t.c(x, 1));
                }
                Kind::Star | Kind::Plus => stack.push(t.c(x, 0)),
                _ => {}
            }
        }
        n
    }

    #[test]
    fn common_prefixes_and_suffixes_are_factored() {
        let (mut t, root) = tree_of(&["/a/b/c/x", "/a/b/c/y", "/a/b/c/z"]);
        assert_eq!(leaves(&t, root), 24);
        let s = t.simplify(root).unwrap();
        assert_eq!(leaves(&t, s), 10);
        let (mut t, root) = tree_of(&["/x/data", "/y/data"]);
        let s = t.simplify(root).unwrap();
        assert_eq!(leaves(&t, s), 8);
    }

    #[test]
    fn duplicates_collapse() {
        let (mut t, root) = tree_of(&["/etc/passwd", "/etc/passwd"]);
        let s = t.simplify(root).unwrap();
        assert_eq!(leaves(&t, s), 11);
    }

    #[test]
    fn deep_tries_need_no_stack() {
        let long: Vec<String> = (0..4)
            .map(|i| format!("/{}{}", "d/".repeat(2_000), i))
            .collect();
        let refs: Vec<&str> = long.iter().map(|s| s.as_str()).collect();
        let (mut t, root) = tree_of(&refs);
        let s = t.simplify(root).unwrap();
        assert!(leaves(&t, s) < 4_100);
        assert_eq!(t.min_match_len(s), 4_002);
    }

    #[test]
    fn a_spent_budget_is_an_error() {
        let (mut t, root) = tree_of(&["/a/b/c/x", "/a/b/c/y"]);
        t.budget = 10;
        assert_eq!(t.simplify(root).unwrap_err(), DfaError::TooLarge);
    }

    #[test]
    fn min_match_len_keeps_upstreams_quirks() {
        let (t, root) = tree_of(&["/a.c"]);
        assert_eq!(t.min_match_len(root), 3);
        let (t, root) = tree_of(&["/[^x]abc"]);
        assert_eq!(t.min_match_len(root), 2);
    }
}
