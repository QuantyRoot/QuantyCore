//! From an expression tree to a minimal deterministic automaton whose
//! states carry permissions.
//!
//! The construction is the followpos one (Aho, Sethi, Ullman), as
//! upstream's. The input alphabet is split once into classes of bytes no
//! expression tells apart, plus one out of band symbol, so a state stores
//! one transition per class. A state's permissions come from the rules
//! that end in it, by upstream's rules: priority first, then deny over
//! exact exec rules over other allow rules over prompt rules, and two
//! allow rules of equal standing that name different exec transitions
//! for the same path are an error.

use std::collections::HashMap;

use super::regex::{ByteSet, Sym};
use super::tree::{Kind as TKind, Tree};
use crate::apparmor::model::perm::*;
use crate::apparmor::model::MIN_INTERNAL_PRIORITY;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Kind {
    Allow,
    Exact,
    Deny,
    Prompt,
}

/// The permissions one rule grants where it matches.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct MatchInfo {
    pub priority: i32,
    pub kind: Kind,
    pub perms: u32,
    /// Audit bits, or quiet bits for a deny rule.
    pub audit: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Perms {
    pub allow: u32,
    pub deny: u32,
    pub prompt: u32,
    pub audit: u32,
    pub quiet: u32,
}

impl Perms {
    pub fn is_accept(&self) -> bool {
        (self.allow | self.deny | self.prompt | self.audit | self.quiet) != 0
    }

    fn clear_bits(&mut self, bits: u32) {
        self.allow &= !bits;
        self.deny &= !bits;
        self.prompt &= !bits;
        self.audit &= !bits;
        self.quiet &= !bits;
    }

    /// The two accept table entries of a kernel that takes no
    /// permissions table: the allow mask, and audit and quiet packed as
    /// upstream's PACK_AUDIT_CTL packs them.
    pub fn accept_pair(&self) -> (u32, u32) {
        (
            self.allow,
            (self.audit & 0x1f_c07f) | ((self.quiet & 0x1f_c07f) << 7),
        )
    }

    /// Folds denials into the allow and prompt masks, for kernels whose
    /// tables carry no deny mask. Audit and quiet stay as computed.
    pub fn apply_deny(mut self) -> Perms {
        if self.deny != 0 {
            self.allow &= !self.deny;
            self.prompt &= !self.deny;
            self.deny = 0;
        }
        self
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum DfaError {
    TooLarge,
    ConflictingExec,
}

/// Bounds on one automaton, so a profile that explodes is an error and
/// not an exhausted machine.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub max_states: usize,
    /// Positions held across all states while building.
    pub max_positions: usize,
    /// Steps tree simplification may take; upstream's factoring is
    /// quadratic in the length of the paths it factors.
    pub max_tree_steps: u64,
}

impl Default for Limits {
    fn default() -> Limits {
        Limits {
            max_states: 1 << 21,
            max_positions: 1 << 27,
            max_tree_steps: 1 << 31,
        }
    }
}

/// Permissions for the set of rules ending in one state.
pub fn accept_perms(matches: &[MatchInfo], filedfa: bool) -> Result<Perms, DfaError> {
    let mut p = Perms::default();
    let mut priority = [MIN_INTERNAL_PRIORITY * 4; 32];
    for m in matches {
        let mut check = m.perms | m.audit;
        if filedfa {
            check &= !ALL_EXEC_TYPE;
        }
        let mut bit = 0;
        while check != 0 {
            if check & 1 != 0 && !update_perm(&mut priority, bit, m, &mut p, filedfa) {
                return Err(DfaError::ConflictingExec);
            }
            check >>= 1;
            bit += 1;
        }
    }
    if filedfa && p.allow & EXEC_BITS != 0 {
        if p.allow & MAY_EXEC != 0 && p.allow & EXEC_INHERIT != 0 && priority[6] <= priority[0] {
            p.allow |= OLD_EXEC_MMAP;
            priority[6] = priority[0];
        }
        let other_exec = MAY_EXEC << OTHER_SHIFT;
        let other_inherit = EXEC_INHERIT << OTHER_SHIFT;
        if p.allow & other_exec != 0 && p.allow & other_inherit != 0 && priority[20] <= priority[14]
        {
            p.allow |= OLD_EXEC_MMAP << OTHER_SHIFT;
        }
    }
    Ok(p)
}

/// One permission bit of one rule. Returns false on an exec conflict.
fn update_perm(
    priority: &mut [i32; 32],
    i: u32,
    m: &MatchInfo,
    p: &mut Perms,
    filedfa: bool,
) -> bool {
    let mask = 1u32 << i;
    let mut xmask = 0;
    let mut amask = mask;
    let mut pri = m.priority * 4;
    pri += match m.kind {
        Kind::Deny => 3,
        Kind::Exact if mask & EXEC_BITS != 0 => 2,
        Kind::Prompt => 0,
        _ => 1,
    };
    let slot = &mut priority[i as usize];
    if *slot > pri {
        return true;
    }
    if filedfa {
        if mask & USER_EXEC != 0 {
            xmask = USER_EXEC_TYPE;
            amask = mask | xmask;
        } else if mask & OTHER_EXEC != 0 {
            xmask = OTHER_EXEC_TYPE;
            amask = mask | xmask;
        }
    }
    if *slot < pri {
        *slot = pri;
        p.clear_bits(amask);
    }
    let conflicts = |p: &Perms| {
        filedfa && xmask != 0 && p.allow & amask != 0 && !x_consistent(p.allow, m.perms & amask)
    };
    match m.kind {
        Kind::Deny => {
            p.deny |= m.perms & amask;
            p.quiet |= m.audit & amask;
            p.allow &= !amask;
            p.audit &= !amask;
            p.prompt &= !amask;
        }
        Kind::Exact => {
            if conflicts(p) {
                return false;
            }
            p.allow &= !xmask;
            p.audit &= !xmask;
            p.prompt &= !xmask;
            p.allow |= m.perms & amask;
            p.audit |= m.audit & amask;
        }
        Kind::Allow => {
            if conflicts(p) {
                return false;
            }
            p.allow |= m.perms & amask;
            p.audit |= m.audit & amask;
        }
        Kind::Prompt => {
            if conflicts(p) {
                return false;
            }
            p.prompt |= m.perms & amask;
            p.audit |= m.audit & amask;
        }
    }
    true
}

/// A deterministic automaton over byte classes. State 0 matches nothing
/// and loops on itself; state 1 is the start.
#[derive(Clone, Debug)]
pub struct Dfa {
    /// The class of each byte.
    pub class: Box<[u16; 256]>,
    /// Byte classes; the out of band symbol is column `nclasses`.
    pub nclasses: usize,
    /// `states * (nclasses + 1)` targets.
    pub trans: Vec<u32>,
    pub perms: Vec<Perms>,
    /// Whether any expression used the out of band symbol.
    pub has_oob: bool,
}

pub const DEAD: u32 = 0;
pub const START: u32 = 1;

impl Dfa {
    pub fn columns(&self) -> usize {
        self.nclasses + 1
    }

    pub fn states(&self) -> usize {
        self.perms.len()
    }

    pub fn next(&self, state: u32, byte: u8) -> u32 {
        self.trans[state as usize * self.columns() + self.class[byte as usize] as usize]
    }

    pub fn next_oob(&self, state: u32) -> u32 {
        self.trans[state as usize * self.columns() + self.nclasses]
    }

    /// The state reached from the start on `input`.
    pub fn run(&self, input: &[u8]) -> u32 {
        input.iter().fold(START, |s, &b| self.next(s, b))
    }
}

struct Info {
    nullable: bool,
    first: Vec<u32>,
    last: Vec<u32>,
}

/// What a position matches: an index into the distinct byte sets, the
/// out of band symbol, or nothing (the end of a rule).
#[derive(Clone, Copy)]
enum Pos {
    Set(u32),
    Oob,
    Accept(u32),
}

struct Builder {
    pos: Vec<Pos>,
    follow: Vec<Vec<u32>>,
    sets: Vec<ByteSet>,
    set_index: HashMap<ByteSet, u32>,
    /// The position of each leaf node, so that a shared accept node is
    /// one position, as upstream's is.
    leaf_pos: HashMap<u32, u32>,
}

/// Joins two position lists, copying the shorter into the longer.
fn join(mut a: Vec<u32>, mut b: Vec<u32>) -> Vec<u32> {
    if a.len() < b.len() {
        std::mem::swap(&mut a, &mut b);
    }
    a.extend_from_slice(&b);
    a
}

impl Builder {
    fn leaf(&mut self, node: u32, p: Pos) -> Info {
        let id = match self.leaf_pos.get(&node) {
            Some(&id) => id,
            None => {
                let id = self.pos.len() as u32;
                self.pos.push(p);
                self.follow.push(Vec::new());
                self.leaf_pos.insert(node, id);
                id
            }
        };
        Info {
            nullable: false,
            first: vec![id],
            last: vec![id],
        }
    }

    /// firstpos, lastpos and followpos for every node, children first,
    /// without recursion.
    fn analyze(&mut self, t: &Tree, root: u32, limits: Limits) -> Result<Info, DfaError> {
        let mut stack = vec![(root, false)];
        let mut vals: Vec<Info> = Vec::new();
        let mut follow_total: usize = 0;
        while let Some((n, done)) = stack.pop() {
            let kind = t.kind(n);
            if !done {
                match kind {
                    TKind::Eps => vals.push(Info {
                        nullable: true,
                        first: Vec::new(),
                        last: Vec::new(),
                    }),
                    TKind::Sym(Sym::Oob) => vals.push(self.leaf(n, Pos::Oob)),
                    TKind::Sym(Sym::Bytes { set, .. }) => {
                        let next = self.sets.len() as u32;
                        let idx = *self.set_index.entry(set).or_insert(next);
                        if idx == next {
                            self.sets.push(set);
                        }
                        vals.push(self.leaf(n, Pos::Set(idx)));
                    }
                    TKind::Accept(a) => vals.push(self.leaf(n, Pos::Accept(a))),
                    TKind::Star | TKind::Plus => {
                        stack.push((n, true));
                        stack.push((t.c(n, 0), false));
                    }
                    TKind::Cat | TKind::Alt => {
                        stack.push((n, true));
                        stack.push((t.c(n, 1), false));
                        stack.push((t.c(n, 0), false));
                    }
                }
                continue;
            }
            match kind {
                TKind::Star | TKind::Plus => {
                    let mut i = vals.pop().expect("child analyzed");
                    for &p in &i.last {
                        follow_total += i.first.len();
                        self.follow[p as usize].extend_from_slice(&i.first);
                    }
                    if kind == TKind::Star {
                        i.nullable = true;
                    }
                    vals.push(i);
                }
                TKind::Cat => {
                    let r = vals.pop().expect("child analyzed");
                    let l = vals.pop().expect("child analyzed");
                    for &p in &l.last {
                        follow_total += r.first.len();
                        self.follow[p as usize].extend_from_slice(&r.first);
                    }
                    let first = if l.nullable {
                        join(l.first, r.first)
                    } else {
                        l.first
                    };
                    let last = if r.nullable {
                        join(l.last, r.last)
                    } else {
                        r.last
                    };
                    vals.push(Info {
                        nullable: l.nullable && r.nullable,
                        first,
                        last,
                    });
                }
                TKind::Alt => {
                    let r = vals.pop().expect("child analyzed");
                    let l = vals.pop().expect("child analyzed");
                    vals.push(Info {
                        nullable: l.nullable || r.nullable,
                        first: join(l.first, r.first),
                        last: join(l.last, r.last),
                    });
                }
                _ => unreachable!("leaves are never revisited"),
            }
            if follow_total > limits.max_positions {
                return Err(DfaError::TooLarge);
            }
        }
        Ok(vals.pop().expect("root analyzed"))
    }
}

fn sort_dedup(v: &mut Vec<u32>) {
    v.sort_unstable();
    v.dedup();
}

/// Builds the minimal automaton for `root` of `tree`, whose accept
/// leaves index `matches`.
pub fn build(
    tree: &Tree,
    root: u32,
    matches: &[MatchInfo],
    filedfa: bool,
    filter_deny: bool,
    limits: Limits,
) -> Result<Dfa, DfaError> {
    let mut b = Builder {
        pos: Vec::new(),
        follow: Vec::new(),
        sets: Vec::new(),
        set_index: HashMap::new(),
        leaf_pos: HashMap::new(),
    };
    let top = b.analyze(tree, root, limits)?;
    for f in b.follow.iter_mut() {
        sort_dedup(f);
    }
    let mut start = top.first;
    sort_dedup(&mut start);

    // Classes of bytes that no byte set tells apart.
    let mut class = [0u16; 256];
    let mut nclasses = 1usize;
    for set in &b.sets {
        let mut remap: HashMap<(u16, bool), u16> = HashMap::new();
        let mut next = 0u16;
        for byte in 0..=255u8 {
            let key = (class[byte as usize], set.contains(byte));
            let id = *remap.entry(key).or_insert_with(|| {
                next += 1;
                next - 1
            });
            class[byte as usize] = id;
        }
        nclasses = next as usize;
    }
    let cols = nclasses + 1;
    // Which columns each distinct byte set covers.
    let set_cols: Vec<Vec<u16>> = b
        .sets
        .iter()
        .map(|s| {
            let mut c: Vec<u16> = (0..=255u8)
                .filter(|&x| s.contains(x))
                .map(|x| class[x as usize])
                .collect();
            c.sort_unstable();
            c.dedup();
            c
        })
        .collect();

    let mut states: Vec<Box<[u32]>> = vec![Box::from([]), start.into_boxed_slice()];
    let mut index: HashMap<Box<[u32]>, u32> = HashMap::new();
    index.insert(states[0].clone(), DEAD);
    if !index.contains_key(&states[1]) {
        index.insert(states[1].clone(), START);
    } else {
        // The start matches nothing at all; it still gets its own state,
        // as upstream's start always does.
        states[1] = Box::from([]);
    }
    let mut held: usize = states[1].len();
    let mut trans: Vec<u32> = Vec::new();
    let mut work = 0usize;
    let has_oob = b.pos.iter().any(|p| matches!(p, Pos::Oob));
    while work < states.len() {
        let s = states[work].clone();
        work += 1;
        // Group the state's positions by what they match.
        let mut groups: HashMap<i64, Vec<u32>> = HashMap::new();
        for &p in s.iter() {
            match b.pos[p as usize] {
                Pos::Set(i) => groups
                    .entry(i as i64)
                    .or_default()
                    .extend_from_slice(&b.follow[p as usize]),
                Pos::Oob => groups
                    .entry(-1)
                    .or_default()
                    .extend_from_slice(&b.follow[p as usize]),
                Pos::Accept(_) => {}
            }
        }
        let mut gkeys: Vec<i64> = groups.keys().copied().collect();
        gkeys.sort_unstable();
        let words = gkeys.len().div_ceil(64).max(1);
        let mut col_key = vec![0u64; cols * words];
        for (g, &k) in gkeys.iter().enumerate() {
            let cs: &[u16] = if k < 0 { &[] } else { &set_cols[k as usize] };
            for &c in cs {
                col_key[c as usize * words + g / 64] |= 1 << (g % 64);
            }
            if k < 0 {
                col_key[nclasses * words + g / 64] |= 1 << (g % 64);
            }
        }
        let mut memo: HashMap<&[u64], u32> = HashMap::new();
        let row_start = trans.len();
        trans.resize(row_start + cols, DEAD);
        for c in 0..cols {
            let key = &col_key[c * words..(c + 1) * words];
            if key.iter().all(|&w| w == 0) {
                continue;
            }
            if let Some(&t) = memo.get(key) {
                trans[row_start + c] = t;
                continue;
            }
            let mut target: Vec<u32> = Vec::new();
            for (g, k) in gkeys.iter().enumerate() {
                if key[g / 64] & (1 << (g % 64)) != 0 {
                    target.extend_from_slice(&groups[k]);
                }
            }
            sort_dedup(&mut target);
            let t = match index.get(target.as_slice()) {
                Some(&t) => t,
                None => {
                    if states.len() >= limits.max_states {
                        return Err(DfaError::TooLarge);
                    }
                    held += target.len();
                    if held > limits.max_positions {
                        return Err(DfaError::TooLarge);
                    }
                    let t = states.len() as u32;
                    let boxed: Box<[u32]> = target.into_boxed_slice();
                    index.insert(boxed.clone(), t);
                    states.push(boxed);
                    t
                }
            };
            memo.insert(key, t);
            trans[row_start + c] = t;
        }
    }
    drop(index);

    let mut cache: HashMap<Vec<u32>, Perms> = HashMap::new();
    let mut perms = Vec::with_capacity(states.len());
    for s in &states {
        let mut acc: Vec<u32> = s
            .iter()
            .filter_map(|&p| match b.pos[p as usize] {
                Pos::Accept(a) => Some(a),
                _ => None,
            })
            .collect();
        acc.sort_unstable();
        acc.dedup();
        let p = match cache.get(&acc) {
            Some(p) => *p,
            None => {
                let infos: Vec<MatchInfo> = acc.iter().map(|&a| matches[a as usize]).collect();
                let mut p = accept_perms(&infos, filedfa)?;
                if filter_deny {
                    p = p.apply_deny();
                }
                cache.insert(acc, p);
                p
            }
        };
        perms.push(p);
    }
    drop(states);

    let dfa = Dfa {
        class: Box::new(class),
        nclasses,
        trans,
        perms,
        has_oob,
    };
    Ok(minimize(dfa))
}

/// Merges states that no input tells apart: Hopcroft's partition
/// refinement, starting from equal permissions, in O(columns n log n).
/// Refining round by round instead is quadratic in the length of a
/// literal path. The start state is kept apart, as upstream keeps it, so
/// it is never merged with another state.
pub fn minimize(dfa: Dfa) -> Dfa {
    let n = dfa.states();
    let cols = dfa.columns();
    let mut blk: Vec<u32> = vec![0; n];
    let mut nblocks = 1usize;
    {
        let mut ids: HashMap<Perms, u32> = HashMap::new();
        for (s, slot) in blk.iter_mut().enumerate() {
            if s == START as usize {
                *slot = 0;
                continue;
            }
            *slot = *ids.entry(dfa.perms[s]).or_insert_with(|| {
                nblocks += 1;
                nblocks as u32 - 1
            });
        }
    }
    // States grouped by block, each block a range of `elems`.
    let mut elems: Vec<u32> = (0..n as u32).collect();
    elems.sort_by_key(|&s| blk[s as usize]);
    let mut loc: Vec<usize> = vec![0; n];
    let mut first: Vec<usize> = vec![0; nblocks];
    let mut end: Vec<usize> = vec![0; nblocks];
    for (i, &s) in elems.iter().enumerate() {
        loc[s as usize] = i;
        let b = blk[s as usize] as usize;
        if i == 0 || blk[elems[i - 1] as usize] as usize != b {
            first[b] = i;
        }
        end[b] = i + 1;
    }
    // Predecessors by symbol: pred_at[c * n + t] .. pred_at[c * n + t + 1]
    // index the states that go to t on c.
    let mut pred_at: Vec<usize> = vec![0; cols * n + 1];
    for s in 0..n {
        for c in 0..cols {
            pred_at[c * n + dfa.trans[s * cols + c] as usize + 1] += 1;
        }
    }
    for i in 1..pred_at.len() {
        pred_at[i] += pred_at[i - 1];
    }
    let mut preds: Vec<u32> = vec![0; cols * n];
    {
        let mut fill = pred_at.clone();
        for s in 0..n {
            for c in 0..cols {
                let k = c * n + dfa.trans[s * cols + c] as usize;
                preds[fill[k]] = s as u32;
                fill[k] += 1;
            }
        }
    }
    let mut waiting: Vec<(u32, u32)> = Vec::new();
    let mut queued: Vec<bool> = Vec::new();
    for b in 0..nblocks {
        for c in 0..cols {
            waiting.push((b as u32, c as u32));
            queued.push(true);
        }
    }
    let mut marked: Vec<usize> = vec![0; nblocks];
    let mut touched: Vec<u32> = Vec::new();
    let mut splitter: Vec<u32> = Vec::new();
    while let Some((b, c)) = waiting.pop() {
        let (b, c) = (b as usize, c as usize);
        queued[b * cols + c] = false;
        splitter.clear();
        for &t in &elems[first[b]..end[b]] {
            let k = c * n + t as usize;
            splitter.extend_from_slice(&preds[pred_at[k]..pred_at[k + 1]]);
        }
        for &s in &splitter {
            let s = s as usize;
            let y = blk[s] as usize;
            let at = first[y] + marked[y];
            if loc[s] < at {
                continue;
            }
            if marked[y] == 0 {
                touched.push(y as u32);
            }
            // Move s to the front of its block, among the marked ones.
            let other = elems[at] as usize;
            elems.swap(loc[s], at);
            loc[other] = loc[s];
            loc[s] = at;
            marked[y] += 1;
        }
        for &y in &touched {
            let y = y as usize;
            let m = std::mem::take(&mut marked[y]);
            if m == end[y] - first[y] {
                continue;
            }
            let z = first.len();
            first.push(first[y]);
            end.push(first[y] + m);
            first[y] += m;
            marked.push(0);
            for &s in &elems[first[z]..end[z]] {
                blk[s as usize] = z as u32;
            }
            let (ys, zs) = (end[y] - first[y], end[z] - first[z]);
            queued.resize(first.len() * cols, false);
            for d in 0..cols {
                let pick = if queued[y * cols + d] || zs <= ys {
                    z
                } else {
                    y
                };
                if !queued[pick * cols + d] {
                    queued[pick * cols + d] = true;
                    waiting.push((pick as u32, d as u32));
                }
            }
        }
        touched.clear();
    }
    let part = blk;
    let count = first.len();
    // Renumber so that the dead state is 0 and the start 1.
    let mut order: Vec<u32> = vec![u32::MAX; count];
    let mut reps: Vec<usize> = Vec::with_capacity(count);
    for s in [DEAD as usize, START as usize].into_iter().chain(0..n) {
        let p = part[s] as usize;
        if order[p] == u32::MAX {
            order[p] = reps.len() as u32;
            reps.push(s);
        }
    }
    let mut trans = Vec::with_capacity(reps.len() * cols);
    let mut perms = Vec::with_capacity(reps.len());
    for &r in &reps {
        for c in 0..cols {
            trans.push(order[part[dfa.trans[r * cols + c] as usize] as usize]);
        }
        perms.push(dfa.perms[r]);
    }
    Dfa {
        class: dfa.class,
        nclasses: dfa.nclasses,
        trans,
        perms,
        has_oob: dfa.has_oob,
    }
}

#[cfg(test)]
mod tests {
    use super::super::regex::{parse, Node};
    use super::*;

    fn build(
        root: &Node,
        m: &[MatchInfo],
        filedfa: bool,
        deny: bool,
        limits: Limits,
    ) -> Result<Dfa, DfaError> {
        let mut t = Tree::new(u64::MAX);
        let r = t.add(root);
        super::build(&t, r, m, filedfa, deny, limits)
    }

    fn rule(re: &str, id: u32) -> Node {
        Node::Cat(vec![parse(re.as_bytes()).unwrap(), Node::Accept(id)])
    }

    fn allow(perms: u32) -> MatchInfo {
        MatchInfo {
            priority: 0,
            kind: Kind::Allow,
            perms,
            audit: 0,
        }
    }

    #[test]
    fn glob_and_literal_rules_combine() {
        let root = Node::Alt(vec![rule("/etc/[^/\\x00]*", 0), rule("/etc/passwd", 1)]);
        let dfa = build(
            &root,
            &[allow(MAY_READ), allow(MAY_WRITE)],
            true,
            false,
            Limits::default(),
        )
        .unwrap();
        assert_eq!(
            dfa.perms[dfa.run(b"/etc/passwd") as usize].allow,
            MAY_READ | MAY_WRITE
        );
        assert_eq!(dfa.perms[dfa.run(b"/etc/group") as usize].allow, MAY_READ);
        assert_eq!(dfa.perms[dfa.run(b"/etc/a/b") as usize].allow, 0);
        assert_eq!(dfa.perms[dfa.run(b"/etc/") as usize].allow, MAY_READ);
    }

    #[test]
    fn deny_wins_at_equal_priority_and_priority_wins_over_deny() {
        let root = Node::Alt(vec![rule("/x", 0), rule("/x", 1)]);
        let deny = MatchInfo {
            priority: 0,
            kind: Kind::Deny,
            perms: MAY_READ,
            audit: 0,
        };
        let dfa = build(
            &root,
            &[allow(MAY_READ), deny],
            true,
            false,
            Limits::default(),
        )
        .unwrap();
        let p = dfa.perms[dfa.run(b"/x") as usize];
        assert_eq!((p.allow, p.deny), (0, MAY_READ));
        let high = MatchInfo {
            priority: 5,
            ..allow(MAY_READ)
        };
        let dfa = build(&root, &[high, deny], true, false, Limits::default()).unwrap();
        assert_eq!(dfa.perms[dfa.run(b"/x") as usize].allow, MAY_READ);
    }

    #[test]
    fn different_exec_modifiers_on_overlapping_paths_conflict() {
        let root = Node::Alt(vec![
            rule("/bin/[^/\\x00]*", 0),
            rule("/bin/[^/\\x00]*h", 1),
        ]);
        let px = allow(MAY_EXEC | EXEC_PROFILE);
        let ix = allow(MAY_EXEC | EXEC_INHERIT);
        assert_eq!(
            build(&root, &[px, ix], true, false, Limits::default()).unwrap_err(),
            DfaError::ConflictingExec
        );
        let exact_ix = MatchInfo {
            kind: Kind::Exact,
            ..ix
        };
        let root = Node::Alt(vec![rule("/bin/[^/\\x00]*", 0), rule("/bin/sh", 1)]);
        let dfa = build(&root, &[px, exact_ix], true, false, Limits::default()).unwrap();
        let p = dfa.perms[dfa.run(b"/bin/sh") as usize];
        assert_eq!(p.allow & EXEC_TYPE, EXEC_INHERIT);
        assert!(p.allow & OLD_EXEC_MMAP != 0, "ix implies m");
        let exact_px = MatchInfo {
            kind: Kind::Exact,
            ..px
        };
        let root = Node::Alt(vec![rule("/bin/sh", 0), rule("/bin/sh", 1)]);
        assert_eq!(
            build(&root, &[exact_px, exact_ix], true, false, Limits::default()).unwrap_err(),
            DfaError::ConflictingExec
        );
    }

    #[test]
    fn explosion_is_an_error_not_an_abort() {
        let re = format!("[^/\\x00]*a{}", "[^/\\x00]".repeat(24));
        let root = rule(&re, 0);
        let limits = Limits {
            max_states: 10_000,
            max_positions: 1 << 20,
            max_tree_steps: 1 << 20,
        };
        assert_eq!(
            build(&root, &[allow(MAY_READ)], true, false, limits).unwrap_err(),
            DfaError::TooLarge
        );
        // Small enough for every other bound: only the state count stops it.
        let re = format!("[^/\\x00]*a{}", "[^/\\x00]".repeat(8));
        let root = rule(&re, 0);
        let states = |max_states| Limits {
            max_states,
            ..Limits::default()
        };
        let p = [allow(MAY_READ)];
        assert!(build(&root, &p, true, false, states(1 << 12)).is_ok());
        assert_eq!(
            build(&root, &p, true, false, states(50)).unwrap_err(),
            DfaError::TooLarge
        );
    }

    /// A literal path is a chain of states that refinement round by round
    /// splits one state per round; this one would take minutes that way.
    #[test]
    fn a_long_literal_path_minimizes_quickly() {
        let path = format!("/{}", "a".repeat(20_000));
        let root = Node::Alt(vec![rule(&path, 0), rule("/b", 0)]);
        let start = std::time::Instant::now();
        let dfa = build(&root, &[allow(MAY_READ)], true, false, Limits::default()).unwrap();
        assert_eq!(dfa.perms[dfa.run(path.as_bytes()) as usize].allow, MAY_READ);
        assert_eq!(dfa.states(), 20_003);
        assert!(start.elapsed().as_secs() < 60);
    }

    #[test]
    fn minimization_merges_equivalent_states() {
        let root = Node::Alt(vec![rule("/a/x", 0), rule("/b/x", 0)]);
        let dfa = build(&root, &[allow(MAY_READ)], true, false, Limits::default()).unwrap();
        assert_eq!(dfa.run(b"/a/"), dfa.run(b"/b/"));
    }
}
