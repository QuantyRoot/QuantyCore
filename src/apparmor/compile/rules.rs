//! A set of rules that becomes one automaton: upstream's aare_rules.
//!
//! Rules with the same permissions form one group, an alternation in the
//! order they were added, and each group is simplified on its own before
//! the groups are joined, as upstream does.

use super::dfa::{self, Dfa, DfaError, Kind, Limits, MatchInfo};
use super::regex::{self, Node, Sym};
use super::tree::Tree;
use crate::apparmor::model::RuleMode;

enum Part {
    Rule(Node),
    /// A separator and expression every rule so far continues with.
    Append {
        tail: Node,
        with_perm: bool,
    },
}

#[derive(Default)]
pub struct RuleSet {
    groups: Vec<(u32, Vec<Part>)>,
    infos: Vec<MatchInfo>,
    count: usize,
}

pub use super::regex::BadExpr;

impl RuleSet {
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn len(&self) -> usize {
        self.count
    }

    fn info(&mut self, priority: i32, mode: RuleMode, perms: u32, audit: u32, exact: bool) -> u32 {
        let kind = match mode {
            RuleMode::Deny => Kind::Deny,
            RuleMode::Prompt => Kind::Prompt,
            _ if exact => Kind::Exact,
            _ => Kind::Allow,
        };
        let m = MatchInfo {
            priority,
            kind,
            perms,
            audit,
        };
        if let Some(i) = self.infos.iter().position(|x| *x == m) {
            return i as u32;
        }
        self.infos.push(m);
        (self.infos.len() - 1) as u32
    }

    pub fn add(
        &mut self,
        re: &[u8],
        priority: i32,
        mode: RuleMode,
        perms: u32,
        audit: u32,
    ) -> Result<(), BadExpr> {
        self.add_vec(priority, mode, perms, audit, &[re], false)
    }

    /// One rule over several fields, joined by NUL or, with `oob`, by
    /// the out of band symbol.
    pub fn add_vec(
        &mut self,
        priority: i32,
        mode: RuleMode,
        perms: u32,
        audit: u32,
        parts: &[&[u8]],
        oob: bool,
    ) -> Result<(), BadExpr> {
        let mut items = Vec::with_capacity(parts.len() * 2);
        for (i, p) in parts.iter().enumerate() {
            if i > 0 {
                items.push(if oob {
                    Node::Sym(Sym::Oob)
                } else {
                    Node::byte(0)
                });
            }
            items.push(regex::parse(p).map_err(|_| BadExpr)?);
        }
        let tree = Node::cat(items);
        let exact = tree.is_exact();
        let id = self.info(priority, mode, perms, audit, exact);
        match self.groups.iter_mut().find(|(g, _)| *g == id) {
            Some((_, parts)) => parts.push(Part::Rule(tree)),
            None => self.groups.push((id, vec![Part::Rule(tree)])),
        }
        self.count += 1;
        Ok(())
    }

    /// Lets every rule so far continue with a separator and `re`, for
    /// xattr values after a path. With `with_perm` a rule still matches
    /// where it used to end.
    pub fn append(&mut self, re: &[u8], oob: bool, with_perm: bool) -> Result<(), BadExpr> {
        let tail = regex::parse(re).map_err(|_| BadExpr)?;
        let sep = if oob {
            Node::Sym(Sym::Oob)
        } else {
            Node::byte(0)
        };
        let tail = Node::Cat(vec![sep, tail]);
        for (_, parts) in self.groups.iter_mut() {
            parts.push(Part::Append {
                tail: tail.clone(),
                with_perm,
            });
        }
        Ok(())
    }

    /// The tree upstream builds: each group simplified, followed by its
    /// accept node, the groups alternated in order.
    fn tree(&self, limits: Limits) -> Result<(Tree, u32), DfaError> {
        let mut t = Tree::new(limits.max_tree_steps);
        let mut root: Option<u32> = None;
        for (id, parts) in &self.groups {
            let accept = t.accept(*id);
            let mut acc: Option<u32> = None;
            for p in parts {
                acc = Some(match (p, acc) {
                    (Part::Rule(n), None) => t.add(n),
                    (Part::Rule(n), Some(a)) => {
                        let n = t.add(n);
                        t.alt(a, n)
                    }
                    (Part::Append { tail, with_perm }, Some(a)) => {
                        let mut x = t.add(tail);
                        if *with_perm {
                            x = t.alt(accept, x);
                        }
                        t.cat(a, x)
                    }
                    (Part::Append { .. }, None) => continue,
                });
            }
            let Some(g) = acc else { continue };
            let g = t.simplify(g)?;
            let g = t.cat(g, accept);
            root = Some(match root {
                None => g,
                Some(r) => t.alt(r, g),
            });
        }
        let root = root.unwrap_or(super::tree::EPS);
        Ok((t, root))
    }

    /// The automaton, and the length of the shortest string any rule
    /// matches, as upstream computes it for attachment priority.
    pub fn build(
        &self,
        filedfa: bool,
        filter_deny: bool,
        limits: Limits,
    ) -> Result<(Dfa, usize), DfaError> {
        let (tree, root) = self.tree(limits)?;
        let len = tree.min_match_len(root);
        let dfa = dfa::build(&tree, root, &self.infos, filedfa, filter_deny, limits)?;
        Ok((dfa, len))
    }
}
