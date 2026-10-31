//! One walk of the tree for all of a rule's patterns (sources, sinks,
//! sanitizers, guards) instead of one walk per pattern: patterns are indexed by
//! the node kinds they can match, so each node is only tried against those.

use ast_grep_core::matcher::MatcherExt;
use ast_grep_core::{Doc, Matcher, Node, NodeMatch, Pattern};
use std::collections::HashMap;

/// Pattern groups, in this order: sources, sinks, sanitizers, guards.
pub(super) const GROUPS: usize = 4;

pub(super) struct Indexed {
    pub groups: [Vec<Pattern>; GROUPS],
    /// Node kind → (group, pattern) that can match it.
    by_kind: HashMap<u16, Vec<(usize, usize)>>,
    /// Patterns that can match any kind.
    any: Vec<(usize, usize)>,
}

impl Indexed {
    pub fn new(groups: [Vec<Pattern>; GROUPS]) -> Self {
        let mut by_kind: HashMap<u16, Vec<(usize, usize)>> = HashMap::new();
        let mut any = Vec::new();
        for (g, patterns) in groups.iter().enumerate() {
            for (i, p) in patterns.iter().enumerate() {
                match p.potential_kinds() {
                    Some(kinds) => {
                        for k in kinds.iter() {
                            by_kind.entry(k as u16).or_default().push((g, i));
                        }
                    }
                    None => any.push((g, i)),
                }
            }
        }
        Self {
            groups,
            by_kind,
            any,
        }
    }

    /// Matches of every group, each in tree order (as `find_all` gives them).
    pub fn scan<'a, D: Doc>(&self, root: &Node<'a, D>) -> [Vec<NodeMatch<'a, D>>; GROUPS] {
        let mut found: [Vec<NodeMatch<'a, D>>; GROUPS] = Default::default();
        for node in root.dfs() {
            let candidates = self.by_kind.get(&node.kind_id()).into_iter().flatten();
            for &(g, i) in candidates.chain(&self.any) {
                if let Some(m) = self.groups[g][i].match_node(node.clone()) {
                    found[g].push(m);
                }
            }
        }
        found
    }
}
