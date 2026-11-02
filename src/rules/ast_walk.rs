//! One walk of a tree for every ast-grep rule: the nodes are bucketed by kind
//! and a rule only tests the buckets its patterns can match.

use ast_grep_core::matcher::MatcherExt;
use ast_grep_core::{Doc, Node, NodeMatch};
use std::collections::HashMap;

/// The nodes of a file, by kind, in document order.
pub struct Buckets<'t, D: Doc> {
    nodes: Vec<Node<'t, D>>,
    by_kind: HashMap<u16, Vec<usize>>,
}

impl<'t, D: Doc> Buckets<'t, D> {
    pub fn new(root: &Node<'t, D>) -> Self {
        let nodes: Vec<Node<'t, D>> = root.dfs().collect();
        let mut by_kind: HashMap<u16, Vec<usize>> = HashMap::new();
        for (i, node) in nodes.iter().enumerate() {
            // `dfs` yields document order already, so each bucket keeps it.
            by_kind.entry(node.kind_id()).or_default().push(i);
        }
        Buckets { nodes, by_kind }
    }

    /// The matches of one rule: the nodes of the kinds it names, or every
    /// node when the rule cannot say (a relation, an `all:` of matchers).
    pub fn matches<M: MatcherExt>(
        &self,
        root: &Node<'t, D>,
        matcher: &M,
        kept: impl Fn(&NodeMatch<'t, D>) -> bool,
    ) -> Vec<NodeMatch<'t, D>> {
        let Some(kinds) = matcher.potential_kinds() else {
            return root.find_all(matcher).filter(|m| kept(m)).collect();
        };
        let mut out: Vec<(usize, NodeMatch<'t, D>)> = Vec::new();
        for (kind, bucket) in &self.by_kind {
            if !kinds.contains(*kind as usize) {
                continue;
            }
            for i in bucket {
                if let Some(m) = matcher.match_node(self.nodes[*i].clone()) {
                    if kept(&m) {
                        out.push((*i, m));
                    }
                }
            }
        }
        // One bucket at a time would report the kinds out of document order.
        out.sort_by_key(|(i, _)| *i);
        out.into_iter().map(|(_, m)| m).collect()
    }
}
