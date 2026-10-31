//! One walk of the tree for all of a rule's patterns (sources, sinks,
//! sanitizers, guards) instead of one walk per pattern: patterns are indexed by
//! the node kinds they can match, so each node is only tried against those.
//! The walk itself is shared by every taint rule checking a file
//! ([`FileIndex`]), as are the file's functions and imports.

use super::events::Skeletons;
use super::imports::{self, Import};
use super::summary;
use ast_grep_core::matcher::MatcherExt;
use ast_grep_core::{Doc, Matcher, Node, NodeMatch, Pattern};
use ast_grep_language::SupportLang;
use std::cell::OnceCell;
use std::collections::HashMap;
use std::path::Path;

/// Pattern groups, in this order: sources, sinks, sanitizers, guards.
pub(super) const GROUPS: usize = 4;

type Defs<'a, D> = Vec<(String, Node<'a, D>, Vec<String>)>;

/// A parsed file's nodes by kind, its named functions and its imports:
/// computed once, whatever the number of taint rules.
pub struct FileIndex<'a, D: Doc> {
    pub(super) root: Node<'a, D>,
    nodes: Vec<Node<'a, D>>,
    by_kind: HashMap<u16, Vec<usize>>,
    functions: OnceCell<Defs<'a, D>>,
    imports: OnceCell<Vec<Import>>,
    pub(super) skeletons: Skeletons<'a, D>,
}

impl<'a, D: Doc> FileIndex<'a, D> {
    pub fn new(root: Node<'a, D>) -> Self {
        let nodes: Vec<Node<'a, D>> = root.dfs().collect();
        let mut by_kind: HashMap<u16, Vec<usize>> = HashMap::new();
        for (i, n) in nodes.iter().enumerate() {
            by_kind.entry(n.kind_id()).or_default().push(i);
        }
        Self {
            root,
            nodes,
            by_kind,
            functions: OnceCell::new(),
            imports: OnceCell::new(),
            skeletons: Default::default(),
        }
    }

    /// Named functions: (name, node, parameter names).
    pub(super) fn functions(&self) -> &Defs<'a, D> {
        self.functions
            .get_or_init(|| summary::functions(&self.root))
    }

    pub(super) fn imports(&self, lang: SupportLang, file: &Path, repo: &Path) -> &[Import] {
        self.imports
            .get_or_init(|| imports::imports(lang, &self.root, file, repo))
    }
}

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
    pub fn scan<'a, D: Doc>(&self, index: &FileIndex<'a, D>) -> [Vec<NodeMatch<'a, D>>; GROUPS] {
        let mut found: [Vec<(usize, NodeMatch<'a, D>)>; GROUPS] = Default::default();
        let mut try_at = |at: usize, (g, i): (usize, usize)| {
            if let Some(m) = self.groups[g][i].match_node(index.nodes[at].clone()) {
                found[g].push((at, m));
            }
        };
        for (kind, patterns) in &self.by_kind {
            for &at in index.by_kind.get(kind).into_iter().flatten() {
                patterns.iter().for_each(|&p| try_at(at, p));
            }
        }
        for &p in &self.any {
            (0..index.nodes.len()).for_each(|at| try_at(at, p));
        }
        found.map(|mut ms| {
            ms.sort_by_key(|(at, _)| *at);
            ms.into_iter().map(|(_, m)| m).collect()
        })
    }
}
