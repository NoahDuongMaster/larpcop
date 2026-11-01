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

/// Pattern groups, in this order: sources, sinks, sanitizers, guards, rejects.
pub(super) const GROUPS: usize = 5;

type Defs<'a, D> = Vec<(String, Node<'a, D>, Vec<String>)>;

/// A parsed file's nodes by kind, its named functions and its imports:
/// computed once, whatever the number of taint rules.
pub struct FileIndex<'a, D: Doc> {
    pub(super) root: Node<'a, D>,
    nodes: Vec<Node<'a, D>>,
    by_kind: HashMap<u16, Vec<usize>>,
    functions: OnceCell<Defs<'a, D>>,
    /// The calls of the file with their callee name, computed once.
    callees: OnceCell<Vec<(usize, String)>>,
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
            callees: OnceCell::new(),
            imports: OnceCell::new(),
            skeletons: Default::default(),
        }
    }

    /// The calls of the file and the names they call.
    pub(super) fn callees(&self) -> impl Iterator<Item = (&Node<'a, D>, &str)> {
        self.callees
            .get_or_init(|| {
                self.nodes
                    .iter()
                    .enumerate()
                    .filter(|(_, n)| super::flow::CALLS.contains(&n.kind().as_ref()))
                    .filter_map(|(i, n)| Some((i, summary::callee(n)?)))
                    .collect()
            })
            .iter()
            .map(|(i, c)| (&self.nodes[*i], c.as_str()))
    }

    /// Ranges of the calls whose called name (its last segment) matches.
    /// The nodes of the file of these kinds.
    pub(super) fn of_kinds<'s>(
        &'s self,
        kinds: &'s [&str],
    ) -> impl Iterator<Item = &'s Node<'a, D>> {
        self.nodes
            .iter()
            .filter(move |n| kinds.contains(&n.kind().as_ref()))
    }

    /// Every call of the file.
    pub(super) fn calls(&self) -> impl Iterator<Item = &Node<'a, D>> {
        self.nodes
            .iter()
            .filter(|n| super::flow::CALLS.contains(&n.kind().as_ref()))
    }

    pub(super) fn calls_named(&self, re: &regex::Regex) -> Vec<Node<'a, D>> {
        self.nodes
            .iter()
            .filter(|n| super::flow::CALLS.contains(&n.kind().as_ref()))
            .filter(|n| {
                // By the called name alone: `a.b().escapeHtml(x)` has no plain callee.
                summary::called_name(n)
                    .or_else(|| summary::callee(n))
                    .is_some_and(|c| re.is_match(c.rsplit('.').next().unwrap_or(&c)))
            })
            .cloned()
            .collect()
    }

    /// Ranges of the names in `wanted` wherever they are read (`$_GET`).
    pub(super) fn named(
        &self,
        wanted: &std::collections::HashSet<String>,
    ) -> Vec<std::ops::Range<usize>> {
        if wanted.is_empty() {
            return Vec::new();
        }
        // An entry with `[` names a subscript by prefix: `$_SERVER['HTTP_`.
        let prefixes: Vec<&String> = wanted.iter().filter(|w| w.contains('[')).collect();
        self.nodes
            .iter()
            .filter(|n| {
                let kind = n.kind();
                if kind == "subscript_expression" && !prefixes.is_empty() {
                    let text: String = n.text().split_whitespace().collect();
                    return prefixes.iter().any(|p| text.starts_with(p.as_str()));
                }
                super::NAMES.contains(&kind.as_ref()) && wanted.contains(n.text().as_ref())
            })
            .map(|n| n.range())
            .collect()
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

/// A pattern and the longest name it spells out (`FormValue` in
/// `$R.FormValue($K)`): a node whose text lacks it cannot match, which is far
/// cheaper to find out than matching.
/// A pattern, its needle, and how specific it is (characters that are not
/// metavariables): of a guard and a reject matching the same check, the more
/// specific one says what it means (`"$S" not in $P` over `$X not in $L`).
pub(super) type Compiled = (Pattern, Option<String>, usize);

pub(super) fn specificity(pattern: &str) -> usize {
    let mut n = 0;
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '$' {
            while chars
                .next_if(|c| *c == '$' || *c == '_' || c.is_ascii_uppercase() || c.is_ascii_digit())
                .is_some()
            {}
        } else if !c.is_whitespace() {
            n += 1;
        }
    }
    n
}

/// The longest identifier of a pattern that is not a metavariable.
pub(super) fn needle(pattern: &str) -> Option<String> {
    let mut best: Option<&str> = None;
    let bytes = pattern.as_bytes();
    let mut start = None;
    for (i, &b) in bytes.iter().chain(std::iter::once(&b' ')).enumerate() {
        let word = b.is_ascii_alphanumeric() || b == b'_';
        match (word, start) {
            (true, None) => start = Some(i),
            (false, Some(s)) => {
                let meta = s > 0 && bytes[s - 1] == b'$';
                let w = &pattern[s..i];
                if !meta && best.is_none_or(|b: &str| w.len() > b.len()) {
                    best = Some(w);
                }
                start = None;
            }
            _ => {}
        }
    }
    best.map(str::to_string)
}

pub(super) struct Indexed {
    groups: [Vec<Compiled>; GROUPS],
    /// Node kind → (group, pattern) that can match it.
    by_kind: HashMap<u16, Vec<(usize, usize)>>,
    /// Patterns that can match any kind.
    any: Vec<(usize, usize)>,
}

impl Indexed {
    pub fn new(groups: [Vec<Compiled>; GROUPS]) -> Self {
        let mut by_kind: HashMap<u16, Vec<(usize, usize)>> = HashMap::new();
        let mut any = Vec::new();
        for (g, patterns) in groups.iter().enumerate() {
            for (i, (p, ..)) in patterns.iter().enumerate() {
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

    /// The words a source or sink match must contain, one per pattern; `None`
    /// when some pattern needs none.
    pub(super) fn needles(&self) -> Option<Vec<&str>> {
        self.groups[..2]
            .iter()
            .flatten()
            .map(|(_, needle, _)| needle.as_deref())
            .collect()
    }

    /// Matches of every group, each in tree order (as `find_all` gives them).
    /// Each match comes with the specificity of its pattern.
    pub fn scan<'a, D: Doc>(
        &self,
        index: &FileIndex<'a, D>,
    ) -> [Vec<(NodeMatch<'a, D>, usize)>; GROUPS] {
        let mut found: [Vec<(usize, NodeMatch<'a, D>, usize)>; GROUPS] = Default::default();
        let mut try_at = |at: usize, (g, i): (usize, usize)| {
            let (pattern, needle, weight) = &self.groups[g][i];
            let node = &index.nodes[at];
            if needle
                .as_ref()
                .is_some_and(|n| !node.text().contains(n.as_str()))
            {
                return;
            }
            if let Some(m) = pattern.match_node(node.clone()) {
                found[g].push((at, m, *weight));
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
            ms.sort_by_key(|(at, ..)| *at);
            ms.into_iter().map(|(_, m, w)| (m, w)).collect()
        })
    }
}
