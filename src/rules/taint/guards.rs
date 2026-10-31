//! Validation in `if` conditions (`guards:` patterns). After
//! `if (!url.startsWith("/")) return …;` the checked names are clean for the
//! rest of the scope; inside `if (isSafe(url)) { … }` they are clean in that
//! block only. Polarity is not judged: `if (!name.includes("/")) { … }` is a
//! check as much as `if (allowed.has(name)) { … }`.

use super::VARIABLES;
use ast_grep_core::{Doc, Node};
use std::collections::HashSet;
use std::ops::Range;

pub(super) const IFS: [&str; 2] = ["if_statement", "if_expression"];
const EXITS: [&str; 6] = [
    "return_statement",
    "return_expression",
    "throw_statement",
    "raise_statement",
    "continue_statement",
    "break_statement",
];

pub(super) enum Guard {
    /// The branch leaves the scope: names are clean from `at` on.
    After(usize, HashSet<String>),
    /// Names are clean within this range only.
    Within(Range<usize>, HashSet<String>),
}

/// The guard an `if` node sets up, if its condition checks names with a guard.
pub(super) fn of<D: Doc>(n: &Node<D>, guards: &[Range<usize>]) -> Option<Guard> {
    if guards.is_empty() || !IFS.contains(&n.kind().as_ref()) {
        return None;
    }
    let condition = n.field("condition")?;
    let consequence = n.field("consequence")?;
    let inside = |r: &Range<usize>| guards.iter().any(|g| g.start <= r.start && r.end <= g.end);
    let names: HashSet<String> = condition
        .dfs()
        .filter(|c| VARIABLES[..2].contains(&c.kind().as_ref()) && inside(&c.range()))
        .map(|c| c.text().to_string())
        .collect();
    if names.is_empty() {
        return None;
    }
    if exits(&consequence) {
        return Some(Guard::After(n.range().end, names));
    }
    Some(Guard::Within(consequence.range(), names))
}

/// Does this branch always leave (return, throw, …)?
fn exits<D: Doc>(branch: &Node<D>) -> bool {
    if EXITS.contains(&branch.kind().as_ref()) {
        return true;
    }
    let last = branch
        .children()
        .filter(|c| c.is_named() && c.kind() != "comment")
        .last();
    last.is_some_and(|l| {
        EXITS.contains(&l.kind().as_ref())
            || (l.kind() == "expression_statement"
                && l.children().any(|c| EXITS.contains(&c.kind().as_ref())))
    })
}
