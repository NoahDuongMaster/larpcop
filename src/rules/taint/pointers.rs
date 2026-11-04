//! C pointers to a local (`char **p = &data;`, `p = &data`): `*p = x` writes
//! `data` and `*p` reads it, so the pointer and what it points to are one
//! place. Several pointers to the same local share it (`p1 = &data;
//! p2 = &data`: what is written through `p1` is read through `p2`). A member
//! of such a group tainted taints the group.

use ast_grep_core::{Doc, Node};
use std::collections::HashSet;

/// The groups of names the scope's `&local` assignments join.
pub(super) fn groups<'a: 'x, 'x, D: Doc>(
    assigns: impl IntoIterator<Item = (&'x Node<'a, D>, &'x Node<'a, D>)>,
) -> Vec<HashSet<String>> {
    let mut groups: Vec<HashSet<String>> = Vec::new();
    for (left, right) in assigns {
        if right.kind() != "pointer_expression" || !right.text().starts_with('&') {
            continue;
        }
        let Some(target) = right.field("argument").filter(|a| a.kind() == "identifier") else {
            continue;
        };
        let pair: HashSet<String> = [left.text().to_string(), target.text().to_string()].into();
        // Join every group the pair touches.
        let (mut joined, rest): (Vec<_>, Vec<_>) =
            groups.into_iter().partition(|g| !g.is_disjoint(&pair));
        let mut group = pair;
        for g in joined.drain(..) {
            group.extend(g);
        }
        groups = rest;
        groups.push(group);
    }
    groups
}

/// Taints every member of a group one member of which is tainted.
pub(super) fn spread(groups: &[HashSet<String>], names: &mut HashSet<String>) {
    if groups.is_empty() || names.is_empty() {
        return;
    }
    for g in groups {
        if g.iter().any(|n| names.contains(n)) {
            names.extend(g.iter().cloned());
        }
    }
}
