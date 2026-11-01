//! Static fields of another class read by a callee: `String data =
//! Case68a.data;` in `Case68b.badSink()` is an input of that method, like a
//! parameter. Its summary records the sinks such a field reaches; a caller
//! holding the field tainted at the call (`data = request.getParameter(…)` in
//! `Case68a`, or `Case68a.data = …` anywhere) reaches them there. A caller
//! that set it to a constant first (`data = "foo"`) does not.

use ast_grep_core::{Doc, Node};
use std::collections::HashSet;

/// `Cls[field]` for every `Cls.field` that `f` reads: a class (capitalized)
/// and a field that is not a constant (`HttpStatus.OK`, `MAX_SIZE`).
pub(super) fn read<D: Doc>(f: &Node<D>) -> Vec<String> {
    let mut out: Vec<String> = f
        .dfs()
        .filter(|n| {
            matches!(
                n.kind().as_ref(),
                "field_access" | "member_access_expression"
            )
        })
        .filter(|n| {
            // A write is not a read.
            !n.parent().is_some_and(|p| {
                super::flow::assignment(&p).is_some_and(|(l, _)| l.range() == n.range())
            })
        })
        .filter_map(|n| super::entries::entry(&n))
        .filter(|key| {
            let (class, field) = key.split_once('[').unwrap_or_default();
            class.chars().next().is_some_and(char::is_uppercase)
                && field.chars().next().is_some_and(char::is_lowercase)
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// Does the caller hold `key` (`Cls[field]`) tainted at `call`: the entry
/// itself, or its own bare field when it is `Cls`?
pub(super) fn held<D: Doc>(call: &Node<D>, key: &str, names: &HashSet<String>) -> bool {
    if names.contains(key) {
        return true;
    }
    let Some((class, field)) = key.strip_suffix(']').and_then(|k| k.split_once('[')) else {
        return false;
    };
    names.contains(field)
        && call
            .ancestors()
            .find(|a| crate::rules::complexity::is_function(a))
            .and_then(|f| super::defs::class_of(&f))
            .is_some_and(|c| c == class)
}
