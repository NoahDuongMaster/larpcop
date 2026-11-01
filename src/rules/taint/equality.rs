//! Equality with a string literal as a guard: where `x == "jpg"` holds, `x`
//! is that literal, so nothing injected can be in it. Through a call that only
//! changes case (`strtolower($ext) == 'jpg'`, `ext.lower() == "png"`) it still
//! holds; through anything else (`substr($x, 0, 3) == 'abc'`) it does not.
//! `a == 'x' || a == 'y'` holds `a` in every branch, so it guards `a` too.

use super::guards::{Sets, names};
use super::kotlin::Part;
use ast_grep_core::{Doc, Node};
use std::collections::HashSet;

/// Calls whose result is their argument (or receiver) in another case.
const CASE_FOLDS: [&str; 16] = [
    "strtolower",
    "strtoupper",
    "mb_strtolower",
    "mb_strtoupper",
    "lower",
    "upper",
    "casefold",
    "toLowerCase",
    "toUpperCase",
    "downcase",
    "upcase",
    "ToLower",
    "ToUpper",
    "ToLowerInvariant",
    "ToUpperInvariant",
    "lowercase",
];

/// The guard sets of `l op r` when one side is a string literal and `op`
/// compares for (in)equality.
pub(super) fn literal<'a, D: Doc>(op: &str, l: &Node<'a, D>, r: &Node<'a, D>) -> Option<Sets> {
    let equal = match op {
        "==" | "===" | "eq" => true,
        "!=" | "!==" | "ne" => false,
        _ => return None,
    };
    let value = if is_string(r) {
        l
    } else if is_string(l) {
        r
    } else {
        return None;
    };
    let held = compared(value)?;
    Some(if equal {
        (held, HashSet::new())
    } else {
        (HashSet::new(), held)
    })
}

/// A non-empty string literal without interpolation.
fn is_string<D: Doc>(n: &Node<D>) -> bool {
    let kind = n.kind();
    kind.contains("string")
        && n.text().len() > 2
        && !n.dfs().skip(1).any(|c| {
            c.kind().contains("interpolation") || super::NAMES.contains(&c.kind().as_ref())
        })
}

/// The names a compared value pins down: a plain name, or the one name a
/// case-folding call is applied to.
fn compared<D: Doc>(n: &Node<D>) -> Option<HashSet<String>> {
    if super::NAMES.contains(&n.kind().as_ref()) {
        return Some(names(n));
    }
    if !super::flow::CALLS.contains(&n.kind().as_ref())
        && !matches!(n.kind().as_ref(), "call_expression" | "call")
    {
        return None;
    }
    let name = super::summary::called_name(n)?;
    if !CASE_FOLDS.contains(&name.as_str()) {
        return None;
    }
    // `strtolower($x)` / `x.lower()`: the one name in it besides the call's.
    let inner: HashSet<String> = names(n)
        .into_iter()
        .filter(|t| t != &name && !CASE_FOLDS.contains(&t.as_str()))
        .collect();
    (inner.len() == 1
        && n.part("arguments")
            .is_none_or(|a| a.text().matches(',').count() == 0))
    .then_some(inner)
}
