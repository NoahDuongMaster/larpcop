//! A callback run over a tainted value receives it: `ids.forEach(id => q(id))`,
//! `list.forEach(x -> q(x))`, Kotlin `name?.let { q(it) }`. Its first parameter
//! (Kotlin's implicit `it`) is tainted when the receiver is.

use super::flow::{CALLS, Ctx};
use super::kotlin::Part;
use ast_grep_core::{Doc, Node};
use std::collections::HashSet;

/// Methods that call their callback with the receiver or its elements.
const ITERATES: [&str; 17] = [
    "forEach",
    "forEachIndexed",
    "forEachOrdered",
    "onEach",
    "map",
    "mapNotNull",
    "flatMap",
    "filter",
    "find",
    "some",
    "every",
    "ifPresent",
    "let",
    "also",
    "takeIf",
    "takeUnless",
    "use",
];

/// Wrappers between a callback and the call it is passed to.
const BETWEEN: [&str; 5] = [
    "arguments",
    "argument_list",
    "value_argument",
    "value_arguments",
    "annotated_lambda",
];

/// The parameter of nested function `f` that gets the taint of the value it
/// iterates, given the tainted `names` where `f` is written.
pub(super) fn bound<D: Doc>(ctx: &Ctx, f: &Node<D>, names: &HashSet<String>) -> Option<String> {
    let mut at = f.parent()?;
    while BETWEEN.contains(&at.kind().as_ref()) || at.kind() == "call_suffix" {
        at = at.parent()?;
    }
    if !CALLS.contains(&at.kind().as_ref()) {
        return None;
    }
    let method = super::summary::called_name(&at)?;
    if !ITERATES.contains(&method.as_str()) {
        return None;
    }
    let receiver = at.part("function").and_then(|m| m.part("object"))?;
    if !ctx.tainted(&receiver, names) {
        return None;
    }
    let params = super::defs::positional_params(f);
    let first = if method == "forEachIndexed" { 1 } else { 0 };
    params.into_iter().nth(first).filter(|p| !p.is_empty())
}
