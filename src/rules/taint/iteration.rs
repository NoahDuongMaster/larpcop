//! A mapped collection holds what the callback returns, not the elements:
//! `items.map(i => escape(i))`, `items.stream().map(Encode::forHtml)`,
//! `items.map { |i| h(i) }`, `[esc(x) for x in xs]` are clean when the
//! callback's value is, even though `items` is tainted (see mapping.rs).

use super::flow::{CALLS, Ctx};
use super::kotlin::Part;
use ast_grep_core::{Doc, Node};
use std::collections::HashSet;

const COMPREHENSIONS: [&str; 4] = [
    "list_comprehension",
    "set_comprehension",
    "generator_expression",
    "dictionary_comprehension",
];

/// Whether `node`, a mapping, is tainted; `None` when it is not one.
pub(super) fn mapped<D: Doc>(ctx: &Ctx, node: &Node<D>, names: &HashSet<String>) -> Option<bool> {
    let kind = node.kind();
    if COMPREHENSIONS.contains(&kind.as_ref()) {
        return comprehension(ctx, node, names);
    }
    if !CALLS.contains(&kind.as_ref()) {
        return None;
    }
    let (receiver, method, callback) = super::mapping::parts(node)?;
    if !super::mapping::MAPS.contains(&method.as_str()) {
        return None;
    }
    super::mapping::returns(ctx, &callback, ctx.tainted(&receiver, names), names)
}

/// `[body for x in xs if …]`: tainted when the body is, with `x` tainted if
/// `xs` is.
fn comprehension<D: Doc>(ctx: &Ctx, node: &Node<D>, names: &HashSet<String>) -> Option<bool> {
    let body = node.part("body")?;
    let mut inner = names.clone();
    for clause in node.children().filter(|c| c.kind() == "for_in_clause") {
        let (Some(left), Some(right)) = (clause.part("left"), clause.part("right")) else {
            return None;
        };
        let bound = left
            .dfs()
            .filter(|n| n.kind() == "identifier")
            .map(|n| n.text().to_string());
        if ctx.tainted(&right, &inner) {
            inner.extend(bound);
        } else {
            for b in bound {
                inner.remove(&b);
            }
        }
    }
    Some(ctx.tainted(&body, &inner))
}
