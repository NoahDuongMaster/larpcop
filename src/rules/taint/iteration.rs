//! A mapped collection holds what the callback returns, not the elements:
//! `items.map(i => escape(i))`, `items.map { |i| h(i) }`, `[esc(x) for x in xs]`
//! are clean when the callback's value is, even though `items` is tainted.
//! Only callbacks that are a single expression are read this way: a body
//! with statements falls back to the receiver's taint.

use super::flow::{CALLS, Ctx};
use super::kotlin::Part;
use super::summary::param_names;
use ast_grep_core::{Doc, Node};
use std::collections::HashSet;

const MAPS: [&str; 6] = [
    "map",
    "flatMap",
    "flat_map",
    "collect",
    "filter_map",
    "collect_concat",
];
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
    let (receiver, method, callback) = parts(node)?;
    if !MAPS.contains(&method.as_str()) {
        return None;
    }
    let value = single_value(&callback)?;
    let mut inner = names.clone();
    let params = param_names(&callback);
    if ctx.tainted(&receiver, names) {
        inner.extend(params);
    } else {
        inner.retain(|n| !params.contains(n));
    }
    Some(ctx.tainted(&value, &inner))
}

/// Receiver, method name and callback of `recv.map(fn)` / `recv.map { … }`.
fn parts<'a, D: Doc>(call: &Node<'a, D>) -> Option<(Node<'a, D>, String, Node<'a, D>)> {
    if let Some(member) = call.part("function") {
        // JS/TS: `recv.map(x => …)`.
        let receiver = member.part("object")?;
        let method = member.part("property")?.text().to_string();
        let callback = call
            .part("arguments")?
            .children()
            .find(|c| c.is_named())
            .filter(|c| matches!(c.kind().as_ref(), "arrow_function" | "function_expression"))?;
        return Some((receiver, method, callback));
    }
    // Ruby: `recv.map { |x| … }`.
    let receiver = call.part("receiver")?;
    let method = call.part("method")?.text().to_string();
    let callback = call.part("block")?;
    Some((receiver, method, callback))
}

/// The one expression a callback returns: an arrow function's expression
/// body, a Ruby block of one statement.
fn single_value<'a, D: Doc>(callback: &Node<'a, D>) -> Option<Node<'a, D>> {
    let body = callback.part("body")?;
    match callback.kind().as_ref() {
        "arrow_function" => (body.kind() != "statement_block").then_some(body),
        "block" | "do_block" => {
            let statements: Vec<Node<D>> = body
                .children()
                .filter(|c| c.is_named() && !c.kind().contains("comment"))
                .collect();
            match statements.as_slice() {
                [only] => Some(only.clone()),
                _ => None,
            }
        }
        _ => None,
    }
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
