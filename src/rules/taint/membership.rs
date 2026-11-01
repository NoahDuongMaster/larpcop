//! What a membership or equality check proves: the names it makes safe.

use super::NAMES;
use super::kotlin::Part;
use ast_grep_core::{Doc, Node};
use std::collections::HashSet;

/// A membership test (`allowed.contains(host)`) proves its argument is one of
/// the allowed values; it says nothing of the collection, so a tainted
/// receiver (`url.contains(NULL_BYTE)`) stays tainted.
const MEMBERSHIP: [&str; 9] = [
    "contains",
    "includes",
    "has",
    "containsKey",
    "Contains",
    "ContainsKey",
    "include?",
    "member?",
    "key?",
];

/// Equality with a fixed value proves the operands that are plain names:
/// `NICK.equals(cookie.getName())` checks the cookie's name, not the cookie.
const EQUALITY: [&str; 4] = ["equals", "equalsIgnoreCase", "contentEquals", "Equals"];

/// Membership functions and the argument they look for: PHP
/// `in_array($needle, $list)`, Go `slices.Contains(list, needle)`.
const NEEDLES: [(&str, usize); 5] = [
    ("in_array", 0),
    ("array_key_exists", 0),
    ("key_exists", 0),
    ("slices.Contains", 1),
    ("maps.ContainsKey", 1),
];

pub(super) fn members<D: Doc>(n: &Node<D>) -> Option<HashSet<String>> {
    // Python `x in allowed`, Kotlin `x in allowed`: the left operand only
    // (`"k" in form.getlist(name)` says nothing of `name`).
    if let Some((left, op)) = infix(n) {
        return (op == "in").then(|| super::guards::names(&left));
    }
    if !super::flow::CALLS.contains(&n.kind().as_ref()) {
        return None;
    }
    if let Some(callee) = super::summary::callee(n)
        && let Some((_, i)) = NEEDLES.iter().find(|(f, _)| *f == callee)
    {
        let args = super::summary::args(n);
        return Some(
            args.get(*i)
                .map(|a| super::guards::names(a))
                .unwrap_or_default(),
        );
    }
    // From the node: `callee` gives up on chains (`c.getName().equals(X)`).
    let member = n.part("function");
    let method = member
        .as_ref()
        .and_then(|f| f.part("property"))
        .or_else(|| n.part("name"))
        .or_else(|| n.part("method"))?
        .text()
        .to_string();
    let method = method.as_str();
    let args = super::summary::args(n);
    if MEMBERSHIP.contains(&method) {
        return Some(args.iter().flat_map(|a| super::guards::names(a)).collect());
    }
    if !EQUALITY.contains(&method) {
        return None;
    }
    let receiver = n
        .part("object")
        .or_else(|| n.part("function")?.part("object"));
    Some(
        receiver
            .into_iter()
            .chain(args)
            .filter(|o| NAMES.contains(&o.kind().as_ref()))
            .map(|o| o.text().to_string())
            .collect(),
    )
}

/// `x not in allowed` (Python), `x !in allowed` (Kotlin): the names of `x`.
pub(super) fn not_in<D: Doc>(n: &Node<D>) -> Option<HashSet<String>> {
    let (left, op) = infix(n)?;
    matches!(op.as_str(), "not in" | "!in").then(|| super::guards::names(&left))
}

/// The left operand and operator of a Python comparison or a Kotlin `in` check.
fn infix<'a, D: Doc>(n: &Node<'a, D>) -> Option<(Node<'a, D>, String)> {
    if !matches!(
        n.kind().as_ref(),
        "comparison_operator" | "check_expression"
    ) {
        return None;
    }
    let parts: Vec<Node<D>> = n.children().filter(|c| c.is_named()).collect();
    let [left, right] = parts.as_slice() else {
        return None;
    };
    let start = n.range().start;
    let op = n.text()[left.range().end - start..right.range().start - start]
        .trim()
        .to_string();
    Some((left.clone(), op))
}
