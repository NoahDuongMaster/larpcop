//! What a membership or equality check proves: the names it makes safe.

use super::NAMES;
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

pub(super) fn members<D: Doc>(n: &Node<D>) -> Option<HashSet<String>> {
    if !super::flow::CALLS.contains(&n.kind().as_ref()) {
        return None;
    }
    // From the node: `callee` gives up on chains (`c.getName().equals(X)`).
    let member = n.field("function");
    let method = member
        .as_ref()
        .and_then(|f| f.field("property"))
        .or_else(|| n.field("name"))
        .or_else(|| n.field("method"))?
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
        .field("object")
        .or_else(|| n.field("function")?.field("object"));
    Some(
        receiver
            .into_iter()
            .chain(args)
            .filter(|o| NAMES.contains(&o.kind().as_ref()))
            .map(|o| o.text().to_string())
            .collect(),
    )
}
