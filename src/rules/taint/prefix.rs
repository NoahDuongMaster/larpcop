//! `safe_prefix:` a sink argument built as `"<literal>" + x` or `` `<literal>${x}` ``
//! whose fixed start matches the regex is safe: `res.redirect("/products/" + id)`
//! cannot leave the site, `fetch("https://api.example.com/" + id)` cannot pick the host.

use ast_grep_core::{Doc, Node};

/// The fixed text an argument starts with, if it starts with a literal.
pub(super) fn leading<D: Doc>(node: &Node<D>) -> Option<String> {
    match node.kind().as_ref() {
        "binary_expression" | "binary_operator" => leading(&node.field("left")?),
        "parenthesized_expression" => leading(&node.child(1)?),
        "template_string" | "string" => {
            let mut fixed = String::new();
            for c in node.children() {
                match c.kind().as_ref() {
                    "string_fragment" | "string_content" => fixed.push_str(&c.text()),
                    "template_substitution" | "interpolation" => break,
                    _ => {}
                }
            }
            Some(fixed)
        }
        _ => None,
    }
}

/// A guard `x.startsWith("<literal>")` only proves anything when the literal
/// is (the beginning of) a safe start: `startsWith("/")` keeps a redirect on
/// the site, `startsWith("http")` does not. Other guards are kept as they are.
pub(super) fn guard_holds<D: Doc>(guard: &Node<D>, safe: Option<&regex::Regex>) -> bool {
    let (Some(safe), true) = (safe, super::flow::CALLS.contains(&guard.kind().as_ref())) else {
        return true;
    };
    let Some(name) = super::summary::callee(guard) else {
        return true;
    };
    if !(name.ends_with(".startsWith") || name.ends_with(".startswith")) {
        return true;
    }
    let first = super::summary::args(guard).into_iter().next();
    match first.filter(|a| matches!(a.kind().as_ref(), "string" | "template_string")) {
        // The checked start may end where the safe part begins (`"/"` + a path).
        Some(lit) => leading(&lit)
            .is_some_and(|start| safe.is_match(&start) || safe.is_match(&(start + "a"))),
        None => true,
    }
}
