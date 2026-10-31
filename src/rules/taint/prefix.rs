//! `safe_prefix:` a sink argument built as `"<literal>" + x` or `` `<literal>${x}` ``
//! whose fixed start matches the regex is safe: `res.redirect("/products/" + id)`
//! cannot leave the site, `fetch("https://api.example.com/" + id)` cannot pick the host.

use ast_grep_core::{Doc, Node};

/// String literal kinds: JS/TS/Python, Go, Rust.
const STRINGS: [&str; 5] = [
    "string",
    "template_string",
    "interpreted_string_literal",
    "raw_string_literal",
    "string_literal",
];

/// The fixed text an argument starts with, if it starts with a literal.
pub(super) fn leading<D: Doc>(node: &Node<D>) -> Option<String> {
    match node.kind().as_ref() {
        "binary_expression" | "binary_operator" => leading(&node.field("left")?),
        "parenthesized_expression" => leading(&node.child(1)?),
        // C# and PHP wrap each call argument.
        "argument" => leading(&node.children().filter(|c| c.is_named()).last()?),
        "raw_string_literal" => Some(node.text().trim_matches('`').to_string()),
        k if STRINGS.contains(&k) => {
            let mut fixed = String::new();
            for c in node.children() {
                match c.kind().as_ref() {
                    "string_fragment"
                    | "string_content"
                    | "string_literal_content"
                    | "interpreted_string_literal_content" => fixed.push_str(&c.text()),
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
    // Go's strings.HasPrefix(s, prefix) takes the prefix second.
    let at = match name.as_str() {
        n if n.ends_with(".startsWith")
            || n.ends_with(".startswith")
            || n.ends_with(".starts_with") =>
        {
            0
        }
        "strings.HasPrefix" | "bytes.HasPrefix" => 1,
        _ => return true,
    };
    let literal = super::summary::args(guard).into_iter().nth(at);
    match literal.filter(|a| STRINGS.contains(&a.kind().as_ref())) {
        // The checked start may end where the safe part begins (`"/"` + a path).
        Some(lit) => leading(&lit)
            .is_some_and(|start| safe.is_match(&start) || safe.is_match(&(start + "a"))),
        None => true,
    }
}
