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
