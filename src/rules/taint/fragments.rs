//! HTML fragments built from values (`html_fragments`): PHP pages commonly
//! build markup into a variable (`$html .= '<pre>' . $name . '</pre>'`) that
//! a shared template prints later, often through an include whose path is
//! only known at run time. Markup has no use but being rendered, so a value
//! placed into a string whose literal parts hold an HTML tag, and assigned,
//! is a sink where it is placed. Escaping (`htmlspecialchars`) cleans it as
//! for any other sink.

use super::scan::FileIndex;
use ast_grep_core::{Doc, Node};
use regex::Regex;
use std::sync::LazyLock;

const ASSIGNMENTS: [&str; 2] = ["assignment_expression", "augmented_assignment_expression"];
/// Literal parts of a string expression.
const LITERALS: [&str; 3] = ["string", "string_content", "encapsed_string"];
static TAG: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"<[a-zA-Z][\w-]*[\s>/]|</[a-zA-Z][\w-]*\s*>").expect("valid regex")
});

/// (assignment start, value) for each value placed into markup.
pub(super) fn sinks<'a, D: Doc>(index: &FileIndex<'a, D>) -> Vec<(usize, Node<'a, D>)> {
    let mut out = Vec::new();
    for a in index.of_kinds(&ASSIGNMENTS) {
        let Some(right) = a.field("right") else {
            continue;
        };
        let mut literal = String::new();
        let mut values = Vec::new();
        parts(&right, &mut literal, &mut values);
        if !values.is_empty() && TAG.is_match(&literal) {
            out.extend(values.into_iter().map(|v| (a.range().start, v)));
        }
    }
    out
}

/// The literal text and the values of a concatenation (`.`) or an
/// interpolated string.
fn parts<'a, D: Doc>(n: &Node<'a, D>, literal: &mut String, values: &mut Vec<Node<'a, D>>) {
    match n.kind().as_ref() {
        "binary_expression" if n.children().any(|c| !c.is_named() && c.text() == ".") => {
            for side in [n.field("left"), n.field("right")].into_iter().flatten() {
                parts(&side, literal, values);
            }
        }
        "parenthesized_expression" => {
            if let Some(inner) = n.children().find(|c| c.is_named()) {
                parts(&inner, literal, values);
            }
        }
        "encapsed_string" | "heredoc" | "heredoc_body" => {
            for c in n.children().filter(|c| c.is_named()) {
                if c.kind() == "string_content"
                    || c.kind() == "heredoc_start"
                    || c.kind() == "heredoc_end"
                {
                    literal.push_str(&c.text());
                } else {
                    parts(&c, literal, values);
                }
            }
        }
        k if LITERALS.contains(&k) => literal.push_str(&n.text()),
        _ => values.push(n.clone()),
    }
}
