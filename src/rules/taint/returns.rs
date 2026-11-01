//! Values a function returns without a `return`: an arrow function's
//! expression body, a Ruby method's or lambda's last statement, a Rust
//! block's trailing expression.

use super::kotlin::Part;
use ast_grep_core::{Doc, Node};

/// Wrappers around a Ruby body's statements.
const BODIES: [&str; 5] = [
    "block",
    "block_body",
    "body_statement",
    "do_block",
    "begin_block",
];
/// Rust block children that are not a trailing value.
const STATEMENTS: [&str; 6] = [
    "expression_statement",
    "let_declaration",
    "empty_statement",
    "function_item",
    "use_declaration",
    "line_comment",
];

pub(super) fn implicit<'a, D: Doc>(scope: &Node<'a, D>) -> Option<Node<'a, D>> {
    let body = scope.part("body")?;
    match scope.kind().as_ref() {
        "arrow_function" => (body.kind() != "statement_block").then_some(body),
        "method" | "singleton_method" | "lambda" => last(&body),
        "function_item" | "closure_expression" if body.kind() != "block" => Some(body),
        "function_item" | "closure_expression" => {
            let tail = named(&body).pop()?;
            (!STATEMENTS.contains(&tail.kind().as_ref())).then_some(tail)
        }
        // Kotlin `fun f(s: String) = s.trim()`.
        "function_declaration" | "anonymous_function" => super::kotlin::expression_body(&body),
        _ => None,
    }
}

/// The last statement, through Ruby's body and block wrappers.
fn last<'a, D: Doc>(body: &Node<'a, D>) -> Option<Node<'a, D>> {
    let mut at = body.clone();
    loop {
        let tail = named(&at).pop()?;
        if !BODIES.contains(&tail.kind().as_ref()) {
            return Some(tail);
        }
        at = tail;
    }
}

fn named<'a, D: Doc>(n: &Node<'a, D>) -> Vec<Node<'a, D>> {
    n.children()
        .filter(|c| c.is_named() && !c.kind().contains("comment"))
        .collect()
}
