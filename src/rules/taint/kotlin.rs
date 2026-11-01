//! Kotlin's grammar names almost no fields; the walk reads nodes by field.
//! `part` is `field`, falling back to the child that plays that role in a
//! Kotlin node: the name and value of `val x = v`, the callee and arguments of
//! `f(a)`, the object and member of `a.b`, the parameters and body of a
//! function. Kinds that other grammars share (`call_expression`, `assignment`,
//! `for_statement`) only fall back when the Kotlin-only child is there.

use ast_grep_core::{Doc, Node};

pub(super) trait Part<'a, D: Doc> {
    /// The child in role `field`: the grammar's field, or Kotlin's equivalent.
    fn part(&self, field: &str) -> Option<Node<'a, D>>;
}

impl<'a, D: Doc> Part<'a, D> for Node<'a, D> {
    fn part(&self, field: &str) -> Option<Node<'a, D>> {
        self.field(field).or_else(|| kotlin(self, field))
    }
}

/// Is `node` a `return` (Kotlin's `jump_expression` is also `throw`, `break`).
pub(super) fn is_return<D: Doc>(node: &Node<D>) -> bool {
    match node.kind().as_ref() {
        "return_statement" | "return_expression" | "return" => true,
        "jump_expression" => node.text().starts_with("return"),
        _ => false,
    }
}

/// `fun f(s: String) = s.trim()`: the expression a function body returns.
pub(super) fn expression_body<'a, D: Doc>(body: &Node<'a, D>) -> Option<Node<'a, D>> {
    if body.kind() != "function_body" {
        return None;
    }
    let mut children = body.children();
    children.next().filter(|c| c.text() == "=")?;
    children.find(|c| c.is_named())
}

fn child<'a, D: Doc>(n: &Node<'a, D>, kinds: &[&str]) -> Option<Node<'a, D>> {
    n.children().find(|c| kinds.contains(&c.kind().as_ref()))
}

fn first_named<'a, D: Doc>(n: &Node<'a, D>) -> Option<Node<'a, D>> {
    n.children().find(|c| c.is_named() && c.kind() != "comment")
}

/// The first named child after the token `token`.
fn after<'a, D: Doc>(n: &Node<'a, D>, token: &str) -> Option<Node<'a, D>> {
    n.children()
        .skip_while(|c| c.is_named() || c.text() != token)
        .find(|c| c.is_named())
}

/// `x` in `val x: T` (a `variable_declaration`), or the whole
/// `(a, b)` of a destructuring declaration.
fn declared<'a, D: Doc>(n: &Node<'a, D>) -> Option<Node<'a, D>> {
    if let Some(m) = child(n, &["multi_variable_declaration"]) {
        return Some(m);
    }
    child(
        &child(n, &["variable_declaration"])?,
        &["simple_identifier"],
    )
}

const TYPES: [&str; 3] = ["user_type", "nullable_type", "function_type"];

fn kotlin<'a, D: Doc>(n: &Node<'a, D>, field: &str) -> Option<Node<'a, D>> {
    match (n.kind().as_ref(), field) {
        ("property_declaration", "name" | "pattern" | "left") => declared(n),
        ("property_declaration", "value" | "right") => {
            after(n, "=").or_else(|| child(n, &["property_delegate"]))
        }
        ("property_declaration", "type") => child(&child(n, &["variable_declaration"])?, &TYPES),
        ("assignment", "left") => {
            let target = child(n, &["directly_assignable_expression"])?;
            let named: Vec<_> = target.children().filter(|c| c.is_named()).collect();
            match named.as_slice() {
                [only] if only.kind() == "simple_identifier" => Some(only.clone()),
                _ => Some(target),
            }
        }
        ("assignment", "right") => {
            child(n, &["directly_assignable_expression"])?;
            n.children().filter(|c| c.is_named()).last()
        }
        ("call_expression", "function") => {
            child(n, &["call_suffix"])?;
            first_named(n)
        }
        ("call_expression", "arguments") => {
            child(&child(n, &["call_suffix"])?, &["value_arguments"])
        }
        (
            "navigation_expression" | "directly_assignable_expression",
            "object" | "expression" | "receiver",
        ) => {
            child(n, &["navigation_suffix"])?;
            first_named(n)
        }
        (
            "navigation_expression" | "directly_assignable_expression",
            "property" | "name" | "field" | "attribute",
        ) => child(&child(n, &["navigation_suffix"])?, &["simple_identifier"]),
        ("indexing_expression", "object") => first_named(n),
        ("indexing_expression", "index") => first_named(&child(n, &["indexing_suffix"])?),
        ("function_declaration" | "anonymous_function", "name") => child(n, &["simple_identifier"]),
        ("function_declaration" | "anonymous_function" | "secondary_constructor", "parameters") => {
            child(n, &["function_value_parameters"])
        }
        ("function_declaration" | "anonymous_function", "body") => child(n, &["function_body"]),
        ("secondary_constructor", "body") => child(n, &["statements", "block"]),
        ("function_declaration", "type") => {
            let params = child(n, &["function_value_parameters"])?;
            n.children()
                .skip_while(|c| c.range() != params.range())
                .find(|c| TYPES.contains(&c.kind().as_ref()))
        }
        ("lambda_literal", "parameters") => child(n, &["lambda_parameters"]),
        ("lambda_literal", "body") => child(n, &["statements"]),
        ("class_declaration" | "object_declaration", "name") => child(n, &["type_identifier"]),
        ("class_declaration" | "object_declaration", "body") => {
            child(n, &["class_body", "enum_class_body"])
        }
        ("parameter" | "class_parameter", "name" | "pattern") => child(n, &["simple_identifier"]),
        ("parameter" | "class_parameter", "type") => child(n, &TYPES),
        ("for_statement", "left" | "name") => declared(n),
        ("for_statement", "right" | "value") => {
            child(n, &["variable_declaration", "multi_variable_declaration"])?;
            after(n, "in")
        }
        ("for_statement" | "while_statement" | "do_while_statement", "body") => {
            child(n, &["control_structure_body"])
        }
        ("if_expression", "consequence") => child(n, &["control_structure_body"]),
        ("if_expression", "alternative") => after(n, "else"),
        ("when_expression", "subject" | "value") => first_named(&child(n, &["when_subject"])?),
        ("when_entry", "body" | "consequence") => child(n, &["control_structure_body"]),
        ("value_argument", "value") => n.children().filter(|c| c.is_named()).last(),
        ("elvis_expression" | "additive_expression", "left") => first_named(n),
        ("elvis_expression" | "additive_expression", "right") => {
            n.children().filter(|c| c.is_named()).last()
        }
        _ => None,
    }
}
