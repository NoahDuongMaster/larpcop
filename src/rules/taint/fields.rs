//! Fields of the object a method runs on: `this.x`, `self.x`, `$this->x`,
//! `@x`, and in Java and C# a bare name the class declares as a field. Data
//! stored there is read by the class's other methods.

use super::kotlin::Part;
use ast_grep_core::{Doc, Node};

/// `this.x` (JS/TS) or `self.x` (Python): a field of the object a method runs on.
pub(crate) fn is_field<D: Doc>(node: &Node<D>) -> bool {
    // Kind first: a field lookup on every node the walk visits is costly.
    match node.kind().as_ref() {
        "member_expression" => node.part("object").is_some_and(|o| o.kind() == "this"),
        "attribute" => node.part("object").is_some_and(|o| o.text() == "self"),
        // C# `this.x`, PHP `$this->x`, Java `this.x`, Ruby `@x`.
        "member_access_expression" => node
            .part("expression")
            .or_else(|| node.part("object"))
            .is_some_and(|o| matches!(o.text().as_ref(), "this" | "$this")),
        "field_access" => node.part("object").is_some_and(|o| o.text() == "this"),
        "instance_variable" => true,
        _ => false,
    }
}

/// Java/C#: `data = …` where `data` is a field of the enclosing class and
/// not a parameter or local of the method.
pub(super) fn class_field<D: Doc>(node: &Node<D>) -> bool {
    if node.kind() != "identifier" {
        return false;
    }
    let name = node.text();
    let mut method = None;
    for a in node.ancestors() {
        match a.kind().as_ref() {
            "method_declaration" | "constructor_declaration" | "local_function_statement" => {
                method.get_or_insert(a);
            }
            "class_declaration" | "struct_declaration" | "record_declaration"
            | "enum_declaration" => {
                // The class's own members first: most names are not fields.
                return has_field(&a, &name) && !method.is_some_and(|m| declares(&m, &name));
            }
            "lambda_expression" | "arrow_function" | "function_definition" => return false,
            _ => {}
        }
    }
    false
}

/// Does `class` declare `name` as a field?
fn has_field<D: Doc>(class: &Node<D>, name: &str) -> bool {
    let Some(body) = class.part("body") else {
        return false;
    };
    body.children()
        .filter(|m| m.kind() == "field_declaration")
        .any(|m| {
            m.dfs()
                .filter(|d| d.kind() == "variable_declarator")
                .any(|d| {
                    d.part("name")
                        .or_else(|| d.children().find(|c| c.kind() == "identifier"))
                        .is_some_and(|n| n.text() == name)
                })
        })
}

/// Does the method declare `name` as a parameter or local?
pub(super) fn declares<D: Doc>(method: &Node<D>, name: &str) -> bool {
    method.dfs().any(|d| {
        matches!(
            d.kind().as_ref(),
            "parameter" | "formal_parameter" | "variable_declarator"
        ) && d
            .part("name")
            .or_else(|| d.children().find(|c| c.kind() == "identifier"))
            .is_some_and(|n| n.text() == name)
    })
}
