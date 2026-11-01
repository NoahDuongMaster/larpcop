//! PHP declares no variable types: a variable's type is the class it is
//! assigned with `new` (`$xp = new DOMXPath($doc)`) or the type of the
//! parameter it is (`function f(DOMXPath $xp)`), in its function or file.

use crate::rules::complexity::is_function;
use ast_grep_core::{Doc, Node};

/// The class of PHP variable `at`, as far as its scope tells.
pub(super) fn php_type<D: Doc>(at: &Node<D>) -> Option<String> {
    let name = at.text();
    let scope = at
        .ancestors()
        .find(|a| is_function(a))
        .or_else(|| at.ancestors().last())?;
    let class = |n: &Node<D>| -> Option<String> {
        match n.kind().as_ref() {
            "assignment_expression" => {
                let (left, right) = (n.field("left")?, n.field("right")?);
                if left.text() != name || right.kind() != "object_creation_expression" {
                    return None;
                }
                right
                    .children()
                    .find(|c| matches!(c.kind().as_ref(), "name" | "qualified_name"))
                    .map(|c| c.text().trim_start_matches('\\').to_string())
            }
            "simple_parameter" | "property_promotion_parameter" => {
                (n.field("name")?.text() == name).then_some(())?;
                n.field("type")
                    .map(|t| t.text().trim_start_matches('\\').to_string())
            }
            _ => None,
        }
    };
    scope.dfs().find_map(|n| class(&n))
}
