//! `case`/`match`/`switch`/`when` expressions: the value is one of the
//! branches' results, never the subject or a pattern compared with it
//! (`case theme when "light" then "/a.svg" … end` holds a literal whatever
//! `theme` holds). Ruby `case`, PHP `match`, Rust `match`, Kotlin `when`,
//! Java and C# switch expressions.

use super::kotlin::Part;
use ast_grep_core::{Doc, Node};

const ARMS: [&str; 6] = [
    "match_arm",
    "match_conditional_expression",
    "match_default_expression",
    "switch_rule",
    "switch_expression_arm",
    "when_entry",
];

/// The results of choice expression `n`; `None` when it is not one.
pub(super) fn results<'a, D: Doc>(n: &Node<'a, D>) -> Option<Vec<Node<'a, D>>> {
    let arms: Vec<Node<'a, D>> = match n.kind().as_ref() {
        "case" => n
            .children()
            .filter(|c| matches!(c.kind().as_ref(), "when" | "else" | "in_clause"))
            .collect(),
        "match_expression" | "switch_expression" | "when_expression" => {
            let block = n
                .children()
                .find(|c| matches!(c.kind().as_ref(), "match_block" | "switch_block"));
            block
                .unwrap_or_else(|| n.clone())
                .children()
                .filter(|c| ARMS.contains(&c.kind().as_ref()))
                .collect()
        }
        _ => return None,
    };
    if arms.is_empty() {
        return None;
    }
    let result = |a: &Node<'a, D>| match a.kind().as_ref() {
        "when" => a.children().find(|c| c.kind() == "then"),
        "in_clause" => a.part("body"),
        "else" => Some(a.clone()),
        "match_arm" => a.part("value"),
        "when_entry" => a.children().find(|c| c.kind() == "control_structure_body"),
        // PHP and C# arms, Java `case … -> x`: the result comes last.
        _ => a.children().filter(|c| c.is_named()).last(),
    };
    Some(arms.iter().filter_map(result).collect())
}
