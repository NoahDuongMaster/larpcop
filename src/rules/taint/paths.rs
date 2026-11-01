//! Which code runs on some paths only, and which assignments add to their target.

use ast_grep_core::{Doc, Node};

/// Constructs whose insides run on some paths only.
pub(super) const CONDITIONAL: [&str; 38] = [
    "if_statement",
    "if_expression",
    "else_clause",
    "elif_clause",
    "switch_statement",
    "switch_expression",
    "expression_switch_statement",
    "type_switch_statement",
    "select_statement",
    "match_expression",
    "match_statement",
    "case_clause",
    "conditional_expression",
    "ternary_expression",
    "while_statement",
    "while_expression",
    "do_statement",
    "for_statement",
    "enhanced_for_statement",
    "for_in_statement",
    "for_expression",
    "loop_expression",
    "try_statement",
    "catch_clause",
    "except_clause",
    "case",
    "when",
    "rescue",
    "if",
    "unless",
    "if_modifier",
    "unless_modifier",
    "while",
    "until",
    "while_modifier",
    "until_modifier",
    "conditional",
    "elsif",
];

/// `x += v`, `x .= v`, `x ||= v`: the operator between the sides is more than `=`.
pub(super) fn compound<D: Doc>(n: &Node<D>, left: &Node<D>, right: &Node<D>) -> bool {
    if matches!(
        n.kind().as_ref(),
        "augmented_assignment_expression"
            | "augmented_assignment"
            | "compound_assignment_expr"
            | "operator_assignment"
    ) {
        return true;
    }
    let start = n.range().start;
    let (from, to) = (left.range().end, right.range().start);
    if from < start || to < from {
        return false;
    }
    let op = n.text()[from - start..to - start].trim().to_string();
    op.len() >= 2
        && op.ends_with('=')
        && !matches!(op.as_str(), "==" | "<=" | ">=" | "!=" | ":=")
        && op[..op.len() - 1]
            .chars()
            .all(|c| "+-*/%|&^<>?.".contains(c))
}
