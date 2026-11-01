//! An `if` with an `else` whose every branch assigns a name: after it the
//! name holds what one of the branches assigned, never what it held before
//! (`if (settype($t, "integer")) $t = $t; else $t = 0;`). A branch that
//! exits (`return`, `throw`, `die()`) assigns everything. The walk keeps
//! such a name clean after the `if` unless an assignment inside it tainted
//! the name (walk.rs).

use super::flow::assignment;
use super::kotlin::Part;
use ast_grep_core::{Doc, Node};
use std::collections::HashSet;

/// What a branch assigns at its top level; `None` when it exits.
type Assigned = Option<HashSet<String>>;

/// The names every branch of if-node `n` assigns, when it has an `else`.
pub(super) fn both<D: Doc>(n: &Node<D>) -> Option<HashSet<String>> {
    if !matches!(n.kind().as_ref(), "if_statement" | "if_expression" | "if") {
        return None;
    }
    let then = n.part("consequence").or_else(|| n.part("body"))?;
    let mut acc = assigned(&then);
    let mut otherwise = false;
    for alt in n.field_children("alternative") {
        let branch = match alt.kind().as_ref() {
            "else_clause" | "else" => {
                otherwise = true;
                let body = alt
                    .part("body")
                    .or_else(|| alt.children().find(|c| c.is_named()))?;
                // JS/Java `else if (…) {…} else {…}`: the nested `if` as a whole.
                if matches!(body.kind().as_ref(), "if_statement" | "if_expression") {
                    Some(both(&body)?)
                } else {
                    assigned(&body)
                }
            }
            "elif_clause" | "else_if_clause" => {
                assigned(&alt.part("consequence").or_else(|| alt.part("body"))?)
            }
            _ => return None,
        };
        acc = meet(acc, branch);
    }
    if !otherwise {
        return None;
    }
    acc.filter(|names| !names.is_empty())
}

fn meet(a: Assigned, b: Assigned) -> Assigned {
    match (a, b) {
        (None, b) => b,
        (a, None) => a,
        (Some(a), Some(b)) => Some(a.intersection(&b).cloned().collect()),
    }
}

/// The names a branch assigns as statements of its own (not in nested blocks).
fn assigned<D: Doc>(branch: &Node<D>) -> Assigned {
    let statements: Vec<Node<D>> =
        if branch.kind().contains("block") || branch.kind() == "compound_statement" {
            branch.children().filter(|c| c.is_named()).collect()
        } else {
            vec![branch.clone()]
        };
    let mut out = HashSet::new();
    for s in statements {
        if super::exits::exits(&s) {
            return None;
        }
        let named = (s.kind() == "expression_statement")
            .then(|| s.children().find(|c| c.is_named()))
            .flatten();
        let inner = named.unwrap_or(s);
        if let Some((left, _)) = assignment(&inner)
            && super::NAMES.contains(&left.kind().as_ref())
        {
            out.insert(left.text().to_string());
        }
    }
    Some(out)
}
