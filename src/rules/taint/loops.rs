//! A loop's condition holds in its body and fails after it, unless the body
//! `break`s out: after `while (p.contains("..")) p = p.replace("..", "");`
//! `p` holds no `..`. `do … while` and Ruby `until`/`… while c` too.

use super::guards::{Check, Guard};
use super::kotlin::Part;
use ast_grep_core::{Doc, Node};

/// Loops ending when their condition fails: Ruby `until` the other way round.
pub(super) const WHILES: [&str; 8] = [
    "while_statement",
    "while_expression",
    "do_statement",
    "do_while_statement",
    "while",
    "until",
    "while_modifier",
    "until_modifier",
];

/// A loop's condition: true in the body, false after the loop when nothing
/// in the body `break`s out of it.
pub(super) fn guards<D: Doc>(n: &Node<D>, checks: &[Check]) -> Vec<Guard> {
    let (Some(condition), Some(body)) = (n.part("condition"), n.part("body")) else {
        return Vec::new();
    };
    let (holds, fails) = super::guards::safe(&condition, checks);
    let (holds, fails) = if n.kind().starts_with("until") {
        (fails, holds)
    } else {
        (holds, fails)
    };
    let mut out = Vec::new();
    let breaks = body.dfs().any(|b| {
        matches!(
            b.kind().as_ref(),
            "break_statement" | "break" | "break_expression"
        ) && b
            .ancestors()
            .take_while(|a| a.range() != n.range())
            .all(|a| {
                !WHILES.contains(&a.kind().as_ref())
                    && !super::flow::LOOPS.contains(&a.kind().as_ref())
                    && !super::switches::SWITCHES.contains(&a.kind().as_ref())
            })
    });
    if !breaks && !fails.is_empty() {
        out.push(Guard::After(n.range().end, fails));
    }
    if !holds.is_empty() && !n.kind().starts_with("do") {
        out.push(Guard::Within(body.range(), holds));
    }
    out
}
