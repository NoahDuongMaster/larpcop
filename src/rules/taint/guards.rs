//! Validation in `if` conditions. A `guards:` pattern is true when the value
//! is safe (`isLocalUrl(u)`, `allowed.includes(h)`), a `rejects:` pattern when
//! it is not (`name.includes("..")`). The condition is read with its `!`,
//! `&&`, `||` and comparisons to `false`/`-1`, giving the names that are safe
//! when it holds (clean in the `then` branch, and after the `if` when the
//! `else` leaves) and those safe when it fails (clean in the `else` branch,
//! and after the `if` when the `then` branch leaves: `if (!ok(u)) return;`).

use super::NAMES;
use ast_grep_core::{Doc, Node};
use std::collections::HashSet;
use std::ops::Range;

/// Ruby's `unless` and `… unless c` read their condition the other way round.
pub(super) const IFS: [&str; 6] = [
    "if_statement",
    "if_expression",
    "if",
    "unless",
    "if_modifier",
    "unless_modifier",
];
/// Calls that end the request: PHP `die()`, Go `panic()`, Flask `abort()`.
const EXIT_CALLS: [&str; 14] = [
    "raise ",
    "raise(",
    "fail ",
    "halt",
    "die(",
    "exit(",
    "panic(",
    "abort(",
    "sys.exit(",
    "os.Exit(",
    "process.exit(",
    "log.Fatal(",
    "log.Fatalf(",
    "log.Fatalln(",
];
const EXITS: [&str; 8] = [
    "exit_statement",
    "return",
    "return_statement",
    "return_expression",
    "throw_statement",
    "raise_statement",
    "continue_statement",
    "break_statement",
];
/// Negations: JS/TS/Java/Go/Rust `!x`, C# `!x`, PHP `!x`, Python `not x`.
const NOTS: [&str; 6] = [
    "unary",
    "unary_expression",
    "prefix_unary_expression",
    "unary_op_expression",
    "not_operator",
    "prefix_expression",
];
const BINARIES: [&str; 5] = [
    "binary",
    "binary_expression",
    "boolean_operator",
    "comparison_operator",
    "binary_op_expression",
];
/// Blocks that may end in the exit: Go's `statement_list`, the block of an `else`.
const BLOCKS: [&str; 5] = [
    "statement_list",
    "block",
    "statement_block",
    "compound_statement",
    "else_clause",
];

/// A guard match: its range, whether it holds when the value is safe
/// (`guards:`) rather than unsafe (`rejects:`), and its pattern's specificity.
pub(super) type Check = (Range<usize>, bool, usize);

/// Names clean from an offset to the end of the scope, or within a range.
pub(super) enum Guard {
    After(usize, HashSet<String>),
    Within(Range<usize>, HashSet<String>),
    /// Safe where the `if` is not taken: a clean value the branch assigns
    /// them is clean after it too (`if (!ok(x)) { x = fallback; }`).
    Settle(Range<usize>, HashSet<String>),
}

/// The guards an `if` node sets up.
pub(super) fn of<D: Doc>(n: &Node<D>, checks: &[Check]) -> Vec<Guard> {
    let mut out = Vec::new();
    if checks.is_empty() || !IFS.contains(&n.kind().as_ref()) {
        return out;
    }
    let (Some(condition), Some(then)) = (
        n.field("condition"),
        // PHP names the branch `body`.
        n.field("consequence").or_else(|| n.field("body")),
    ) else {
        return out;
    };
    let (holds, fails) = safe(&condition, checks);
    let (holds, fails) = if n.kind().starts_with("unless") {
        (fails, holds)
    } else {
        (holds, fails)
    };
    let otherwise = n.field("alternative");
    if exits(&then) && !fails.is_empty() {
        out.push(Guard::After(n.range().end, fails.clone()));
    } else if otherwise.is_none() && !fails.is_empty() {
        out.push(Guard::Settle(n.range(), fails.clone()));
    }
    if let Some(alt) = &otherwise
        && !matches!(
            alt.kind().as_ref(),
            "elif_clause" | "else_if_clause" | "if_statement"
        )
        && exits(alt)
        && !holds.is_empty()
    {
        out.push(Guard::After(n.range().end, holds.clone()));
    }
    if !holds.is_empty() {
        out.push(Guard::Within(then.range(), holds));
    }
    if let Some(alt) = otherwise
        && !fails.is_empty()
    {
        // Every `elif`/`else` from the first alternative on runs on failure.
        out.push(Guard::Within(alt.range().start..n.range().end, fails));
    }
    out
}

type Sets = (HashSet<String>, HashSet<String>);

/// Names safe when `n` is true, and names safe when it is false.
pub(super) fn safe<D: Doc>(n: &Node<D>, checks: &[Check]) -> Sets {
    let range = n.range();
    // Of a guard and a reject matching the same node (`$A.includes($B)`,
    // `$P.includes("$S")`), the more specific pattern wins; a tie rejects.
    let exact = checks
        .iter()
        .filter(|(r, ..)| *r == range)
        .max_by_key(|(_, safe, weight)| (*weight, !*safe));
    if let Some((_, safe, _)) = exact {
        let names = names(n);
        return if *safe {
            (names, HashSet::new())
        } else {
            (HashSet::new(), names)
        };
    }
    if !checks
        .iter()
        .any(|(r, ..)| range.start <= r.start && r.end <= range.end)
    {
        return Default::default();
    }
    let kind = n.kind();
    let named: Vec<Node<D>> = n.children().filter(|c| c.is_named()).collect();
    if NOTS.contains(&kind.as_ref()) && n.text().trim_start().starts_with(['!', 'n']) {
        return named
            .last()
            .map(|o| swap(safe(o, checks)))
            .unwrap_or_default();
    }
    if BINARIES.contains(&kind.as_ref())
        && let (Some(l), Some(r)) = (
            n.field("left").or_else(|| named.first().cloned()),
            n.field("right").or_else(|| named.get(1).cloned()),
        )
        // Python's comparison_operator names no operands: `a != b`, two children.
        && (n.field("left").is_some() || named.len() == 2)
    {
        return binary(&operator(n, &l, &r), &l, &r, checks);
    }
    match named.as_slice() {
        // Parentheses and other wrappers.
        [only] => safe(only, checks),
        _ => Default::default(),
    }
}

fn binary<'a, D: Doc>(op: &str, l: &Node<'a, D>, r: &Node<'a, D>, checks: &[Check]) -> Sets {
    match op {
        "&&" | "and" => {
            let ((lh, lf), (rh, rf)) = (safe(l, checks), safe(r, checks));
            (&lh | &rh, &lf & &rf)
        }
        "||" | "or" => {
            let ((lh, lf), (rh, rf)) = (safe(l, checks), safe(r, checks));
            (&lh & &rh, &lf | &rf)
        }
        _ => {
            // `check(x) === false`, `s.indexOf("..") !== -1`, `i < 0`.
            let (value, constant) = if is_constant(r) {
                (l, r.text().to_string())
            } else {
                (r, l.text().to_string())
            };
            let negative = matches!(
                constant.as_str(),
                "false" | "False" | "-1" | "null" | "nil" | "None" | "\"\"" | "''"
            );
            let flip = match op {
                "==" | "===" | "is" => negative,
                "!=" | "!==" | "is not" => !negative && constant != "0",
                "<" | "<=" => constant == "0",
                _ => false,
            };
            let sets = safe(value, checks);
            if flip { swap(sets) } else { sets }
        }
    }
}

/// The text between the operands: `&&`, `===`, `is not`.
fn operator<'a, D: Doc>(n: &Node<'a, D>, l: &Node<'a, D>, r: &Node<'a, D>) -> String {
    let start = n.range().start;
    n.text()[l.range().end - start..r.range().start - start]
        .trim()
        .to_string()
}

fn is_constant<D: Doc>(n: &Node<D>) -> bool {
    matches!(
        n.text().as_ref(),
        "true" | "false" | "True" | "False" | "null" | "nil" | "None" | "-1" | "0" | "\"\"" | "''"
    )
}

fn swap((a, b): Sets) -> Sets {
    (b, a)
}

fn names<D: Doc>(n: &Node<D>) -> HashSet<String> {
    n.dfs()
        .filter(|c| NAMES.contains(&c.kind().as_ref()))
        .map(|c| c.text().to_string())
        .collect()
}

/// Does this branch always leave (return, throw, …)?
fn exits<D: Doc>(branch: &Node<D>) -> bool {
    if EXITS.contains(&branch.kind().as_ref()) {
        return true;
    }
    let last = branch
        .children()
        .filter(|c| c.is_named() && c.kind() != "comment")
        .last();
    last.is_some_and(|l| {
        (BLOCKS.contains(&l.kind().as_ref()) && exits(&l))
            || EXITS.contains(&l.kind().as_ref())
            || (l.kind() == "expression_statement"
                && l.children().any(|c| EXITS.contains(&c.kind().as_ref())))
            || (matches!(l.kind().as_ref(), "expression_statement" | "call" | "identifier")
                && EXIT_CALLS.iter().any(|e| l.text().starts_with(e)))
            // Ruby: `redirect_to root_path and return`.
            || (l.kind() == "binary"
                && l.field("right").is_some_and(|r| EXITS.contains(&r.kind().as_ref())))
    })
}
