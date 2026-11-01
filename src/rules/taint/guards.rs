//! Validation in `if` conditions. A `guards:` pattern is true when the value
//! is safe (`isLocalUrl(u)`, `allowed.includes(h)`), a `rejects:` pattern when
//! it is not (`name.includes("..")`). The condition is read with its `!`,
//! `&&`, `||` and comparisons to `false`/`-1`, giving the names that are safe
//! when it holds (clean in the `then` branch, and after the `if` when the
//! `else` leaves) and those safe when it fails (clean in the `else` branch,
//! and after the `if` when the `then` branch leaves: `if (!ok(u)) return;`).
//! Loops read their condition the same way (loops.rs).

use super::NAMES;
use super::kotlin::Part;
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
/// Negations: JS/TS/Java/Go/Rust `!x`, C# `!x`, PHP `!x`, Python `not x`.
const NOTS: [&str; 6] = [
    "unary",
    "unary_expression",
    "prefix_unary_expression",
    "unary_op_expression",
    "not_operator",
    "prefix_expression",
];
const BINARIES: [&str; 9] = [
    "binary",
    "binary_expression",
    "boolean_operator",
    "comparison_operator",
    "binary_op_expression",
    // Kotlin `&&`, `||`, `==`, `<`.
    "conjunction_expression",
    "disjunction_expression",
    "equality_expression",
    "comparison_expression",
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

/// The guards an `if` node sets up, or the arms of a `switch`.
pub(super) fn of<D: Doc>(n: &Node<D>, checks: &[Check]) -> Vec<Guard> {
    if super::switches::SWITCHES.contains(&n.kind().as_ref()) {
        return super::switches::arms(n);
    }
    if super::loops::WHILES.contains(&n.kind().as_ref()) {
        return super::loops::guards(n, checks);
    }
    let mut out = Vec::new();
    if !IFS.contains(&n.kind().as_ref()) {
        return out;
    }
    let (Some(condition), Some(then)) = (
        n.part("condition"),
        // PHP names the branch `body`.
        n.part("consequence").or_else(|| n.part("body")),
    ) else {
        return out;
    };
    let text = condition.text();
    if checks.is_empty() && !text.contains("==") && !text.contains("!=") {
        return out;
    }
    let (holds, fails) = safe(&condition, checks);
    let (holds, fails) = if n.kind().starts_with("unless") {
        (fails, holds)
    } else {
        (holds, fails)
    };
    let otherwise = n.part("alternative");
    if super::exits::exits(&then) && !fails.is_empty() {
        out.push(Guard::After(n.range().end, fails.clone()));
    } else if otherwise.is_none() && !fails.is_empty() {
        out.push(Guard::Settle(n.range(), fails.clone()));
    }
    if let Some(alt) = &otherwise
        && !matches!(
            alt.kind().as_ref(),
            "elif_clause" | "else_if_clause" | "if_statement"
        )
        && super::exits::exits(alt)
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

pub(super) type Sets = (HashSet<String>, HashSet<String>);

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
        return if *safe {
            let mut held = super::membership::members(n).unwrap_or_else(|| names(n));
            held.extend(super::prefix::derived(n));
            (held, HashSet::new())
        } else {
            // `x not in allowed` rejects `x`; `".." in p`, `p.includes("..")` reject `p`.
            let needle = super::membership::not_in(n).or_else(|| super::membership::haystack(n));
            (HashSet::new(), needle.unwrap_or_else(|| names(n)))
        };
    }
    // Nothing to read: no configured check in it, no comparison with a literal.
    if !checks
        .iter()
        .any(|(r, ..)| range.start <= r.start && r.end <= range.end)
        && !n.text().contains("==")
        && !n.text().contains("!=")
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
            n.part("left").or_else(|| named.first().cloned()),
            n.part("right").or_else(|| named.get(1).cloned()),
        )
        // Python's comparison_operator names no operands: `a != b`, two children.
        && (n.part("left").is_some() || named.len() == 2)
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
            if let Some(sets) = super::equality::literal(op, l, r) {
                return sets;
            }
            // `check(x) === false`, `s.indexOf("..") !== -1`, `i < 0`,
            // PHP `preg_match(…) == 1`.
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
        "true"
            | "false"
            | "True"
            | "False"
            | "null"
            | "nil"
            | "None"
            | "-1"
            | "0"
            | "1"
            | "\"\""
            | "''"
    )
}

fn swap((a, b): Sets) -> Sets {
    (b, a)
}

pub(super) fn names<D: Doc>(n: &Node<D>) -> HashSet<String> {
    n.dfs()
        .filter(|c| NAMES.contains(&c.kind().as_ref()))
        .map(|c| c.text().to_string())
        .collect()
}
