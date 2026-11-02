//! Expressions whose value is a number whatever data went in: PHP
//! arithmetic (`$t + 0`; `.` joins strings), and an argument a format call
//! writes through a numeric placeholder (`sprintf("… id=%d", $t)`,
//! `String.format("%d", n)`). Go's `Sprintf` is left out: `%d` of a string
//! prints the string (`%!d(string=…)`). `%c` writes a character, so it is
//! not one. A count — `len(x)`, `count($x)`, `x.size()` — is a number
//! whatever the data it counted was.

use super::constant::{Env, Value, eval};
use super::summary::{args, called_name};
use crate::rules::complexity::is_function;
use ast_grep_core::{Doc, Node};
use std::ops::Range;
use std::sync::LazyLock;

static PLACEHOLDER: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(
        r"%%|%(\d+\$)?[-+ 0#']*(?:'.)?\d*(?:\.\d+)?(?:hh|h|ll|l|L|q|j|z|t)?([a-zA-Z])",
    )
    .expect("regex")
});

const FORMATS: [&str; 5] = ["sprintf", "printf", "fprintf", "snprintf", "format"];

/// `a + b`, `a * b`… (and `+=` as the operator of an assignment).
pub(super) fn arithmetic<D: Doc>(node: &Node<D>) -> bool {
    node.field("operator").is_some_and(|o| {
        matches!(
            o.text().as_ref(),
            "+" | "-" | "*" | "/" | "%" | "**" | "+=" | "-=" | "*=" | "/=" | "%=" | "**="
        )
    })
}

/// Calls whose result is a count: `len(x)`, `strlen($x)`, `buf.size()`.
const COUNTING: [&str; 14] = [
    "len",
    "__len__",
    "count",
    "strlen",
    "mb_strlen",
    "mb_strwidth",
    "sizeof",
    "size",
    "length",
    "nchar",
    "nbytes",
    "ord",
    "abs",
    "count_chars",
];

/// Is `node` a call of a counting function? Its value is a number, so no
/// text a user wrote can be injected through it.
pub(super) fn counted<D: Doc>(node: &Node<D>) -> bool {
    if !super::flow::CALLS.contains(&node.kind().as_ref()) {
        return false;
    }
    super::summary::called_name(node).is_some_and(|name| {
        let last = name.rsplit('.').next().unwrap_or(&name);
        COUNTING.contains(&last)
    })
}

/// The arguments of format call `call` written through numeric
/// placeholders; `None` when it is not a format call with a known format.
pub(super) fn formatted<D: Doc>(call: &Node<D>) -> Option<Vec<Range<usize>>> {
    if !FORMATS.contains(&called_name(call)?.as_str()) {
        return None;
    }
    let args = args(call);
    let literal = |a: &Node<D>| match eval(&inner(a), &Env::empty(), 0) {
        Some(Value::Str(s)) if s.contains('%') => Some(s),
        _ => None,
    };
    let (at, fmt) = match args
        .iter()
        .enumerate()
        .find_map(|(i, a)| literal(a).map(|s| (i, s)))
    {
        Some(found) => found,
        None => {
            // A format held in a local: `$fmt = "… %d"; sprintf($fmt, $t)`.
            let scope = call.ancestors().find(|a| is_function(a))?;
            let env = Env::new(&scope);
            args.iter()
                .enumerate()
                .find_map(|(i, a)| match eval(&inner(a), &env, 0) {
                    Some(Value::Str(s)) if s.contains('%') => Some((i, s)),
                    _ => None,
                })?
        }
    };
    // Argument index → written as a number everywhere it is placed.
    let mut numeric: std::collections::HashMap<usize, bool> = Default::default();
    let mut next = 0;
    for m in PLACEHOLDER.captures_iter(&fmt) {
        let Some(conv) = m.get(2) else { continue };
        let index = match m.get(1) {
            Some(n) => n
                .as_str()
                .trim_end_matches('$')
                .parse::<usize>()
                .ok()?
                .checked_sub(1)?,
            None => {
                next += 1;
                next - 1
            }
        };
        let number = "bdeEfFgGiouxXaA".contains(conv.as_str());
        *numeric.entry(index).or_insert(true) &= number;
    }
    let out = numeric
        .into_iter()
        .filter(|(_, number)| *number)
        .filter_map(|(i, _)| args.get(at + 1 + i).map(|a| a.range()))
        .collect();
    Some(out)
}

/// PHP and C# wrap an argument: `argument` → the expression.
pub(super) fn inner<'a, D: Doc>(a: &Node<'a, D>) -> Node<'a, D> {
    let named = (a.kind() == "argument").then(|| a.children().find(|c| c.is_named()));
    named.flatten().unwrap_or_else(|| a.clone())
}
