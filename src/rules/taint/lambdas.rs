//! Checks passed as a function: `readFile(() -> ALLOWED.contains(f), f)`
//! where `readFile(cond, name)` reads `name` only `if (cond.get())`. The
//! callee's summary records which parameter's call guards a sink; the caller's
//! lambda is then judged with the rule's guards.

use super::guards::{Check, safe};
use ast_grep_core::{Doc, Node};
use std::collections::HashSet;

/// Calls that run a function-typed parameter: Java's functional interfaces,
/// and a plain call (`cond()`) elsewhere.
const RUNS: [&str; 6] = ["get", "test", "getAsBoolean", "apply", "call", "invoke"];

/// The parameter (by index) whose call decides, in an enclosing `if`, that
/// `at` runs: `if (condition.get()) { … at … }`.
pub(super) fn condition_param<D: Doc>(
    at: &Node<D>,
    f: &Node<D>,
    params: &[String],
) -> Option<usize> {
    let end = f.range();
    for a in at.ancestors().take_while(|a| a.range() != end) {
        if a.kind() != "if_statement" {
            continue;
        }
        let (Some(cond), Some(then)) = (a.field("condition"), a.field("consequence")) else {
            continue;
        };
        let r = at.range();
        if !(then.range().start <= r.start && r.end <= then.range().end) {
            continue;
        }
        let text: String = cond.text().chars().filter(|c| !c.is_whitespace()).collect();
        let text = text.trim_start_matches('(').trim_end_matches(')');
        let called = match text.split_once('(') {
            Some((callee, rest)) if rest.ends_with(')') || rest.is_empty() => callee,
            _ => continue,
        };
        let name = match called.rsplit_once('.') {
            Some((object, method)) if RUNS.contains(&method) => object,
            None => called,
            _ => continue,
        };
        if let Some(i) = params.iter().position(|p| p == name) {
            return Some(i);
        }
    }
    None
}

/// Names a lambda argument proves safe when it returns true: its expression
/// body, or the value of its only `return`.
pub(super) fn validated<D: Doc>(lambda: &Node<D>, checks: &[Check]) -> HashSet<String> {
    if !matches!(
        lambda.kind().as_ref(),
        "lambda_expression" | "arrow_function" | "lambda"
    ) {
        return HashSet::new();
    }
    let Some(body) = lambda.field("body") else {
        return HashSet::new();
    };
    let value = if body.kind().contains("block") {
        let returns: Vec<Node<D>> = body
            .dfs()
            .filter(|n| matches!(n.kind().as_ref(), "return_statement" | "return"))
            .collect();
        match returns.as_slice() {
            [only] => match only.children().find(|c| c.is_named()) {
                Some(v) => v,
                None => return HashSet::new(),
            },
            _ => return HashSet::new(),
        }
    } else {
        body
    };
    safe(&value, checks).0
}

/// Is every tainted name in `arg` among `safe`?
pub(super) fn covers<D: Doc>(
    arg: &Node<D>,
    names: &HashSet<String>,
    safe: &HashSet<String>,
) -> bool {
    let used: Vec<String> = arg
        .dfs()
        .filter(|n| n.kind() == "identifier" && names.contains(n.text().as_ref()))
        .map(|n| n.text().to_string())
        .collect();
    !used.is_empty() && used.iter().all(|n| safe.contains(n))
}
