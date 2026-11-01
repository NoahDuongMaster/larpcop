//! Checks passed to a helper that runs its sink only when the check holds:
//! `readFile(() -> ALLOWED.contains(f), f)` with `if (condition.get())`,
//! `redirect(url, WHITELIST::contains)` with `if (validator.apply(url))`,
//! `ping(ip, validator.get())` with `if (isValid)`. The callee's summary
//! records which parameter guards a sink (and what it is applied to); the
//! caller's argument is then judged with the rule's guards.

use super::guards::{Check, safe};
use crate::rules::complexity::is_function;
use ast_grep_core::{Doc, Node};
use std::collections::HashSet;

/// Calls that run a function-typed parameter: Java's functional interfaces,
/// and a plain call (`cond()`) elsewhere.
const RUNS: [&str; 6] = ["get", "test", "getAsBoolean", "apply", "call", "invoke"];
/// Methods that, given by reference (`ALLOWED::contains`), check their argument.
const CHECKS: [&str; 6] = [
    "contains",
    "containsKey",
    "equals",
    "equalsIgnoreCase",
    "matches",
    "contentEquals",
];
const LAMBDAS: [&str; 3] = ["lambda_expression", "arrow_function", "lambda"];

/// The guarding parameter and the parameter it is applied to, if any.
pub(super) type Condition = (usize, Option<usize>);

/// What decides, in an enclosing `if`, that `at` runs: `if (cond.get())`,
/// `if (validator.apply(url))`, `if (isValid)` on parameters of `f`.
pub(super) fn condition_param<D: Doc>(
    at: &Node<D>,
    f: &Node<D>,
    params: &[String],
) -> Option<Condition> {
    let end = f.range();
    let index = |name: &str| params.iter().position(|p| p == name);
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
        let (called, argument) = match text.split_once('(') {
            Some((callee, rest)) => (callee, rest.trim_end_matches(')')),
            None => (text, ""),
        };
        let name = match called.rsplit_once('.') {
            Some((object, method)) if RUNS.contains(&method) => object,
            None => called,
            _ => continue,
        };
        if let Some(g) = index(name) {
            return Some((g, index(argument)));
        }
    }
    None
}

/// Names the check argument `check` proves safe at `call`, where the callee
/// applies it to `applied` (the caller's argument for that parameter).
pub(super) fn validated<D: Doc>(
    check: &Node<D>,
    applied: Option<&Node<D>>,
    call: &Node<D>,
    checks: &[Check],
) -> HashSet<String> {
    let applied_names = || -> HashSet<String> {
        applied
            .map(|a| {
                a.dfs()
                    .filter(|n| n.kind() == "identifier")
                    .map(|n| n.text().to_string())
                    .collect()
            })
            .unwrap_or_default()
    };
    let kind = check.kind();
    if LAMBDAS.contains(&kind.as_ref()) {
        let Some(value) = returned(check) else {
            return HashSet::new();
        };
        let mut holds = safe(&value, checks).0;
        // `u -> ALLOWED.contains(u)` applied to the caller's `url`.
        let param = check
            .field("parameters")
            .or_else(|| check.field("parameter"))
            .and_then(|p| p.dfs().find(|n| n.kind() == "identifier"));
        if param.is_some_and(|p| holds.contains(p.text().as_ref())) {
            holds.extend(applied_names());
        }
        return holds;
    }
    // `ALLOWED::contains`
    if kind == "method_reference" {
        let text = check.text();
        let method = text.rsplit("::").next().unwrap_or_default().trim();
        return if CHECKS.contains(&method) {
            applied_names()
        } else {
            HashSet::new()
        };
    }
    // A lambda kept in a variable, or called there (`validator.get()`).
    let named = if kind == "identifier" {
        Some(check.text().to_string())
    } else if super::flow::CALLS.contains(&kind.as_ref()) {
        super::summary::callee(check).and_then(|c| {
            c.rsplit_once('.')
                .filter(|(_, m)| RUNS.contains(m))
                .map(|(o, _)| o.to_string())
        })
    } else {
        None
    };
    if let Some(name) = named
        && let Some(lambda) = lambda_named(call, &name)
    {
        return validated(&lambda, applied, call, checks);
    }
    // A plain boolean expression: `ping(ip, ALLOWED.contains(ip))`.
    safe(check, checks).0
}

/// What a lambda returns when it can return true: its expression body, or
/// its one `return` whose value is not `false`.
fn returned<'a, D: Doc>(lambda: &Node<'a, D>) -> Option<Node<'a, D>> {
    let body = lambda.field("body")?;
    if !body.kind().contains("block") {
        return Some(body);
    }
    let values: Vec<Node<D>> = body
        .dfs()
        .filter(|n| matches!(n.kind().as_ref(), "return_statement" | "return"))
        .filter_map(|r| r.children().find(|c| c.is_named()))
        .filter(|v| v.text() != "false")
        .collect();
    match values.as_slice() {
        [only] => Some(only.clone()),
        _ => None,
    }
}

/// `Supplier<Boolean> name = () -> …;` in the function around `at`.
fn lambda_named<'a, D: Doc>(at: &Node<'a, D>, name: &str) -> Option<Node<'a, D>> {
    let f = at.ancestors().find(|a| is_function(a))?;
    f.dfs()
        .filter(|n| matches!(n.kind().as_ref(), "variable_declarator" | "assignment"))
        .find_map(|n| {
            let left = n.field("name").or_else(|| n.field("left"))?;
            let value = n.field("value").or_else(|| n.field("right"))?;
            (left.text() == name && LAMBDAS.contains(&value.kind().as_ref())).then_some(value)
        })
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
