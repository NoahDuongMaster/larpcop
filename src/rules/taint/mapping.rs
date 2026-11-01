//! A mapping call's parts, in every language, and what its callback returns:
//! - `recv.map(cb)` (JS/TS, Java), `recv.Select(cb)` (C#),
//!   `recv.map { … }` (Ruby, Kotlin), `map(cb, recv)` (Python),
//!   `array_map(cb, $recv)` (PHP);
//! - a callback is a lambda (expression or statements) or a reference to a
//!   function (`Encode::forHtml`, `::esc`, `html.escape`, `'htmlspecialchars'`).
//!
//! In a lambda with statements, locals are followed in order (an assignment
//! in a branch can taint but not clean) and every `return` counts; a Kotlin
//! or Ruby block's last statement is its value too.

use super::flow::Ctx;
use super::kotlin::Part;
use super::summary::param_names;
use crate::rules::complexity::is_function;
use ast_grep_core::{Doc, Node};
use std::collections::HashSet;

/// Methods mapping a collection to their callback's values.
pub(super) const MAPS: [&str; 10] = [
    "map",
    "flatMap",
    "flat_map",
    "collect",
    "filter_map",
    "collect_concat",
    "mapNotNull",
    "Select",
    "SelectMany",
    "array_map",
];

/// Receiver, method name and callback of a mapping call.
pub(super) fn parts<'a, D: Doc>(call: &Node<'a, D>) -> Option<(Node<'a, D>, String, Node<'a, D>)> {
    let named = |n: &Node<'a, D>| -> Vec<Node<'a, D>> {
        n.children()
            .filter(|c| c.is_named() && !c.kind().contains("comment"))
            // C# `argument`, PHP `argument`, Kotlin `value_argument`.
            .map(|c| {
                let inner = matches!(c.kind().as_ref(), "argument" | "value_argument")
                    .then(|| c.children().find(|x| x.is_named()))
                    .flatten();
                inner.unwrap_or(c)
            })
            .collect()
    };
    match call.kind().as_ref() {
        // Java `recv.map(cb)`.
        "method_invocation" => {
            let args = named(&call.part("arguments")?);
            Some((
                call.part("object")?,
                call.part("name")?.text().to_string(),
                args.first()?.clone(),
            ))
        }
        // Ruby `recv.map { |x| … }`.
        "call" if call.part("block").is_some() => Some((
            call.part("receiver")?,
            call.part("method")?.text().to_string(),
            call.part("block")?,
        )),
        // Kotlin `recv.map { … }`, `recv.map(::f)`.
        "call_expression" if call.field("function").is_none() => {
            let nav = call
                .children()
                .find(|c| c.kind() == "navigation_expression")?;
            let receiver = nav.children().find(|c| c.is_named())?;
            let method = nav.children().find(|c| c.kind() == "navigation_suffix")?;
            let method = method.children().find(|c| c.is_named())?.text().to_string();
            let suffix = call.children().find(|c| c.kind() == "call_suffix")?;
            let callback = match suffix.children().find(|c| c.kind() == "annotated_lambda") {
                Some(l) => l.children().find(|c| c.kind() == "lambda_literal")?,
                None => named(&suffix.children().find(|c| c.kind() == "value_arguments")?)
                    .first()?
                    .clone(),
            };
            Some((receiver, method, callback))
        }
        _ => {
            let function = call.part("function")?;
            let args = named(&call.part("arguments")?);
            match function.kind().as_ref() {
                // Python `map(cb, recv)`, PHP `array_map(cb, $recv)`.
                "identifier" | "name" => {
                    let method = function.text().to_string();
                    let [cb, recv, ..] = args.as_slice() else {
                        return None;
                    };
                    (method == "map" || method == "array_map")
                        .then(|| (recv.clone(), method, cb.clone()))
                }
                // JS `recv.map(cb)`, C# `recv.Select(cb)`.
                _ => {
                    let receiver = function
                        .part("object")
                        .or_else(|| function.part("expression"))?;
                    let method = function
                        .part("property")
                        .or_else(|| function.part("name"))?;
                    Some((receiver, method.text().to_string(), args.first()?.clone()))
                }
            }
        }
    }
}

/// The names a rule's sanitizers are called by: `forHtml` of
/// `Encode.forHtml($X)` (a call with arguments; `encoder()` of
/// `ESAPI.encoder().encodeForHTML($X)` is not one), and `sanitizer_names`.
#[derive(Default)]
pub(crate) struct Cleaners {
    names: HashSet<String>,
    re: Option<regex::Regex>,
}

impl Cleaners {
    pub(crate) fn new(patterns: &[String], re: Option<regex::Regex>) -> Self {
        let call = regex::Regex::new(r"(\w+)\s*\(\s*[^)\s]").expect("regex");
        let names = patterns
            .iter()
            .flat_map(|p| {
                call.captures_iter(p)
                    .map(|c| c[1].to_string())
                    .collect::<Vec<_>>()
            })
            .collect();
        Cleaners { names, re }
    }

    fn cleans(&self, name: &str) -> bool {
        self.names.contains(name) || self.re.as_ref().is_some_and(|re| re.is_match(name))
    }
}

const LAMBDAS: [&str; 9] = [
    "arrow_function",
    "function_expression",
    "lambda_expression",
    "lambda",
    "lambda_literal",
    "block",
    "do_block",
    "anonymous_function",
    "anonymous_function_creation_expression",
];

/// Does `callback` return tainted data, its elements being tainted when
/// `elements` is? `None` when it is not a callback we can read.
pub(super) fn returns<D: Doc>(
    ctx: &Ctx,
    callback: &Node<D>,
    elements: bool,
    names: &HashSet<String>,
) -> Option<bool> {
    if !LAMBDAS.contains(&callback.kind().as_ref()) {
        return reference(ctx, callback).map(|passes| elements && passes);
    }
    let params = param_names(callback);
    let mut inner = names.clone();
    if elements {
        inner.extend(params);
    } else {
        inner.retain(|n| !params.contains(n));
    }
    let body = match callback.kind().as_ref() {
        "lambda_literal" => callback
            .children()
            .find(|c| c.kind() == "statements")
            .unwrap_or_else(|| callback.clone()),
        "block" | "do_block" => callback.part("body").unwrap_or_else(|| callback.clone()),
        _ => callback.part("body")?,
    };
    let statements = matches!(
        body.kind().as_ref(),
        "statement_block"
            | "block"
            | "statements"
            | "block_body"
            | "body_statement"
            | "compound_statement"
    );
    if !statements {
        return Some(ctx.tainted(&body, &inner));
    }
    Some(flow(ctx, &body, inner))
}

/// Follows a callback's statements; true when a value it returns is tainted.
fn flow<D: Doc>(ctx: &Ctx, body: &Node<D>, mut names: HashSet<String>) -> bool {
    let mut tainted = false;
    let nested = |n: &Node<D>| {
        n.ancestors()
            .take_while(|a| a.range() != body.range())
            .any(|a| is_function(&a))
    };
    for n in body.dfs().filter(|n| !nested(n)) {
        let kind = n.kind();
        if let Some((left, right)) = super::flow::assignment(&n)
            && matches!(
                left.kind().as_ref(),
                "identifier" | "simple_identifier" | "variable_name"
            )
        {
            if ctx.tainted(&right, &names) {
                names.insert(left.text().to_string());
            } else if !branched(&n, body) {
                names.remove(left.text().as_ref());
            }
        } else if matches!(kind.as_ref(), "return_statement" | "return" | "next")
            || (kind == "jump_expression" && n.text().starts_with("return"))
        {
            tainted |= n
                .children()
                .filter(|c| c.is_named())
                .any(|v| ctx.tainted(&v, &names));
        }
    }
    // Kotlin and Ruby blocks: the last statement is the value.
    if matches!(
        body.kind().as_ref(),
        "statements" | "block_body" | "body_statement"
    ) && let Some(last) = body.children().filter(|c| c.is_named()).last()
    {
        tainted |= ctx.tainted(&last, &names);
    }
    tainted
}

/// Is `n` under a branch or loop of `body`?
fn branched<D: Doc>(n: &Node<D>, body: &Node<D>) -> bool {
    n.ancestors()
        .take_while(|a| a.range() != body.range())
        .any(|a| {
            super::paths::CONDITIONAL.contains(&a.kind().as_ref())
                || super::flow::LOOPS.contains(&a.kind().as_ref())
        })
}

/// A function passed by reference: does it pass its argument through?
/// A sanitizer does not; a function we have a summary for does when it
/// returns its parameter; any other one (a library's) is assumed to.
fn reference<D: Doc>(ctx: &Ctx, r: &Node<D>) -> Option<bool> {
    let text = r.text();
    let name = match r.kind().as_ref() {
        "method_reference" | "callable_reference" => text.rsplit("::").next()?.trim().to_string(),
        "identifier"
        | "attribute"
        | "member_expression"
        | "member_access_expression"
        | "simple_identifier" => text.rsplit('.').next()?.to_string(),
        // PHP `'htmlspecialchars'`.
        "string" | "encapsed_string" => text.trim_matches(['\'', '"']).to_string(),
        _ => return None,
    };
    if name.is_empty() || !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
        return None;
    }
    if ctx.cleaners.cleans(&name) {
        return Some(false);
    }
    let summary = ctx.summaries.get(&name).or_else(|| {
        ctx.summaries
            .iter()
            .find(|(k, _)| k.rsplit('.').next() == Some(name.as_str()))
            .map(|(_, s)| s)
    });
    Some(summary.is_none_or(|s| s.returns.contains(&0) || s.returns_source))
}
