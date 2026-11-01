//! Functions whose behaviour a flag parameter picks:
//! `add_guestbook($name, $comment, $vuln = False)` escaping unless `$vuln`.
//! Such a function gets one more summary per value of the flag,
//! `name!k=true` and `name!k=false`, walked with the branches that value
//! decides dropped (deadcode.rs), and `name!k` for the value it defaults to.
//! A call passing a literal `true`/`false` as argument `k`, or leaving out a
//! parameter that defaults to one, uses it.

use super::constant::{Env, Value, eval};
use super::flow::Ctx;
use super::kotlin::Part;
use super::summary::Summary;
use ast_grep_core::{Doc, Node};

/// Branching kinds whose condition a flag can be.
const DECIDING: [&str; 4] = [
    "if_statement",
    "conditional_expression",
    "ternary_expression",
    "else_if_clause",
];

/// At most this many flags per function get their own summaries.
const MAX_FLAGS: usize = 2;

/// Parameters of `f` that alone decide a branch (`if ($vuln)`,
/// `if (!debug)`) and are never assigned in it: (index, the literal value it
/// defaults to).
pub(super) fn flags<D: Doc>(f: &Node<D>, params: &[String]) -> Vec<(usize, Option<bool>)> {
    let deciding: Vec<String> = f
        .dfs()
        .filter(|n| DECIDING.contains(&n.kind().as_ref()))
        .filter_map(|n| n.part("condition"))
        .filter_map(|c| bare(&c))
        .collect();
    if deciding.is_empty() {
        return Vec::new();
    }
    let env = Env::new(f);
    params
        .iter()
        .enumerate()
        .filter(|(_, p)| !p.is_empty() && deciding.contains(p) && !env.writes(p))
        .map(|(k, p)| (k, default(f, p)))
        .take(MAX_FLAGS)
        .collect()
}

/// The name a condition tests as it is: `($vuln)`, `(!debug)`, `not flag`.
fn bare<D: Doc>(c: &Node<D>) -> Option<String> {
    match c.kind().as_ref() {
        "identifier" | "variable_name" | "simple_identifier" => Some(c.text().to_string()),
        "parenthesized_expression"
        | "unary_op_expression"
        | "unary_expression"
        | "prefix_unary_expression"
        | "not_operator" => {
            let mut named = c.children().filter(|x| x.is_named());
            let only = named.next()?;
            named.next().is_none().then_some(())?;
            bare(&only)
        }
        _ => None,
    }
}

/// The literal `true`/`false` parameter `p` of `f` defaults to.
fn default<D: Doc>(f: &Node<D>, p: &str) -> Option<bool> {
    let list = f.part("parameters")?;
    list.children().find_map(|param| {
        let name = ["name", "pattern", "left"]
            .iter()
            .find_map(|k| param.part(k))?;
        if name.text() != p {
            return None;
        }
        let value = ["default_value", "value", "right"]
            .iter()
            .find_map(|k| param.part(k))?;
        match eval(&value, &Env::empty(), 0)? {
            Value::Bool(b) => Some(b),
            _ => None,
        }
    })
}

/// The key of `name`'s summary with its parameter `k` set to `value`, or to
/// its default.
pub(super) fn key(name: &str, k: usize, value: Option<bool>) -> String {
    match value {
        Some(v) => format!("{name}!{k}={v}"),
        None => format!("{name}!{k}"),
    }
}

impl Ctx {
    /// `name`'s summary for a `call` that sets one of its flags.
    pub(super) fn flagged<D: Doc>(&self, name: &str, call: &Node<D>) -> Option<&Summary> {
        let args = super::summary::args(call);
        // Left-out arguments: up to a few past the last one given.
        (0..args.len() + 4).find_map(|k| {
            let value = match args.get(k) {
                Some(a) => match eval(&super::numeric::inner(a), &Env::empty(), 0) {
                    Some(Value::Bool(b)) => Some(b),
                    _ => return None,
                },
                None => None,
            };
            self.summaries.get(&key(name, k, value))
        })
    }
}
