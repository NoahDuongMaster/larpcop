//! Where functions are defined: named functions, methods (also known as
//! `Class.method`), Rails scopes, and their parameters.

use crate::rules::complexity::is_function;
use ast_grep_core::{Doc, Node};
use std::collections::HashSet;

/// Named functions defined in `root`: (name, function node, parameter names).
pub fn functions<'a, D: Doc>(root: &Node<'a, D>) -> Vec<(String, Node<'a, D>, Vec<String>)> {
    let mut out: Vec<(String, Node<'a, D>, Vec<String>)> = named(root).collect();
    // Methods are also known as `Class.method`, the way callers outside name them.
    let qualified: Vec<_> = out
        .iter()
        .filter_map(|(name, f, p)| Some((format!("{}.{name}", class_of(f)?), f.clone(), p.clone())))
        .collect();
    out.extend(qualified);
    out
}

/// The class a method is defined in: the enclosing class, the receiver type
/// of a Go method (`func (p *Profile) Load()`), the type of a Rust `impl`.
pub(super) fn class_of<D: Doc>(f: &Node<D>) -> Option<String> {
    if f.kind() == "method_declaration"
        && let Some(receiver) = f.field("receiver")
    {
        let ty = receiver.dfs().find(|n| n.kind() == "type_identifier")?;
        return Some(ty.text().to_string());
    }
    let class = f.ancestors().take_while(|a| !is_function(a)).find(|a| {
        matches!(
            a.kind().as_ref(),
            "class_definition" | "class_declaration" | "class" | "impl_item"
        )
    })?;
    let name = class.field("name").or_else(|| class.field("type"))?;
    Some(name.text().split('<').next()?.trim().to_string())
}

/// No body (`void run(String x);`), or one that only stands in for an
/// implementation (`pass`, `...`, `raise NotImplementedError`).
pub(super) fn bodiless<D: Doc>(f: &Node<D>) -> bool {
    let Some(body) = f.field("body") else {
        return !matches!(
            f.kind().as_ref(),
            "arrow_function" | "lambda" | "lambda_expression"
        );
    };
    let statements: Vec<Node<D>> = body
        .children()
        .filter(|c| c.is_named() && c.kind() != "comment")
        .collect();
    // `{}` really does nothing.
    !statements.is_empty()
        && statements.iter().all(|c| {
            let text = c.text();
            matches!(c.kind().as_ref(), "pass_statement")
                || text == "..."
                || (c.kind() == "raise_statement" && text.contains("NotImplementedError"))
                || (c.kind() == "expression_statement"
                    && c.children().all(|s| s.kind() == "string"))
        })
}

fn named<'a, D: Doc>(
    root: &Node<'a, D>,
) -> impl Iterator<Item = (String, Node<'a, D>, Vec<String>)> {
    root.dfs().filter(|n| is_function(n)).filter_map(|f| {
        let name = f.field("name").map(|n| n.text().to_string()).or_else(|| {
            // `const f = (…) => …`, `f := func(…)`
            let parent = f.parent()?;
            (parent.kind() == "variable_declarator")
                .then(|| parent.field("name"))
                .flatten()
                .map(|n| n.text().to_string())
                .or_else(|| rails_scope(&f))
        })?;
        let default = f.parent().is_some_and(|p| {
            p.kind() == "export_statement" && p.text().starts_with("export default")
        });
        let name = if default { "default".to_string() } else { name };
        Some((name, f.clone(), params(&f)))
    })
}

/// Rails `scope :recent, ->(n) { … }` defines the class method `recent`.
fn rails_scope<D: Doc>(lambda: &Node<D>) -> Option<String> {
    let call = lambda.parent()?.parent()?;
    let method = call.field("method")?;
    if lambda.kind() != "lambda" || method.text() != "scope" {
        return None;
    }
    let name = call.field("arguments")?.children().find(|c| c.is_named())?;
    (name.kind() == "simple_symbol").then(|| name.text().trim_start_matches(':').to_string())
}

/// Parameter names of a function, as a set.
pub fn param_names<D: Doc>(f: &Node<D>) -> HashSet<String> {
    params(f).into_iter().filter(|p| !p.is_empty()).collect()
}

fn params<D: Doc>(f: &Node<D>) -> Vec<String> {
    if let Some(one) = f.field("parameter") {
        return vec![one.text().to_string()]; // `x => …`
    }
    let Some(list) = f.field("parameters") else {
        return Vec::new();
    };
    // Python's `self` / `cls` are not among the call's arguments.
    let receiver = |p: &Node<D>| matches!(p.text().as_ref(), "self" | "cls");
    list.children()
        .filter(|c| !(f.kind() == "function_definition" && receiver(c)))
        .filter(|c| c.is_named() && c.kind() != "comment")
        .map(|p| {
            if p.kind() == "identifier" {
                return p.text().to_string();
            }
            ["pattern", "name", "left"]
                .iter()
                .find_map(|k| p.field(k))
                .or_else(|| p.dfs().find(|n| n.kind() == "identifier"))
                .map(|n| n.text().to_string())
                .unwrap_or_default()
        })
        .collect()
}
