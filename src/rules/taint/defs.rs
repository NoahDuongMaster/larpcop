//! Where functions are defined: named functions, methods (also known as
//! `Class.method`), Rails scopes, and their parameters.

use super::kotlin::Part;
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
        && let Some(receiver) = f.part("receiver")
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
    let name = class.part("name").or_else(|| class.part("type"))?;
    Some(name.text().split('<').next()?.trim().to_string())
}

/// The direct supertypes of the class a method is defined in: what it
/// `extends`/`implements` (Java, TS), its base list (C#, Kotlin, Python,
/// PHP, Ruby), without type arguments.
pub(super) fn supers_of<D: Doc>(f: &Node<D>) -> Vec<String> {
    let Some(class) = f.ancestors().take_while(|a| !is_function(a)).find(|a| {
        matches!(
            a.kind().as_ref(),
            "class_definition" | "class_declaration" | "class"
        )
    }) else {
        return Vec::new();
    };
    let skip = |k: &str| {
        matches!(
            k,
            "modifiers"
                | "type_parameters"
                | "type_parameter_list"
                | "decorator"
                | "annotation"
                | "marker_annotation"
                | "attribute_list"
                | "type_arguments"
                | "type_argument_list"
                | "class_body"
                | "declaration_list"
                | "block"
                | "body"
                | "body_statement"
        )
    };
    let name = class.part("name").map(|n| n.range());
    let mut out = Vec::new();
    for c in class
        .children()
        .filter(|c| c.is_named() && !skip(&c.kind()))
    {
        if Some(c.range()) == name {
            continue;
        }
        let mut stack = vec![c];
        while let Some(n) = stack.pop() {
            let kind = n.kind();
            if skip(&kind) {
                continue;
            }
            if matches!(
                kind.as_ref(),
                "type_identifier" | "identifier" | "constant" | "name" | "simple_identifier"
            ) {
                out.push(n.text().to_string());
                continue;
            }
            stack.extend(n.children().filter(|x| x.is_named()));
        }
    }
    out.retain(|s| s.chars().next().is_some_and(char::is_uppercase));
    out
}

/// No body (`void run(String x);`), or one that only stands in for an
/// implementation (`pass`, `...`, `raise NotImplementedError`).
pub(super) fn bodiless<D: Doc>(f: &Node<D>) -> bool {
    let Some(body) = f.part("body") else {
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
        let c_name = || {
            c_declarator(&f)?
                .field("declarator")
                .map(|n| n.text().to_string())
        };
        let name = f
            .part("name")
            .map(|n| n.text().to_string())
            .or_else(c_name)
            .or_else(|| {
                // `const f = (…) => …`, `f := func(…)`
                let parent = f.parent()?;
                (parent.kind() == "variable_declarator")
                    .then(|| parent.part("name"))
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

/// C/C++ `char *f(int a)`: the `function_declarator` holding the name and the
/// parameters, under any pointer declarators.
fn c_declarator<'a, D: Doc>(f: &Node<'a, D>) -> Option<Node<'a, D>> {
    let mut d = f.field("declarator")?;
    while d.kind() == "pointer_declarator" {
        d = d.field("declarator")?;
    }
    (d.kind() == "function_declarator").then_some(d)
}

/// Rails `scope :recent, ->(n) { … }` defines the class method `recent`.
fn rails_scope<D: Doc>(lambda: &Node<D>) -> Option<String> {
    let call = lambda.parent()?.parent()?;
    let method = call.part("method")?;
    if lambda.kind() != "lambda" || method.text() != "scope" {
        return None;
    }
    let name = call.part("arguments")?.children().find(|c| c.is_named())?;
    (name.kind() == "simple_symbol").then(|| name.text().trim_start_matches(':').to_string())
}

/// Parameter names of a function, as a set.
pub fn param_names<D: Doc>(f: &Node<D>) -> HashSet<String> {
    params(f).into_iter().filter(|p| !p.is_empty()).collect()
}

/// Parameter names by position (`""` where one is not a plain name).
pub(super) fn positional_params<D: Doc>(f: &Node<D>) -> Vec<String> {
    params(f)
}

fn params<D: Doc>(f: &Node<D>) -> Vec<String> {
    if let Some(one) = f.part("parameter") {
        return vec![one.text().to_string()]; // `x => …`
    }
    // C# `x => …`.
    if let Some(one) = f.children().find(|c| c.kind() == "implicit_parameter") {
        return vec![one.text().to_string()];
    }
    let Some(list) = f
        .part("parameters")
        .or_else(|| c_declarator(f)?.field("parameters"))
    else {
        // Kotlin `{ q(it) }`.
        return if f.kind() == "lambda_literal" {
            vec!["it".to_string()]
        } else {
            Vec::new()
        };
    };
    // Java `x -> …`.
    if matches!(list.kind().as_ref(), "identifier" | "simple_identifier") {
        return vec![list.text().to_string()];
    }
    // Python's `self` / `cls` are not among the call's arguments.
    let receiver = |p: &Node<D>| matches!(p.text().as_ref(), "self" | "cls");
    list.children()
        .filter(|c| !(f.kind() == "function_definition" && receiver(c)))
        // Kotlin puts a parameter's annotations before it.
        .filter(|c| c.is_named() && !matches!(c.kind().as_ref(), "comment" | "parameter_modifiers"))
        .map(|p| {
            if matches!(p.kind().as_ref(), "identifier" | "simple_identifier") {
                return p.text().to_string();
            }
            ["pattern", "name", "left"]
                .iter()
                .find_map(|k| p.part(k))
                .or_else(|| {
                    p.dfs()
                        .find(|n| matches!(n.kind().as_ref(), "identifier" | "simple_identifier"))
                })
                .map(|n| n.text().to_string())
                .unwrap_or_default()
        })
        .collect()
}
