//! Parameters that carry request data by framework convention, with no
//! `req.query` in sight: NestJS-style decorated parameters (`@Body() dto`,
//! `@Query('q') q`) and every parameter of a route handler declared by a
//! decorator (FastAPI `@app.get(…)`, Flask `@app.route('/u/<name>')`), and the
//! arguments of GraphQL resolvers (`(parent, args) => …`, `def resolve_x(root, info, id)`).

use ast_grep_core::{Doc, Node};
use regex::Regex;
use std::collections::HashSet;

/// Parameter kinds that are never request data in a handler.
const NOT_INPUT: [&str; 2] = ["self", "cls"];
const NOT_INPUT_TYPES: [&str; 5] = [
    "Request",
    "Response",
    "WebSocket",
    "BackgroundTasks",
    "HTTPConnection",
];
/// Types a handler framework validates before the call (FastAPI): an `int`
/// parameter cannot carry an injection.
const VALIDATED_TYPES: [&str; 8] = [
    "int",
    "float",
    "bool",
    "UUID",
    "uuid.UUID",
    "date",
    "datetime",
    "Decimal",
];
/// NestJS pipes that convert a parameter before the handler sees it.
const CONVERTING_PIPES: [&str; 5] = [
    "ParseIntPipe",
    "ParseFloatPipe",
    "ParseBoolPipe",
    "ParseUUIDPipe",
    "ParseEnumPipe",
];

/// First parameter of a GraphQL resolver: the parent object.
const RESOLVER_PARENT: [&str; 8] = [
    "parent", "root", "_", "obj", "source", "_parent", "_root", "_obj",
];

pub(super) fn params<D: Doc>(
    function: &Node<D>,
    param_decorators: &[String],
    handler: Option<&Regex>,
    resolvers: bool,
) -> HashSet<String> {
    let mut out = HashSet::new();
    let Some(list) = function.field("parameters") else {
        return out;
    };
    if resolvers {
        out.extend(resolver_args(&list));
    }
    let is_handler =
        handler.is_some_and(|re| decorators_of(function).iter().any(|d| re.is_match(d)));
    for p in list.children().filter(|c| c.is_named()) {
        let Some(name) = name_of(&p) else { continue };
        let decorated = !param_decorators.is_empty()
            && p.children().filter(|c| c.kind() == "decorator").any(|d| {
                let text = d.text();
                let called = text
                    .trim_start_matches('@')
                    .split('(')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
                param_decorators.contains(&called)
                    && !CONVERTING_PIPES.iter().any(|p| text.contains(p))
            });
        if decorated || (is_handler && is_input(&p, &name)) {
            out.insert(name);
        }
    }
    out
}

/// `(parent, args)` / `(parent, { id })` in JS, `(root, info, id, …)` in Python:
/// the names the client's arguments arrive in.
fn resolver_args<D: Doc>(list: &Node<D>) -> Vec<String> {
    let params: Vec<Node<D>> = list
        .children()
        .filter(|c| c.is_named() && c.kind() != "comment")
        .collect();
    let text = |n: &Node<D>| {
        n.field("pattern")
            .unwrap_or_else(|| n.clone())
            .text()
            .to_string()
    };
    if params.len() < 2 || !RESOLVER_PARENT.contains(&text(&params[0]).as_str()) {
        return Vec::new();
    }
    let second = params[1]
        .field("pattern")
        .unwrap_or_else(|| params[1].clone());
    if second.kind() == "object_pattern" {
        return second
            .dfs()
            .filter(|n| {
                n.kind() == "shorthand_property_identifier_pattern"
                    || (n.kind() == "identifier"
                        && n.parent().is_some_and(|p| p.kind() == "pair_pattern"))
            })
            .map(|n| n.text().to_string())
            .collect();
    }
    match text(&params[1]).as_str() {
        "args" | "input" | "variables" => vec![text(&params[1])],
        "info" => params[2..].iter().filter_map(name_of).collect(),
        _ => Vec::new(),
    }
}

/// Text of the decorators on a function (Python `decorated_definition`, or
/// decorators before a JS/TS method), without the `@`.
fn decorators_of<D: Doc>(function: &Node<D>) -> Vec<String> {
    let holder = function
        .parent()
        .filter(|p| p.kind() == "decorated_definition")
        .unwrap_or_else(|| function.clone());
    holder
        .children()
        .filter(|c| c.kind() == "decorator")
        .map(|d| d.text().trim_start_matches('@').trim().to_string())
        .collect()
}

fn name_of<D: Doc>(p: &Node<D>) -> Option<String> {
    let n = match p.kind().as_ref() {
        "identifier" => p.clone(),
        "typed_parameter" => p.children().find(|c| c.kind() == "identifier")?,
        "default_parameter" | "typed_default_parameter" => p.field("name")?,
        "required_parameter" | "optional_parameter" => {
            p.field("pattern").filter(|n| n.kind() == "identifier")?
        }
        _ => return None,
    };
    Some(n.text().to_string())
}

/// Not `self`, not a framework object (`request: Request`), not injected
/// (`db = Depends(get_db)`).
fn is_input<D: Doc>(p: &Node<D>, name: &str) -> bool {
    if NOT_INPUT.contains(&name) {
        return false;
    }
    let ty = p
        .field("type")
        .map(|t| t.text().trim_start_matches(':').trim().to_string());
    let framework = |t: &String| {
        NOT_INPUT_TYPES
            .iter()
            .any(|n| t == n || t.ends_with(&format!(".{n}")))
    };
    if ty
        .as_ref()
        .is_some_and(|t| framework(t) || VALIDATED_TYPES.contains(&t.as_str()))
    {
        return false;
    }
    let default = p
        .field("value")
        .map(|v| v.text().to_string())
        .unwrap_or_default();
    !(default.starts_with("Depends(") || default.starts_with("Security("))
}
