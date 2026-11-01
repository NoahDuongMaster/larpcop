//! `sink_configured`: a sink counts only when the object a metavariable
//! names was set up a certain way in the file. `JM: activateDefaultTyping`
//! keeps `POLYMORPHIC_MAPPER.readValue(json, Object.class)` for a mapper
//! built by `createPolymorphicMapper()`, whose body turns default typing on,
//! and drops `TYPED_MAPPER.readValue(json, Prefs.class)`. What is read: the
//! name's initializers and assignments, the body of a method of the file
//! such a value calls, and every call made on the name in the file
//! (`mapper.enableDefaultTyping()`), and one level down, how the names an
//! initializer is given were set up (`$twig = new Twig_Environment($loader)`
//! with `$loader = new Twig_Loader_String()`). An object set up in another
//! file is not seen, so its sink does not count.

use super::kotlin::Part;
use anyhow::{Context, Result};
use ast_grep_core::meta_var::MetaVarEnv;
use ast_grep_core::{Doc, Node};
use regex::Regex;
use std::collections::BTreeMap;

#[derive(Default)]
pub(crate) struct Configured(Vec<(String, Regex)>);

impl Configured {
    pub(crate) fn new(id: &str, map: &BTreeMap<String, String>) -> Result<Self> {
        map.iter()
            .map(|(var, re)| {
                let re = Regex::new(re)
                    .with_context(|| format!("taint `{id}`: sink_configured.{var}"))?;
                Ok((var.trim_start_matches('$').to_string(), re))
            })
            .collect::<Result<_>>()
            .map(Configured)
    }

    /// Was every constrained object of this match set up as required?
    pub(super) fn holds<D: Doc>(&self, root: &Node<D>, env: &MetaVarEnv<D>) -> bool {
        self.0.iter().all(|(var, re)| {
            env.get_match(var).is_none_or(|n| {
                field_name(n).is_some_and(|name| re.is_match(&setup(root, &name, 1)))
            })
        })
    }
}

/// `sink_texts`: what the sink names (`setcookie("session", …)` only).
#[derive(Default)]
pub(crate) struct SinkTexts(Vec<(String, Regex)>);

impl SinkTexts {
    pub(crate) fn new(id: &str, map: &BTreeMap<String, String>) -> Result<Self> {
        map.iter()
            .map(|(var, re)| {
                let re =
                    Regex::new(re).with_context(|| format!("taint `{id}`: sink_texts.{var}"))?;
                Ok((var.trim_start_matches('$').to_string(), re))
            })
            .collect::<Result<_>>()
            .map(SinkTexts)
    }

    /// Do the metavariables of this sink match?
    pub(super) fn holds<D: Doc>(&self, env: &MetaVarEnv<D>) -> bool {
        self.0.iter().all(|(var, re)| {
            env.get_match(var)
                .is_none_or(|n| re.is_match(n.text().as_ref()))
        })
    }
}

/// `mapper`, `$twig`, the field of `this.mapper`, or of `Utils.MAPPER`.
fn field_name<D: Doc>(n: &Node<D>) -> Option<String> {
    match n.kind().as_ref() {
        "identifier" | "simple_identifier" | "variable_name" => Some(n.text().to_string()),
        "field_access" | "member_access_expression" | "navigation_expression" => n
            .part("field")
            .or_else(|| n.part("name"))
            .map(|f| f.text().to_string()),
        _ => None,
    }
}

/// The text that sets `name` up in the file, and `deeper` more levels of
/// the names its initializers are given.
fn setup<D: Doc>(root: &Node<D>, name: &str, deeper: usize) -> String {
    let mut text = String::new();
    let mut values: Vec<Node<D>> = Vec::new();
    for n in root.dfs() {
        match n.kind().as_ref() {
            "variable_declarator" => {
                let named = n.part("name").is_some_and(|x| x.text() == name);
                if named && let Some(v) = n.part("value") {
                    values.push(v);
                }
            }
            "assignment_expression" | "assignment" => {
                let left = n.part("left");
                if left.is_some_and(|l| field_name(&l).is_some_and(|x| x == name))
                    && let Some(v) = n.part("right")
                {
                    values.push(v);
                }
            }
            "method_invocation" | "member_call_expression"
                if n.part("object")
                    .is_some_and(|o| field_name(&o).is_some_and(|x| x == name)) =>
            {
                text.push_str(&n.text());
                text.push('\n');
            }
            _ => {}
        }
    }
    for v in values {
        text.push_str(&v.text());
        text.push('\n');
        if deeper > 0 {
            let given = v.dfs().skip(1).filter(|x| {
                matches!(x.kind().as_ref(), "identifier" | "variable_name") && x.text() != name
            });
            for g in given {
                text.push_str(&setup(root, &g.text(), deeper - 1));
            }
        }
        // `= createMapper()`: that method's body.
        if v.kind() == "method_invocation"
            && v.part("object").is_none_or(|o| o.kind() == "this")
            && let Some(called) = v.part("name")
            && let Some(body) = method_body(root, &called.text())
        {
            text.push_str(&body);
        }
    }
    text
}

fn method_body<D: Doc>(root: &Node<D>, method: &str) -> Option<String> {
    root.dfs()
        .filter(|n| n.kind() == "method_declaration")
        .find(|n| n.part("name").is_some_and(|x| x.text() == method))
        .and_then(|n| n.part("body"))
        .map(|b| b.text().to_string())
}
