//! `response_returns`: functions whose return value is the response body.
//! A Spring `@ResponseBody` / `@RestController` handler returning a String,
//! a Flask view returning a string: the returned value is written to the
//! client as is, like an argument of `res.send`.

use crate::config::ResponseReturns;
use crate::rules::complexity::is_function;
use anyhow::{Context, Result};
use ast_grep_core::{Doc, Node};
use regex::Regex;

pub struct Responds {
    headers: Vec<Regex>,
    not: Option<Regex>,
    types: Option<Regex>,
    values: Option<Regex>,
}

impl Responds {
    pub fn new(id: &str, cfg: &ResponseReturns) -> Result<Self> {
        let re = |r: &str| {
            Regex::new(r).with_context(|| format!("taint `{id}`: response_returns `{r}`"))
        };
        Ok(Self {
            headers: cfg.headers.iter().map(|h| re(h)).collect::<Result<_>>()?,
            not: cfg.not.as_deref().map(re).transpose()?,
            types: cfg.types.as_deref().map(re).transpose()?,
            values: cfg.values.as_deref().map(re).transpose()?,
        })
    }

    /// Is returning `value` from `function` writing it to the response?
    pub fn holds<D: Doc>(&self, function: &Node<D>, value: &Node<D>) -> bool {
        // A `return` statement stands for its value; an implicit return is the value.
        let returned = value.kind().starts_with("return");
        let value = match returned {
            true => match value
                .children()
                .find(|c| c.is_named() && c.kind() != "comment")
            {
                Some(v) => v,
                None => return false,
            },
            false => value.clone(),
        };
        if self
            .values
            .as_ref()
            .is_some_and(|v| !v.is_match(&value.kind()) && !built_as_string(function, &value))
        {
            return false;
        }
        if let (Some(types), Some(declared)) = (&self.types, function.field("type"))
            && !types.is_match(declared.text().trim())
        {
            return false;
        }
        let headers = headers(function);
        self.headers.iter().all(|h| h.is_match(&headers))
            && self.not.as_ref().is_none_or(|n| !n.is_match(&headers))
    }
}

/// The function's decorators and signature (the text before its body), then
/// those of the class it is defined in.
fn headers<D: Doc>(function: &Node<D>) -> String {
    let mut out = head(function);
    // Python keeps decorators in the parent `decorated_definition`.
    if let Some(parent) = function.parent()
        && parent.kind() == "decorated_definition"
    {
        out = format!("{}\n{out}", head(&parent));
    }
    let class = function
        .ancestors()
        .take_while(|a| !is_function(a))
        .find(|a| {
            matches!(
                a.kind().as_ref(),
                "class_declaration" | "class_definition" | "class" | "decorated_definition"
            ) && a.range() != function.range()
        });
    if let Some(class) = class {
        out.push('\n');
        out.push_str(&head(&class));
    }
    out
}

fn head<D: Doc>(n: &Node<D>) -> String {
    let text = n.text();
    let end = n
        .field("body")
        .or_else(|| n.field("definition").and_then(|d| d.field("body")))
        .map_or(text.len(), |b| b.range().start - n.range().start);
    text[..end.min(text.len())].to_string()
}

/// `out = ""` … `out += f"<p>{x}</p>"` … `return out`: a returned name the
/// function builds as a string (assigned a string or appended to).
fn built_as_string<D: Doc>(function: &Node<D>, value: &Node<D>) -> bool {
    if value.kind() != "identifier" {
        return false;
    }
    let name = value.text();
    function.dfs().any(|n| {
        let assigned = match n.kind().as_ref() {
            "assignment" | "augmented_assignment" => n.field("left"),
            _ => None,
        };
        assigned.is_some_and(|l| l.text() == name)
            && (n.kind() == "augmented_assignment"
                || n.field("right").is_some_and(|r| {
                    matches!(r.kind().as_ref(), "string" | "concatenated_string")
                        || (r.kind() == "binary_operator"
                            && r.children().any(|c| c.kind() == "string"))
                }))
    })
}
