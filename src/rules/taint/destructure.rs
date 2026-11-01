//! Destructuring: `const { query } = req` and `({ query }: Request) => …` read
//! `req.query` under another name, so a source written as `req.query` must
//! taint `query` too.

use super::kotlin::Part;
use ast_grep_core::{Doc, Node};
use std::collections::{BTreeMap, HashSet};

/// `(property, bound name)` of each property an object pattern destructures.
fn properties<D: Doc>(pattern: &Node<D>) -> Vec<(String, String)> {
    pattern
        .children()
        .filter_map(|c| match c.kind().as_ref() {
            "shorthand_property_identifier_pattern" => {
                Some((c.text().to_string(), c.text().to_string()))
            }
            "object_assignment_pattern" => {
                let name = c.part("left")?.text().to_string();
                Some((name.clone(), name))
            }
            "pair_pattern" => {
                let key = c.part("key")?.text().trim_matches(['"', '\'']).to_string();
                let value = c.part("value").filter(|v| v.kind() == "identifier")?;
                Some((key, value.text().to_string()))
            }
            _ => None,
        })
        .collect()
}

/// Names bound by `pattern` from `object`, whose `object.property` is a source.
pub(super) fn from_object<D: Doc>(
    pattern: &Node<D>,
    object: &str,
    sources: &[String],
) -> Vec<String> {
    if pattern.kind() != "object_pattern" {
        return Vec::new();
    }
    properties(pattern)
        .into_iter()
        .filter(|(key, _)| sources.iter().any(|s| *s == format!("{object}.{key}")))
        .map(|(_, bound)| bound)
        .collect()
}

/// Tainted names a function's destructured, typed parameters bind: with
/// `Request: req`, `({ query, body }: Request)` binds `req.query` and `req.body`.
pub(super) fn from_params<D: Doc>(
    function: &Node<D>,
    types: &BTreeMap<String, String>,
    sources: &[String],
) -> HashSet<String> {
    let mut out = HashSet::new();
    let Some(params) = function.part("parameters") else {
        return out;
    };
    for p in params.children() {
        let (Some(pattern), Some(ty)) = (p.part("pattern"), p.part("type")) else {
            continue;
        };
        let ty = ty.text();
        if let Some(object) = types.get(ty.trim_start_matches(':').trim()) {
            out.extend(from_object(&pattern, object, sources));
        }
    }
    out
}
