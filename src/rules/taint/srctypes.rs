//! `source_types` and `source_text`: a source match counts only when its
//! metavariables fit. `source_types` is a regex over the type a name is
//! declared with in the file (a field, local or parameter; `this.repo` is the
//! field `repo`). Unlike `sink_types`, a name whose type the file does not
//! write does not count: `$R.$M($$$A)` would otherwise make every call a
//! source. `source_text` is a regex over a metavariable's text (`M`:
//! `^find\w*`).

use super::declared::{DECLARATIONS, PARAMETERS, typed};
use super::kotlin::Part;
use anyhow::{Context, Result};
use ast_grep_core::{Doc, Node, NodeMatch};
use regex::Regex;
use std::collections::{BTreeMap, HashSet};

#[derive(Default)]
pub(crate) struct SourceTypes {
    types: Vec<(String, Regex)>,
    text: Vec<(String, Regex)>,
}

fn compile(id: &str, key: &str, map: &BTreeMap<String, String>) -> Result<Vec<(String, Regex)>> {
    map.iter()
        .map(|(var, re)| {
            let re = Regex::new(re).with_context(|| format!("taint `{id}`: {key}.{var}"))?;
            Ok((var.trim_start_matches('$').to_string(), re))
        })
        .collect()
}

impl SourceTypes {
    pub(crate) fn new(
        id: &str,
        types: &BTreeMap<String, String>,
        text: &BTreeMap<String, String>,
    ) -> Result<Self> {
        Ok(Self {
            types: compile(id, "source_types", types)?,
            text: compile(id, "source_text", text)?,
        })
    }

    /// Keeps the matches whose metavariables fit; the file's declarations
    /// are read only when a match needs them.
    pub(super) fn keep<'a, D: Doc>(
        &self,
        root: &Node<'a, D>,
        matches: Vec<NodeMatch<'a, D>>,
    ) -> Vec<NodeMatch<'a, D>> {
        if self.types.is_empty() && self.text.is_empty() {
            return matches;
        }
        let mut declared: Option<Vec<HashSet<String>>> = None;
        matches
            .into_iter()
            .filter(|m| {
                let env = m.get_env();
                let texts = self
                    .text
                    .iter()
                    .all(|(v, re)| env.get_match(v).is_none_or(|n| re.is_match(&n.text())));
                texts
                    && self.types.iter().enumerate().all(|(i, (v, _))| {
                        let Some(n) = env.get_match(v) else {
                            return true;
                        };
                        let names = declared.get_or_insert_with(|| self.declared(root));
                        name_of(n).is_some_and(|x| names[i].contains(&x))
                    })
            })
            .collect()
    }

    /// Per constraint: the names the file declares with a type it accepts.
    fn declared<D: Doc>(&self, root: &Node<D>) -> Vec<HashSet<String>> {
        let mut out = vec![HashSet::new(); self.types.len()];
        for n in root.dfs() {
            let kind = n.kind();
            if !DECLARATIONS.contains(&kind.as_ref()) && !PARAMETERS.contains(&kind.as_ref()) {
                continue;
            }
            for name in declared_names(&n) {
                let Some((ty, _)) = typed(&n, &name) else {
                    continue;
                };
                for (i, (_, re)) in self.types.iter().enumerate() {
                    if re.is_match(&ty) {
                        out[i].insert(name.clone());
                    }
                }
            }
        }
        out
    }
}

/// The names a declaration or parameter declares.
fn declared_names<D: Doc>(decl: &Node<D>) -> Vec<String> {
    let declarators: Vec<String> = decl
        .dfs()
        .filter(|n| n.kind() == "variable_declarator")
        .filter_map(|d| {
            d.part("name")
                .or_else(|| d.children().find(|c| c.kind() == "identifier"))
        })
        .map(|n| n.text().to_string())
        .collect();
    if !declarators.is_empty() {
        return declarators;
    }
    decl.part("name")
        .or_else(|| decl.children().find(|c| c.kind() == "identifier"))
        .map(|n| vec![n.text().to_string()])
        .unwrap_or_default()
}

/// `repo`, or the field of `this.repo`.
fn name_of<D: Doc>(n: &Node<D>) -> Option<String> {
    match n.kind().as_ref() {
        "identifier" | "simple_identifier" => Some(n.text().to_string()),
        "field_access" | "member_access_expression"
            if n.part("object")
                .or_else(|| n.part("expression"))
                .is_some_and(|o| o.kind() == "this" || o.text() == "this") =>
        {
            n.part("field")
                .or_else(|| n.part("name"))
                .map(|f| f.text().to_string())
        }
        _ => None,
    }
}
