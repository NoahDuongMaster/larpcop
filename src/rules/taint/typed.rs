//! `sink_types`: a sink only counts when a metavariable has the expected type,
//! e.g. `DB: "Pool|PoolClient"` keeps `pool.query(sql)` and drops
//! `list.query(x)`. The type a name is declared with in the source decides
//! (`Yaml y = …`, `db: Pool`); otherwise the project's language server is
//! asked. No declaration and no server: the syntactic finding stands.
//! `strict_sink_types` are kept only when the type is known: declared, or
//! written at the sink (`new URL(u).getContent()`), for methods whose name is
//! common elsewhere (`getContent()` of a page or an entity).
//! `excluded_sink_types` drop the sink when the type is known and matches
//! (`$xpath->query(…)` on a `DOMXPath` is not SQL).

use crate::files::SourceFile;
use anyhow::{Context, Result};
use ast_grep_core::meta_var::MetaVarEnv;
use ast_grep_core::{Doc, Node};
use ast_grep_language::SupportLang;
use regex::Regex;
use std::collections::BTreeMap;
use std::path::PathBuf;

/// How a sink's type constraint is read.
#[derive(Clone, Copy, PartialEq)]
enum Mode {
    /// The type, when known, must match.
    Known,
    /// The type must be known and match.
    Strict,
    /// The type, when known, must not match.
    Excluded,
}

#[derive(Default)]
pub struct Typed {
    constraints: Vec<(String, Regex, Mode)>,
    root: PathBuf,
    servers: BTreeMap<String, Vec<String>>,
}

impl Typed {
    pub fn new(
        id: &str,
        sink_types: &BTreeMap<String, String>,
        root: PathBuf,
        servers: BTreeMap<String, Vec<String>>,
    ) -> Result<Self> {
        let constraints = sink_types
            .iter()
            .map(|(var, re)| {
                let re =
                    Regex::new(re).with_context(|| format!("taint `{id}`: sink_types.{var}"))?;
                Ok((var.trim_start_matches('$').to_string(), re, Mode::Known))
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            constraints,
            root,
            servers,
        })
    }

    /// Adds constraints that hold only for a known type.
    pub fn with_strict(self, id: &str, strict: &BTreeMap<String, String>) -> Result<Self> {
        self.with(id, "strict_sink_types", strict, Mode::Strict)
    }

    /// Adds types that are not the sink's.
    pub fn with_excluded(self, id: &str, excluded: &BTreeMap<String, String>) -> Result<Self> {
        self.with(id, "excluded_sink_types", excluded, Mode::Excluded)
    }

    fn with(
        mut self,
        id: &str,
        key: &str,
        types: &BTreeMap<String, String>,
        mode: Mode,
    ) -> Result<Self> {
        for (var, re) in types {
            let re = Regex::new(re).with_context(|| format!("taint `{id}`: {key}.{var}"))?;
            self.constraints
                .push((var.trim_start_matches('$').to_string(), re, mode));
        }
        Ok(self)
    }

    /// The constrained metavariables of one sink match, by constraint index.
    pub(super) fn metavariables<'a, D: Doc>(
        &self,
        env: &MetaVarEnv<'a, D>,
    ) -> Vec<(usize, Node<'a, D>)> {
        self.constraints
            .iter()
            .enumerate()
            .filter_map(|(i, (var, ..))| Some((i, env.get_match(var)?.clone())))
            .collect()
    }

    /// False only when the declared type, or else a language server's answer,
    /// does not match.
    pub(super) fn holds<D: Doc>(
        &self,
        lang: SupportLang,
        file: &SourceFile,
        nodes: &[(usize, Node<D>)],
    ) -> bool {
        nodes.iter().all(|(i, node)| {
            let (_, re, mode) = &self.constraints[*i];
            let excluded = *mode == Mode::Excluded;
            if let Some(declared) = super::declared::declared_type(node) {
                return re.is_match(declared.trim_start_matches('\\')) != excluded;
            }
            if *mode != Mode::Known {
                let created = node.kind().contains("creation")
                    && node
                        .field("type")
                        .is_some_and(|t| re.is_match(t.text().as_ref()));
                return created != excluded;
            }
            let pos = node.start_pos();
            let at = (pos.line(), pos.column(node));
            let answer = crate::types::hover(
                &self.root,
                &self.servers,
                lang,
                &file.rel,
                &file.content,
                at,
            );
            if std::env::var_os("LARPCOP_DEBUG_TYPES").is_some() {
                eprintln!(
                    "larpcop: type of `{}` at {}:{}:{} → {answer:?}",
                    node.text(),
                    file.rel,
                    at.0 + 1,
                    at.1 + 1
                );
            }
            answer.is_none_or(|text| re.is_match(&text))
        })
    }
}
