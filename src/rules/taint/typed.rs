//! `sink_types`: a sink only counts when the project's language server says a
//! metavariable has the expected type, e.g. `DB: "Pool|PoolClient"` keeps
//! `pool.query(sql)` and drops `list.query(x)`. No server, no answer: the
//! syntactic finding stands.

use crate::files::SourceFile;
use anyhow::{Context, Result};
use ast_grep_core::meta_var::MetaVarEnv;
use ast_grep_core::{Doc, Node};
use ast_grep_language::SupportLang;
use regex::Regex;
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Default)]
pub struct Typed {
    /// (metavariable, regex over the hover text)
    constraints: Vec<(String, Regex)>,
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
                Ok((var.trim_start_matches('$').to_string(), re))
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            constraints,
            root,
            servers,
        })
    }

    /// The constrained metavariables of one sink match, by constraint index.
    pub(super) fn metavariables<'a, D: Doc>(
        &self,
        env: &MetaVarEnv<'a, D>,
    ) -> Vec<(usize, Node<'a, D>)> {
        self.constraints
            .iter()
            .enumerate()
            .filter_map(|(i, (var, _))| Some((i, env.get_match(var)?.clone())))
            .collect()
    }

    /// False only when a language server answered with a type that does not match.
    pub(super) fn holds<D: Doc>(
        &self,
        lang: SupportLang,
        file: &SourceFile,
        nodes: &[(usize, Node<D>)],
    ) -> bool {
        nodes.iter().all(|(i, node)| {
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
            if std::env::var_os("AGENTKIT_DEBUG_TYPES").is_some() {
                eprintln!("types: {}:{at:?} {} -> {answer:?}", file.rel, node.text());
            }
            answer.is_none_or(|text| self.constraints[*i].1.is_match(&text))
        })
    }
}
