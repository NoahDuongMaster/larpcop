//! Taint tracking: data from a `source` must not reach a `sink` argument
//! unless it went through a `sanitizer`. Flow-sensitive along straight-line
//! code within a function (assignments taint or clean their targets in source
//! order), and across functions through summaries: a call passes taint only
//! where the callee does, a callee that sinks a parameter makes the call a
//! sink, a callee returning source data makes the call a source. Callees are
//! resolved in the same file and through imports (JS/TS, Python, Go).

use super::{Level, RuleInfo, Violation};
use crate::config::TaintConfig;
use crate::files::SourceFile;
use anyhow::{Context, Result};
use ast_grep_core::{Doc, Language, Node, Pattern};
use ast_grep_language::{LanguageExt, SupportLang};
use flow::Reached;
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use summary::Summaries;

/// How many imports deep summaries are followed.
const IMPORT_DEPTH: usize = 2;

pub struct TaintRule {
    id: String,
    level: Level,
    message: String,
    note: Option<String>,
    sink_arg: Option<String>,
    safe_prefix: Option<regex::Regex>,
    /// Sources as written, without whitespace (`req.query`), for destructuring.
    source_texts: Vec<String>,
    param_types: std::collections::BTreeMap<String, String>,
    param_decorators: Vec<String>,
    handler_decorators: Option<regex::Regex>,
    /// `sink_types`: metavariables whose type the project's language server must confirm.
    typed: typed::Typed,
    /// Per language: (sources, sinks, sanitizers, guards), compiled for that grammar.
    langs: Vec<(SupportLang, scan::Indexed)>,
    root: PathBuf,
    /// Summaries of imported files, computed once per run.
    imported: Mutex<HashMap<PathBuf, Arc<Summaries>>>,
}

const VARIABLES: [&str; 3] = [
    "identifier",
    "shorthand_property_identifier",
    "shorthand_property_identifier_pattern",
];

impl TaintRule {
    pub fn new(cfg: &TaintConfig, typed: typed::Typed, root: PathBuf) -> Result<Self> {
        let compile = |lang: SupportLang, list: &[String]| -> Result<Vec<Pattern>> {
            list.iter()
                .flat_map(|p| super::pattern_fixes::variants(p))
                .map(|p| {
                    pattern(&p, lang).with_context(|| format!("taint `{}`: pattern `{p}`", cfg.id))
                })
                .collect()
        };
        let mut langs = Vec::new();
        for name in &cfg.languages {
            let lang = SupportLang::from_str(name)
                .map_err(|_| anyhow::anyhow!("taint `{}`: unknown language `{name}`", cfg.id))?;
            langs.push((
                lang,
                scan::Indexed::new([
                    compile(lang, &cfg.sources)?,
                    compile(lang, &cfg.sinks)?,
                    compile(lang, &cfg.sanitizers)?,
                    compile(lang, &cfg.guards)?,
                ]),
            ));
        }
        Ok(Self {
            id: cfg.id.clone(),
            level: cfg.severity.unwrap_or(Level::Error),
            message: cfg.message.clone(),
            note: cfg.note.clone(),
            sink_arg: cfg.sink_arg.clone(),
            safe_prefix: cfg
                .safe_prefix
                .as_deref()
                .map(regex::Regex::new)
                .transpose()
                .with_context(|| format!("taint `{}`: safe_prefix", cfg.id))?,
            source_texts: cfg
                .sources
                .iter()
                .map(|s| s.split_whitespace().collect())
                .collect(),
            param_types: cfg.param_types.clone(),
            param_decorators: cfg.param_decorators.clone(),
            handler_decorators: cfg
                .handler_decorators
                .as_deref()
                .map(regex::Regex::new)
                .transpose()
                .with_context(|| format!("taint `{}`: handler_decorators", cfg.id))?,
            typed,
            langs,
            root,
            imported: Mutex::default(),
        })
    }

    /// Names a function receives as request data: destructured typed
    /// parameters, decorated parameters, parameters of route handlers.
    fn own_names<D: Doc>(&self, f: &Node<D>) -> std::collections::HashSet<String> {
        let mut out = destructure::from_params(f, &self.param_types, &self.source_texts);
        out.extend(handlers::params(
            f,
            &self.param_decorators,
            self.handler_decorators.as_ref(),
        ));
        out
    }

    pub fn languages(&self) -> Vec<SupportLang> {
        self.langs.iter().map(|(l, _)| *l).collect()
    }

    pub fn info(&self) -> RuleInfo {
        let scope: Vec<String> = self.langs.iter().map(|(l, _)| l.to_string()).collect();
        RuleInfo {
            id: self.id.clone(),
            level: self.level,
            scope: scope.join(", "),
            message: self.message.clone(),
            note: self.note.clone(),
        }
    }

    pub fn check(&self, file: &SourceFile) -> Vec<Violation> {
        let Some(lang) = SupportLang::from_path(&file.rel) else {
            return Vec::new();
        };
        if self.patterns(lang).is_none() {
            return Vec::new();
        }
        let grep = lang.ast_grep(&file.content);
        let root = grep.root();
        let Some((ctx, hits)) = self.prepare(lang, &root, file, 0) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        let own = |n: &Node<_>| self.own_names(n);
        ctx.run(&root, &root, own(&root), &hits, &own, &mut |r| match r {
            Reached::Sink(arg, typed) if self.typed.holds(lang, file, &typed) => {
                out.push(self.violation(file, &arg, None))
            }
            Reached::Call(arg, into) => out.push(self.violation(file, &arg, Some(into))),
            _ => {}
        });
        // A sink reached directly and through a summary is one finding.
        out.sort_by_key(|v| (v.line, v.column));
        out.dedup_by_key(|v| (v.line, v.column));
        out
    }

    fn patterns(&self, lang: SupportLang) -> Option<&scan::Indexed> {
        self.langs.iter().find(|(l, _)| *l == lang).map(|(_, p)| p)
    }

    fn violation<D: Doc>(
        &self,
        file: &SourceFile,
        at: &Node<D>,
        into: Option<String>,
    ) -> Violation {
        let pos = at.start_pos();
        let note = match (into, &self.note) {
            (Some(into), Some(n)) => Some(format!("Reaches the sink through {into}. {n}")),
            (Some(into), None) => Some(format!("Reaches the sink through {into}.")),
            (None, n) => n.clone(),
        };
        Violation {
            rule: self.id.clone(),
            level: self.level,
            file: file.rel.clone(),
            line: pos.line() + 1,
            column: pos.column(at) + 1,
            message: self.message.clone(),
            note,
            snippet: file
                .content
                .lines()
                .nth(pos.line())
                .map(|l| l.trim().chars().take(120).collect()),
        }
    }
}

/// Go calls written alone (`db.Query($X)`) need a function body as context.
fn pattern(p: &str, lang: SupportLang) -> Result<Pattern> {
    if lang == SupportLang::Go
        && let Some((context, selector)) = super::pattern_fixes::context(p)
    {
        return Ok(Pattern::contextual(&context, &selector, lang)?);
    }
    Ok(Pattern::try_new(p, lang)?)
}

mod destructure;
mod events;
mod flow;
mod guards;
mod handlers;
mod imports;
mod prefix;
mod prepare;
mod scan;
mod summary;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_calls;
#[cfg(test)]
mod tests_methods;
pub mod typed;
