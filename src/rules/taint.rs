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
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Mutex;

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
    /// `source_names`: names that are request data wherever they are read.
    source_names: std::collections::HashSet<String>,
    param_types: std::collections::BTreeMap<String, String>,
    param_decorators: Vec<String>,
    handler_decorators: Option<regex::Regex>,
    resolver_args: bool,
    exclude: globset::GlobSet,
    /// `sink_types`: metavariables whose type the project's language server must confirm.
    typed: typed::Typed,
    /// Per language: (sources, sinks, sanitizers, guards), compiled for that grammar.
    langs: Vec<(SupportLang, scan::Indexed)>,
    root: PathBuf,
    /// Summaries of imported files by (path, import depth), computed once per
    /// run even when several threads need the same file at once.
    imported: Mutex<HashMap<(PathBuf, usize), prepare::Slot>>,
}

use names::{NAMES, VARIABLES};

impl TaintRule {
    pub fn new(cfg: &TaintConfig, typed: typed::Typed, root: PathBuf) -> Result<Self> {
        let compile = |lang: SupportLang, list: &[String]| -> Result<Vec<scan::Compiled>> {
            list.iter()
                .flat_map(|p| super::pattern_fixes::variants(p))
                .map(|p| {
                    let compiled = pattern(&p, lang)
                        .with_context(|| format!("taint `{}`: pattern `{p}`", cfg.id))?;
                    Ok((compiled, scan::needle(&p), scan::specificity(&p)))
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
                    compile(lang, &cfg.rejects)?,
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
            source_names: cfg.source_names.iter().cloned().collect(),
            param_types: cfg.param_types.clone(),
            param_decorators: cfg.param_decorators.clone(),
            resolver_args: cfg.resolver_args,
            exclude: crate::files::globset(&cfg.exclude)?,
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
    fn own_names<D: Doc>(&self, f: &Node<D>) -> HashSet<String> {
        let mut out = destructure::from_params(f, &self.param_types, &self.source_texts);
        out.extend(handlers::params(
            f,
            &self.param_decorators,
            self.handler_decorators.as_ref(),
            self.resolver_args,
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

    /// Parses and indexes the file itself; the engine shares one parse
    /// across rules through [`Self::check_indexed`].
    pub fn check(&self, file: &SourceFile) -> Vec<Violation> {
        let Some(lang) = SupportLang::from_path(&file.rel).filter(|l| self.handles(*l)) else {
            return Vec::new();
        };
        let grep = lang.ast_grep(&file.content);
        self.check_indexed(file, lang, &FileIndex::new(grep.root()))
    }

    pub fn handles(&self, lang: SupportLang) -> bool {
        self.patterns(lang).is_some()
    }

    /// The check on a file already parsed and indexed for `lang`.
    pub fn check_indexed<D: Doc>(
        &self,
        file: &SourceFile,
        lang: SupportLang,
        index: &FileIndex<D>,
    ) -> Vec<Violation> {
        if !self.handles(lang) || self.exclude.is_match(&file.rel) {
            return Vec::new();
        }
        let root = &index.root;
        let Some((ctx, hits)) = self.prepare(lang, index, file, 0) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        // Fields a method stores request data in, by class: read by the
        // class's other methods, so a second walk starts them tainted.
        let mut fields: HashMap<(usize, usize), HashSet<String>> = HashMap::new();
        for _ in 0..2 {
            let own = |n: &Node<_>| {
                let mut names = self.own_names(n);
                if let Some(f) = class_of(n).and_then(|c| fields.get(&c)) {
                    names.extend(f.iter().cloned());
                }
                names
            };
            let mut stored: HashMap<(usize, usize), HashSet<String>> = HashMap::new();
            ctx.run(root, own(root), &hits, &own, &mut |r| match r {
                Reached::Sink(arg, typed) if self.typed.holds(lang, file, &typed) => {
                    out.push(self.violation(file, &arg, None))
                }
                Reached::Call(arg, into) => out.push(self.violation(file, &arg, Some(into))),
                Reached::Field(left) => {
                    if let Some(c) = class_of(&left) {
                        stored.entry(c).or_default().insert(left.text().to_string());
                    }
                }
                _ => {}
            });
            let known = |(c, f): (&(usize, usize), &HashSet<String>)| {
                fields.get(c).is_some_and(|k| f.is_subset(k))
            };
            if stored.iter().all(known) {
                break;
            }
            for (c, f) in stored {
                fields.entry(c).or_default().extend(f);
            }
        }
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

/// The class a node is in (its range), for the fields its methods share.
fn class_of<D: Doc>(n: &Node<D>) -> Option<(usize, usize)> {
    let class = n.ancestors().find(|a| {
        matches!(
            a.kind().as_ref(),
            "class_declaration" | "class_definition" | "class" | "abstract_class_declaration"
        )
    })?;
    let r = class.range();
    Some((r.start, r.end))
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

mod containers;
mod destructure;
mod events;
mod flow;
mod guards;
mod handlers;
mod imports;
mod names;
mod prefix;
mod prepare;
mod scan;
pub use scan::FileIndex;
mod summary;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_calls;
#[cfg(test)]
mod tests_methods;
pub mod typed;
