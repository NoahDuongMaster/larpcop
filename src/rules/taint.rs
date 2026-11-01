//! Taint tracking: data from a `source` must not reach a `sink` argument
//! unless it went through a `sanitizer`. Flow-sensitive along straight-line
//! code within a function (assignments taint or clean their targets in source
//! order), and across functions through summaries: a call passes taint only
//! where the callee does, a callee that sinks a parameter makes the call a
//! sink, a callee returning source data makes the call a source. Callees are
//! resolved in the same file and through imports (JS/TS, Python, Go).

use super::{Level, RuleInfo, Violation};
use crate::files::SourceFile;
use ast_grep_core::{Doc, Language, Node};
use ast_grep_language::{LanguageExt, SupportLang};
use flow::Reached;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
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
    sanitizer_names: Option<regex::Regex>,
    /// `unless`: the function around a sink sets it up safely.
    unless: Vec<regex::Regex>,
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
    responds: Option<responds::Responds>,
    /// Per language: (sources, sinks, sanitizers, guards), compiled for that grammar.
    langs: Vec<(SupportLang, scan::Indexed)>,
    root: PathBuf,
    /// Summaries of imported files by (path, import depth), computed once per
    /// run even when several threads need the same file at once.
    imported: Mutex<HashMap<(PathBuf, usize), prepare::Slot>>,
}

use names::{NAMES, VARIABLES};

impl TaintRule {
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
                    // A bare field name is shadowed by a parameter or local.
                    let own = |f: &&String| f.contains('.') || !fields::declares(n, f);
                    names.extend(f.iter().filter(own).cloned());
                }
                names
            };
            let mut stored: HashMap<(usize, usize), HashSet<String>> = HashMap::new();
            ctx.run(root, own(root), &hits, &own, &mut |r| match r {
                Reached::Sink(arg, typed) if self.typed.holds(lang, file, &typed) => {
                    out.push(self.violation(file, &arg, None))
                }
                Reached::Call(arg, into) => out.push(self.violation(file, &arg, Some(into))),
                Reached::Responds(f, value)
                    if self.responds.as_ref().is_some_and(|r| r.holds(&f, &value)) =>
                {
                    out.push(self.violation(file, &value, None))
                }
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

mod build;
mod constant;
mod containers;
mod deadcode;
mod declared;
mod defs;
mod destructure;
mod entries;
mod events;
mod fields;
mod flow;
mod guards;
mod handlers;
mod imports;
mod iteration;
mod lambdas;
mod lists;
mod membership;
mod names;
mod paths;
mod prefix;
mod prepare;
mod responds;
mod returns;
mod scan;
pub use scan::FileIndex;
mod summary;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_branches;
#[cfg(test)]
mod tests_calls;
#[cfg(test)]
mod tests_csharp;
#[cfg(test)]
mod tests_deadcode;
#[cfg(test)]
mod tests_entries;
#[cfg(test)]
mod tests_methods;
#[cfg(test)]
mod tests_ruby;
#[cfg(test)]
mod tests_validators;
pub mod typed;
mod validators;
mod walk;
