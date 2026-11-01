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
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Mutex;

use reach::IMPORT_DEPTH;

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
    handler_classes: Option<regex::Regex>,
    input_types: Option<regex::Regex>,
    escape_contexts: bool,
    own_serialization_safe: bool,
    shell_argv: Option<argv::ShellArgv>,
    fixed_routes: routes::FixedRoutes,
    source_types: srctypes::SourceTypes,
    path_objects: Option<pathobj::PathObjects>,
    html_fragments: bool,
    /// Sanitizers by name, for functions passed by reference (`map(esc)`).
    cleaners: std::sync::Arc<mapping::Cleaners>,
    writes: std::sync::Arc<outputs::Writes>,
    exclude: globset::GlobSet,
    /// `sink_types`: metavariables whose type the project's language server must confirm.
    typed: typed::Typed,
    responds: Option<responds::Responds>,
    /// Per language: (sources, sinks, sanitizers, guards), compiled for that grammar.
    langs: Vec<(SupportLang, scan::Indexed)>,
    /// Languages among `langs` only read to summarize what the others call.
    companions: Vec<SupportLang>,
    root: PathBuf,
    /// Summaries of imported files by (path, import depth), computed once per
    /// run even when several threads need the same file at once.
    imported: Mutex<HashMap<(PathBuf, usize), prepare::Slot>>,
    /// Whether a file leads to a source or sink within some import depth.
    reach: Mutex<HashMap<(PathBuf, usize), bool>>,
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
        out.extend(services::params(
            f,
            self.handler_classes.as_ref(),
            self.input_types.as_ref(),
        ));
        out
    }

    pub fn languages(&self) -> Vec<SupportLang> {
        self.langs
            .iter()
            .map(|(l, _)| *l)
            .filter(|l| !self.companions.contains(l))
            .collect()
    }

    pub fn info(&self) -> RuleInfo {
        let scope: Vec<String> = self.languages().iter().map(|l| l.to_string()).collect();
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
        let grep = lang.ast_grep(crate::rules::macros::expand(lang, &file.content));
        self.check_indexed(file, lang, &FileIndex::new(grep.root()))
    }

    pub fn handles(&self, lang: SupportLang) -> bool {
        self.patterns(lang).is_some() && !self.companions.contains(&lang)
    }

    fn patterns(&self, lang: SupportLang) -> Option<&scan::Indexed> {
        self.langs.iter().find(|(l, _)| *l == lang).map(|(_, p)| p)
    }
}

mod argv;
mod build;
mod callbacks;
mod check;
pub(crate) mod constant;
mod containers;
mod contexts;
mod deadcode;
mod declared;
mod defs;
mod destructure;
mod entries;
mod env;
mod equality;
mod events;
mod fields;
pub(crate) mod flow;
mod fragments;
mod guards;
mod handlers;
mod higher;
mod imports;
mod iteration;
mod kotlin;
mod lambdas;
mod lists;
mod loops;
mod mapping;
mod membership;
mod names;
mod origins;
mod outputs;
mod pathobj;
mod paths;
mod pointers;
mod prefix;
mod prepare;
mod reach;
mod resolve;
mod responds;
mod returns;
mod routes;
mod scan;
mod services;
mod srctypes;
mod statics;
pub use scan::FileIndex;
mod summary;
mod summary_of;
mod switches;
#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_argv;
#[cfg(test)]
mod tests_branches;
#[cfg(test)]
mod tests_c;
#[cfg(test)]
mod tests_calls;
#[cfg(test)]
mod tests_csharp;
#[cfg(test)]
mod tests_deadcode;
#[cfg(test)]
mod tests_dispatch;
/// `DUMP=f.java LANG_=java cargo test dump -- --ignored --nocapture` prints a
/// syntax tree with its fields.
#[cfg(test)]
mod tests_dump;
#[cfg(test)]
mod tests_entries;
#[cfg(test)]
mod tests_equality;
#[cfg(test)]
mod tests_higher;
#[cfg(test)]
mod tests_kotlin;
#[cfg(test)]
mod tests_mapping;
#[cfg(test)]
mod tests_methods;
#[cfg(test)]
mod tests_pathobj;
#[cfg(test)]
mod tests_routes;
#[cfg(test)]
mod tests_ruby;
#[cfg(test)]
mod tests_services;
#[cfg(test)]
mod tests_sinks;
#[cfg(test)]
mod tests_streams;
#[cfg(test)]
mod tests_support;
#[cfg(test)]
mod tests_validators;
pub mod typed;
mod unique;
mod validators;
mod walk;
