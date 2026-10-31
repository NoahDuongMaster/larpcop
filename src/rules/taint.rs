//! Intraprocedural taint tracking (the scope Semgrep OSS covers): data from a
//! `source` must not reach a `sink` argument inside the same function unless it
//! went through a `sanitizer`. Flow-sensitive along straight-line code:
//! assignments taint or clean their targets in source order, and a sink is
//! judged with the variables' state at that point. Calls into other functions
//! and other files are not followed.

use super::complexity::is_function;
use super::{Level, RuleInfo, Violation};
use crate::config::TaintConfig;
use crate::files::SourceFile;
use anyhow::{Context, Result};
use ast_grep_core::{Doc, Language, Node, Pattern};
use ast_grep_language::{LanguageExt, SupportLang};
use std::collections::HashSet;
use std::ops::Range;
use std::str::FromStr;

pub struct TaintRule {
    id: String,
    level: Level,
    message: String,
    note: Option<String>,
    sink_arg: Option<String>,
    /// Sources as written, without whitespace (`req.query`), for destructuring.
    source_texts: Vec<String>,
    param_types: std::collections::BTreeMap<String, String>,
    /// `sink_types`: metavariables whose type the project's language server must confirm.
    typed: typed::Typed,
    /// Per language: (sources, sinks, sanitizers), compiled for that grammar.
    langs: Vec<(SupportLang, [Vec<Pattern>; 3])>,
}

/// Targets (left) and value (right) of the assignment kinds we follow.
const ASSIGNMENTS: [(&str, &str, &str); 7] = [
    ("variable_declarator", "name", "value"),
    ("assignment_expression", "left", "right"),
    ("augmented_assignment_expression", "left", "right"),
    ("assignment", "left", "right"),
    ("augmented_assignment", "left", "right"),
    ("short_var_declaration", "left", "right"),
    ("assignment_statement", "left", "right"),
];

const VARIABLES: [&str; 3] = [
    "identifier",
    "shorthand_property_identifier",
    "shorthand_property_identifier_pattern",
];

impl TaintRule {
    pub fn new(cfg: &TaintConfig, typed: typed::Typed) -> Result<Self> {
        let compile = |lang: SupportLang, list: &[String]| -> Result<Vec<Pattern>> {
            list.iter()
                .map(|p| {
                    Pattern::try_new(p, lang)
                        .with_context(|| format!("taint `{}`: pattern `{p}`", cfg.id))
                })
                .collect()
        };
        let mut langs = Vec::new();
        for name in &cfg.languages {
            let lang = SupportLang::from_str(name)
                .map_err(|_| anyhow::anyhow!("taint `{}`: unknown language `{name}`", cfg.id))?;
            langs.push((
                lang,
                [
                    compile(lang, &cfg.sources)?,
                    compile(lang, &cfg.sinks)?,
                    compile(lang, &cfg.sanitizers)?,
                ],
            ));
        }
        Ok(Self {
            id: cfg.id.clone(),
            level: cfg.severity.unwrap_or(Level::Error),
            message: cfg.message.clone(),
            note: cfg.note.clone(),
            sink_arg: cfg.sink_arg.clone(),
            source_texts: cfg
                .sources
                .iter()
                .map(|s| s.split_whitespace().collect())
                .collect(),
            param_types: cfg.param_types.clone(),
            typed,
            langs,
        })
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
        let Some((_, [sources, sinks, sanitizers])) = self.langs.iter().find(|(l, _)| *l == lang)
        else {
            return Vec::new();
        };
        let grep = lang.ast_grep(&file.content);
        let root = grep.root();
        let ranges = |ps: &[Pattern]| -> Vec<Range<usize>> {
            ps.iter()
                .flat_map(|p| root.find_all(p).map(|m| m.range()))
                .collect()
        };
        let ctx = Ctx {
            sources: ranges(sources),
            sanitizers: ranges(sanitizers),
        };
        // Without a source in sight, only destructuring (`{ query }`) can bring one in.
        let property = |s: &String| s.rsplit('.').next().map(|p| file.content.contains(p));
        if ctx.sources.is_empty() && !self.source_texts.iter().any(|s| property(s) == Some(true)) {
            return Vec::new();
        }
        // (position, sink argument, typed metavariables): judged when the walk reaches it.
        let mut hits: Vec<Hit<_>> = Vec::new();
        for p in sinks {
            for m in root.find_all(p) {
                let arg = self
                    .sink_arg
                    .as_deref()
                    .and_then(|v| m.get_env().get_match(v).cloned());
                let node = arg.unwrap_or_else(|| m.get_node().clone());
                let typed = self.typed.metavariables(m.get_env());
                hits.push((m.range().start, node, typed));
            }
        }
        let mut out = Vec::new();
        for scope in std::iter::once(root.clone()).chain(root.dfs().filter(|n| is_function(n))) {
            let mut events: Vec<(usize, Event<_>)> = Vec::new();
            walk(&scope, &mut |n| {
                if let Some((_, l, r)) = ASSIGNMENTS.iter().find(|(k, ..)| n.kind() == *k)
                    && let (Some(left), Some(right)) = (n.field(l), n.field(r))
                {
                    events.push((n.range().end, Event::Assign(left, right)));
                }
            });
            for (at, sink, typed) in &hits {
                if enclosing(sink, &root).range() == scope.range() {
                    events.push((*at, Event::Sink(sink.clone(), typed.clone())));
                }
            }
            events.sort_by_key(|(at, _)| *at);
            let mut names: HashSet<String> =
                destructure::from_params(&scope, &self.param_types, &self.source_texts);
            for (_, e) in events {
                match e {
                    Event::Assign(left, right) => {
                        let tainted = ctx.tainted(&right, &names);
                        for v in left
                            .dfs()
                            .filter(|n| VARIABLES.contains(&n.kind().as_ref()))
                        {
                            if tainted {
                                names.insert(v.text().to_string());
                            } else if left.kind() == "identifier" {
                                names.remove(v.text().as_ref());
                            }
                        }
                        if !tainted && right.kind() == "identifier" {
                            let object = right.text();
                            names.extend(destructure::from_object(
                                &left,
                                &object,
                                &self.source_texts,
                            ));
                        }
                    }
                    Event::Sink(arg, typed)
                        if ctx.tainted(&arg, &names) && self.typed.holds(lang, file, &typed) =>
                    {
                        out.push(self.violation(file, &arg))
                    }
                    Event::Sink(..) => {}
                }
            }
        }
        out
    }

    fn violation<D: Doc>(&self, file: &SourceFile, at: &Node<D>) -> Violation {
        let pos = at.start_pos();
        Violation {
            rule: self.id.clone(),
            level: self.level,
            file: file.rel.clone(),
            line: pos.line() + 1,
            column: pos.column(at) + 1,
            message: self.message.clone(),
            note: self.note.clone(),
            snippet: file
                .content
                .lines()
                .nth(pos.line())
                .map(|l| l.trim().chars().take(120).collect()),
        }
    }
}

/// A sink match: (position, sink argument, typed metavariables).
type Hit<'a, D> = (usize, Node<'a, D>, Vec<(usize, Node<'a, D>)>);

enum Event<'a, D: Doc> {
    Assign(Node<'a, D>, Node<'a, D>),
    Sink(Node<'a, D>, Vec<(usize, Node<'a, D>)>),
}

struct Ctx {
    sources: Vec<Range<usize>>,
    sanitizers: Vec<Range<usize>>,
}

fn within(r: &Range<usize>, outer: &Range<usize>) -> bool {
    outer.start <= r.start && r.end <= outer.end
}

impl Ctx {
    /// Does `node` carry source data (not passed through a sanitizer)?
    fn tainted<D: Doc>(&self, node: &Node<D>, names: &HashSet<String>) -> bool {
        let r = node.range();
        if self.sanitizers.iter().any(|s| within(&r, s)) {
            return false;
        }
        if self.sources.iter().any(|s| within(&r, s)) {
            return true;
        }
        if VARIABLES[..2].contains(&node.kind().as_ref()) && names.contains(node.text().as_ref()) {
            return true;
        }
        node.children().any(|c| self.tainted(&c, names))
    }
}

/// Nodes of a scope in order, not descending into nested functions.
fn walk<'a, D: Doc>(scope: &Node<'a, D>, f: &mut impl FnMut(&Node<'a, D>)) {
    for c in scope.children() {
        if is_function(&c) {
            continue;
        }
        f(&c);
        walk(&c, f);
    }
}

fn enclosing<'a, D: Doc>(node: &Node<'a, D>, root: &Node<'a, D>) -> Node<'a, D> {
    node.ancestors()
        .find(|a| is_function(a))
        .unwrap_or_else(|| root.clone())
}

mod destructure;
#[cfg(test)]
mod tests;
pub mod typed;
