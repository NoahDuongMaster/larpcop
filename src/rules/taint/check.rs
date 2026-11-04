//! A file's check: the walk over its functions, run again while methods
//! store request data in fields their class's other methods read.

use super::TaintRule;
use super::events::Hit;
use super::fields;
use super::flow::Reached;
use super::scan::FileIndex;
use crate::files::SourceFile;
use crate::rules::Violation;
use ast_grep_core::{Doc, Node};
use ast_grep_language::SupportLang;
use std::collections::{HashMap, HashSet};

impl TaintRule {
    /// Sinks found by the engine rather than by a pattern: shell argument
    /// vectors (argv.rs), path objects used on the file system (pathobj.rs),
    /// values placed into HTML markup (fragments.rs).
    pub(super) fn extra_sinks<'a, D: Doc>(&self, index: &FileIndex<'a, D>) -> Vec<Hit<'a, D>> {
        let argv = self.shell_argv.as_ref().map(|a| a.sinks(index));
        let paths = self.path_objects.as_ref().map(|p| p.sinks(index));
        let markup = self.html_fragments.then(|| super::fragments::sinks(index));
        argv.into_iter()
            .chain(paths)
            .chain(markup)
            .flatten()
            .map(|(at, n)| (at, n, Vec::new()))
            .collect()
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
        fixpoint(|fields: &HashMap<(usize, usize), HashSet<String>>| {
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
                        let name =
                            super::entries::entry(&left).unwrap_or_else(|| left.text().to_string());
                        stored.entry(c).or_default().insert(name);
                    }
                }
                _ => {}
            });
            stored
        });
        // A sink reached directly and through a summary is one finding.
        out.sort_by_key(|v| (v.line, v.column));
        out.dedup_by_key(|v| (v.line, v.column));
        out
    }

    pub(super) fn violation<D: Doc>(
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

/// What a walk stores per class: the fields its methods put request data in.
pub(super) trait Stored: Default {
    /// Is everything stored here already in `known`?
    fn covered_by(&self, known: &Self) -> bool;
    fn absorb(&mut self, more: Self);
}

impl Stored for HashSet<String> {
    fn covered_by(&self, known: &Self) -> bool {
        self.is_subset(known)
    }

    fn absorb(&mut self, more: Self) {
        self.extend(more);
    }
}

/// Walks with the fields stored so far, by class, a second time when the
/// first walk stored fields that were not known.
pub(super) fn fixpoint<S: Stored>(
    mut walk: impl FnMut(&HashMap<(usize, usize), S>) -> HashMap<(usize, usize), S>,
) {
    let mut fields: HashMap<(usize, usize), S> = HashMap::new();
    for _ in 0..2 {
        let stored = walk(&fields);
        let known = |(c, f): (&(usize, usize), &S)| fields.get(c).is_some_and(|k| f.covered_by(k));
        if stored.iter().all(known) {
            break;
        }
        for (c, f) in stored {
            fields.entry(c).or_default().absorb(f);
        }
    }
}

/// The class a node is in (its range), for the fields its methods share.
pub(super) fn class_of<D: Doc>(n: &Node<D>) -> Option<(usize, usize)> {
    let class = n.ancestors().find(|a| {
        matches!(
            a.kind().as_ref(),
            "class_declaration" | "class_definition" | "class" | "abstract_class_declaration"
        )
    })?;
    let r = class.range();
    Some((r.start, r.end))
}
