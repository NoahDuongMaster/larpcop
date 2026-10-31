//! What a check needs before the walk: sources, sinks, sanitizers and guards
//! found in the file, and summaries of the functions it defines or imports.

use super::events::{Hit, Hits};
use super::flow::Ctx;
use super::scan::FileIndex;
use super::summary::{self, Summaries};
use super::{IMPORT_DEPTH, TaintRule, prefix};
use crate::files::SourceFile;
use ast_grep_core::{Doc, Language, NodeMatch};
use ast_grep_language::LanguageExt;
use ast_grep_language::SupportLang;
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;

impl TaintRule {
    /// Sources, sanitizers and sinks found in `root`, and the summaries of the
    /// functions it defines or imports.
    pub(super) fn prepare<'a, D: Doc>(
        &self,
        lang: SupportLang,
        index: &FileIndex<'a, D>,
        file: &SourceFile,
        depth: usize,
    ) -> Option<(Ctx, Hits<'a, D>)> {
        let [sources, sinks, sanitizers, guards] = self.patterns(lang)?.scan(index);
        let ranges = |ms: Vec<NodeMatch<'a, D>>| -> Vec<Range<usize>> {
            ms.iter().map(|m| m.range()).collect()
        };
        let mut hits: Vec<Hit<_>> = Vec::new();
        {
            for m in sinks {
                let arg = self
                    .sink_arg
                    .as_deref()
                    .and_then(|v| m.get_env().get_match(v).cloned());
                let node = arg.unwrap_or_else(|| m.get_node().clone());
                let fixed = self.safe_prefix.as_ref().zip(prefix::leading(&node));
                if fixed.is_some_and(|(re, start)| re.is_match(&start)) {
                    continue;
                }
                let typed = self.typed.metavariables(m.get_env());
                hits.push((m.range().start, node, typed));
            }
        }
        // Overlapping sink patterns (and Go's wrapped patterns) find a call more than once.
        hits.sort_by_key(|(at, node, _)| (*at, node.range().start, node.range().end));
        hits.dedup_by_key(|(at, node, _)| (*at, node.range().start, node.range().end));
        let hits = Hits::new(hits, &index.root, index.skeletons.clone());
        let base = Ctx {
            sources: ranges(sources),
            sanitizers: ranges(sanitizers),
            guards: ranges(
                guards
                    .into_iter()
                    .filter(|m| prefix::guard_holds(m.get_node(), self.safe_prefix.as_ref()))
                    .collect(),
            ),
            summaries: Summaries::new(),
            source_texts: self.source_texts.clone(),
        };
        let known = summary::with_unique_methods(self.imported_summaries(lang, index, file, depth));
        // The file being checked (not an import, whose callers need its
        // summaries) can only carry taint from a source, a destructured request
        // parameter (`{ query }`) or a callee returning source data.
        let property = |s: &String| s.rsplit('.').next().map(|p| file.content.contains(p));
        if depth == 0
            && base.sources.is_empty()
            && !self.source_texts.iter().any(|s| property(s) == Some(true))
            && !known.values().any(|s| s.returns_source)
            && !self.decorated_input(&file.content)
        {
            return None;
        }
        let summaries =
            summary::with_unique_methods(self.summarize(index, lang, file, &base, &hits, &known));
        Some((Ctx { summaries, ..base }, hits))
    }

    /// Summaries of what `root` imports, keyed the way calls name them here.
    fn imported_summaries<D: Doc>(
        &self,
        lang: SupportLang,
        index: &FileIndex<D>,
        file: &SourceFile,
        depth: usize,
    ) -> Summaries {
        let mut out = Summaries::new();
        if depth >= IMPORT_DEPTH {
            return out;
        }
        for imp in index.imports(lang, &self.root.join(&file.rel), &self.root) {
            let Some(theirs) = self.file_summaries(&imp.path, depth + 1) else {
                continue;
            };
            for (exported, local) in &imp.names {
                if let Some(s) = theirs.get(exported) {
                    out.insert(local.clone(), s.clone());
                }
                // An imported class: its methods, `Local.method`.
                let prefix = format!("{exported}.");
                for (name, s) in theirs.iter() {
                    if let Some(method) = name.strip_prefix(&prefix) {
                        out.insert(format!("{local}.{method}"), s.clone());
                    }
                }
            }
            for (name, s) in theirs.iter() {
                if let Some(ns) = &imp.namespace {
                    out.insert(format!("{ns}.{name}"), s.clone());
                }
                if imp.all && !name.contains('.') {
                    out.entry(name.clone()).or_insert_with(|| s.clone());
                }
            }
        }
        out
    }

    fn file_summaries(&self, path: &Path, depth: usize) -> Option<Arc<Summaries>> {
        if let Some(s) = self.imported.lock().ok()?.get(path) {
            return Some(s.clone());
        }
        let lang = SupportLang::from_path(path)?;
        self.patterns(lang)?;
        let content = std::fs::read_to_string(path).ok()?;
        let rel = path
            .strip_prefix(&self.root)
            .unwrap_or(path)
            .to_string_lossy()
            .replace('\\', "/");
        let file = SourceFile { rel, content };
        let grep = lang.ast_grep(&file.content);
        let (ctx, _) = self.prepare(lang, &FileIndex::new(grep.root()), &file, depth)?;
        let s = Arc::new(ctx.summaries);
        self.imported
            .lock()
            .ok()?
            .insert(path.to_path_buf(), s.clone());
        Some(s)
    }

    /// Could a decorator bring request data into this file (`@Body()`, a route
    /// handler)? Cheap text check before the walk.
    fn decorated_input(&self, content: &str) -> bool {
        self.param_decorators
            .iter()
            .any(|d| content.contains(&format!("@{d}(")))
            || (self.handler_decorators.is_some() && content.contains('@'))
            || (self.resolver_args && (content.contains("args") || content.contains("info")))
    }
}
