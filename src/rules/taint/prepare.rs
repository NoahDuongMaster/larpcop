//! What a check needs before the walk: sources, sinks, sanitizers and guards
//! found in the file, and summaries of the functions it defines or imports.

use super::events::{Hit, Hits};
use super::flow::Ctx;
use super::scan::FileIndex;
use super::summary::{self, Summaries};
use super::{IMPORT_DEPTH, TaintRule, prefix};
use crate::files::SourceFile;
use ast_grep_core::{Doc, Language, Node, NodeMatch};
use ast_grep_language::LanguageExt;
use ast_grep_language::SupportLang;
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;

/// One imported file's summaries (`None`: not a file the rule reads).
pub(super) type Slot = Option<Arc<Summaries>>;

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
        let [sources, sinks, sanitizers, guards, rejects] = self.patterns(lang)?.scan(index);
        let [sinks, sanitizers, guards] = [sinks, sanitizers, guards].map(|m| self.valued.keep(m));
        let plain = |ms: Vec<(NodeMatch<'a, D>, usize)>| -> Vec<NodeMatch<'a, D>> {
            ms.into_iter().map(|(m, _)| m).collect()
        };
        let (sources, sinks, sanitizers) = (plain(sources), plain(sinks), plain(sanitizers));
        // A bare-name source (`params`) is not one in a function with a parameter so named.
        let sources: Vec<NodeMatch<'a, D>> = sources
            .into_iter()
            .filter(|m| {
                let n = m.get_node();
                n.kind() != "identifier"
                    || !n
                        .ancestors()
                        .find(|a| crate::rules::complexity::is_function(a))
                        .is_some_and(|f| summary::param_names(&f).contains(n.text().as_ref()))
            })
            .filter(|m| {
                let routes = (&self.fixed_routes, self.handler_decorators.as_ref());
                !routes
                    .1
                    .is_some_and(|h| routes.0.is_constant(m.get_node(), h, &self.root))
            })
            .collect();
        // `source_types`/`source_text` (`repo.findAll()` on a `*Repository`).
        let sources = self.source_types.keep(&index.root, sources);
        let ranges = |ms: Vec<NodeMatch<'a, D>>| -> Vec<Range<usize>> {
            ms.iter().map(|m| m.range()).collect()
        };
        // An HTML escaper in an attribute without quotes, a handler or a
        // script does not clean.
        let misplaced = |n: &Node<'a, D>| {
            super::placements::misplaced(n, self.escape_contexts, self.quote_escapers.as_ref())
        };
        let cleaned: Vec<Range<usize>> = sanitizers
            .iter()
            .map(|m| m.get_node().clone())
            .chain(
                self.sanitizer_names
                    .as_ref()
                    .map(|re| index.calls_named(re))
                    .unwrap_or_default(),
            )
            .filter(|n| !misplaced(n))
            .map(|n| n.range())
            .collect();
        let mut hits: Vec<Hit<_>> = Vec::new();
        {
            // A source expression is not a sink call: gin's `c.Query("q")`
            // also has the shape of `db.Query(sql)`.
            let is_source = |r: &Range<usize>| {
                sources
                    .iter()
                    .any(|s| s.range().start <= r.start && r.end <= s.range().end)
            };
            for m in sinks.into_iter().filter(|m| !is_source(&m.range())) {
                let arg = self
                    .sink_arg
                    .as_deref()
                    .and_then(|v| m.get_env().get_match(v).cloned());
                // A Ruby call without parentheses (`where $SQL`) binds the
                // whole argument list: it stands for its first argument.
                let arg = arg.map(|a| {
                    let first = (a.kind() == "argument_list")
                        .then(|| a.children().find(|c| c.is_named()))
                        .flatten();
                    first.unwrap_or(a)
                });
                // Ruby hash conditions (`where(id: x)`) are bound, not SQL text.
                if arg
                    .as_ref()
                    .is_some_and(|a| matches!(a.kind().as_ref(), "pair" | "hash"))
                {
                    continue;
                }
                let node = arg.unwrap_or_else(|| m.get_node().clone());
                // The function around the sink set it up safely.
                if !self.unless.is_empty() {
                    let around = m
                        .get_node()
                        .ancestors()
                        .find(|a| crate::rules::complexity::is_function(a));
                    let text = around.map(|f| f.text().to_string()).unwrap_or_default();
                    if self.unless.iter().any(|u| u.is_match(&text)) {
                        continue;
                    }
                }
                if (self.safe_prefix.as_ref()).is_some_and(|re| prefix::safe_start(re, &node)) {
                    continue;
                }
                // `reverse(…) + "?q=" + q`: starts with a URL the app builds.
                let first = prefix::leftmost(&node).range();
                if self.safe_prefix.is_some()
                    && first != node.range()
                    && cleaned
                        .iter()
                        .any(|s| s.start <= first.start && first.end <= s.end)
                {
                    continue;
                }
                // `$JM.readValue(…)` on a mapper with default typing on.
                if !self.configured.holds(&index.root, m.get_env()) {
                    continue;
                }
                if !self.sink_texts.holds(m.get_env()) {
                    continue;
                }
                let typed = self.typed.metavariables(m.get_env());
                hits.push((m.range().start, node, typed));
            }
        }
        hits.extend(self.extra_sinks(index));
        // Overlapping sink patterns (and Go's wrapped ones) find a call more than once: keep the match with the fewest type constraints.
        hits.sort_by_key(|(at, n, typed)| (*at, n.range().start, n.range().end, typed.len()));
        hits.dedup_by_key(|(at, node, _)| (*at, node.range().start, node.range().end));
        let hits = Hits::new(hits, &index.root, index.skeletons.clone());
        let base = Ctx {
            sources: ranges(sources)
                .into_iter()
                .chain(index.named(&self.source_names))
                .collect(),
            sanitizers: cleaned,
            guards: guards
                .iter()
                .filter(|(m, _)| prefix::guard_holds(m.get_node(), self.safe_prefix.as_ref()))
                .map(|(m, w)| (m.range(), true, *w))
                .chain(rejects.iter().map(|(m, w)| (m.range(), false, *w)))
                .collect(),
            summaries: Summaries::new(),
            source_texts: self.source_texts.clone(),
            sourcing: Default::default(),
            bare_calls: lang == SupportLang::Ruby,
            safe_prefix: self.safe_prefix.clone(),
            summarized: Default::default(),
            built: Default::default(),
            cleaners: self.cleaners.clone(),
            writes: self.writes.clone(),
            writes_clean: self.own_serialization_safe,
            numbers: lang == SupportLang::Php,
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
            && !self.writes.reads_input(&index.root.text())
        {
            return None;
        }
        let mut summaries = self.summarize(index, lang, file, &base, &hits, &known);
        // An imported Go file stands for its own functions only: Go has no
        // re-exports, and its package's other files are imported directly.
        // Passing on everything it imported made a package of n files cost n².
        if depth > 0 && lang == SupportLang::Go {
            let own: std::collections::HashSet<&str> =
                index.functions().iter().map(|(n, ..)| n.as_str()).collect();
            summaries.retain(|name, _| own.contains(name.as_str()));
        }
        let mut ctx = Ctx {
            summaries: summary::with_unique_methods(summaries),
            sourcing: Default::default(),
            summarized: Default::default(),
            built: Default::default(),
            ..base
        };
        let validating = super::validators::calls(index, &ctx);
        ctx.guards.extend(validating);
        Some((ctx, hits))
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
                super::higher::import_variants(&theirs, exported, local, &mut out);
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
                // Same package (Go): its functions and its types' methods
                // (`Profile.Load`) are named here as there.
                if imp.all && !name.starts_with("*.") {
                    out.entry(name.clone()).or_insert_with(|| s.clone());
                }
            }
        }
        out
    }

    /// Keyed by depth too, so the result never depends on which thread got
    /// there first. Two threads may compute the same entry at once: waiting
    /// for each other instead serialized whole packages.
    fn file_summaries(&self, path: &Path, depth: usize) -> Option<Arc<Summaries>> {
        let key = (path.to_path_buf(), depth);
        if let Some(known) = self.imported.lock().ok()?.get(&key) {
            return known.clone();
        }
        let computed = self.compute_summaries(path, depth);
        self.imported
            .lock()
            .ok()?
            .entry(key)
            .or_insert(computed)
            .clone()
    }

    fn compute_summaries(&self, path: &Path, depth: usize) -> Option<Arc<Summaries>> {
        if depth > super::reach::SHALLOW && !self.reaches(path, IMPORT_DEPTH - depth) {
            return None;
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
        let grep = lang.ast_grep(crate::rules::macros::expand(lang, &file.content));
        let (ctx, _) = self.prepare(lang, &FileIndex::new(grep.root()), &file, depth)?;
        Some(Arc::new(ctx.summaries))
    }

    /// Could a decorator bring request data into this file (`@Body()`, a route
    /// handler)? Cheap text check before the walk.
    fn decorated_input(&self, content: &str) -> bool {
        self.param_decorators
            .iter()
            .any(|d| content.contains(&format!("@{d}")) || content.contains(&format!("[{d}")))
            || (self.handler_decorators.is_some()
                && (content.contains('@') || content.contains('[')))
            || (self.resolver_args && (content.contains("args") || content.contains("info")))
            || super::services::may_serve(
                content,
                self.handler_classes.as_ref(),
                self.input_types.is_some(),
            )
    }
}
