//! How deep imports are followed. Every file imported up to `SHALLOW` levels
//! deep is summarized; past that, up to `IMPORT_DEPTH`, only files that can
//! still lead to the rule's sinks or sources: the file mentions one, or a file
//! it imports within the remaining depth does. Elsewhere a call passes its
//! arguments' taint through, as for code we know nothing of, so leaving such a
//! file out loses no finding; following it cost the time of whole packages
//! (halo: 31 s at depth 2, 102 s at depth 4 summarizing everything).

use super::TaintRule;
use ast_grep_core::Language;
use ast_grep_core::tree_sitter::LanguageExt;
use ast_grep_language::SupportLang;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};

/// How many imports deep summaries are followed.
pub(super) const IMPORT_DEPTH: usize = 4;
/// Up to this depth every imported file is summarized.
pub(super) const SHALLOW: usize = 2;

/// A file's text and the files it imports: the same for every rule of a run.
pub(super) struct Entry {
    pub(super) text: String,
    pub(super) imports: Vec<PathBuf>,
}

static GRAPH: LazyLock<Mutex<HashMap<PathBuf, Option<Arc<Entry>>>>> =
    LazyLock::new(Default::default);

pub(super) fn entry(path: &Path, repo: &Path) -> Option<Arc<Entry>> {
    if let Some(known) = GRAPH.lock().ok()?.get(path) {
        return known.clone();
    }
    let computed = (|| {
        let lang = SupportLang::from_path(path)?;
        let text = std::fs::read_to_string(path).ok()?;
        let grep = lang.ast_grep(crate::rules::macros::expand(lang, &text));
        let imports = super::imports::imports(lang, &grep.root(), path, repo)
            .into_iter()
            .map(|i| i.path)
            .collect();
        Some(Arc::new(Entry { text, imports }))
    })();
    GRAPH
        .lock()
        .ok()?
        .entry(path.to_path_buf())
        .or_insert(computed)
        .clone()
}

impl TaintRule {
    /// Can `path`, or what it imports within `budget` more levels, bring this
    /// rule's sources or sinks into play?
    pub(super) fn reaches(&self, path: &Path, budget: usize) -> bool {
        let key = (path.to_path_buf(), budget);
        if let Some(known) = self.reach.lock().ok().and_then(|m| m.get(&key).copied()) {
            return known;
        }
        let Some(entry) = entry(path, &self.root) else {
            return false;
        };
        let found = self.matches(path, &entry)
            || (budget > 0 && entry.imports.iter().any(|i| self.reaches(i, budget - 1)));
        if let Ok(mut m) = self.reach.lock() {
            m.insert(key, found);
        }
        found
    }
}

impl TaintRule {
    /// Does the file match one of the rule's sources or sinks? Its words
    /// first, then the patterns themselves, then the sources and sinks the
    /// engine finds without a pattern (`fgets(buf, …)`, `execl("/bin/sh", …)`).
    fn matches(&self, path: &Path, entry: &Entry) -> bool {
        // Kept with the depths, under a depth no walk asks for.
        let key = (path.to_path_buf(), usize::MAX);
        if let Some(known) = self.reach.lock().ok().and_then(|m| m.get(&key).copied()) {
            return known;
        }
        let found = self.scan_matches(path, entry);
        if let Ok(mut m) = self.reach.lock() {
            m.insert(key, found);
        }
        found
    }

    fn scan_matches(&self, path: &Path, entry: &Entry) -> bool {
        let Some(lang) = SupportLang::from_path(path) else {
            return false;
        };
        let Some(patterns) = self.patterns(lang) else {
            return false;
        };
        let worded = patterns
            .needles()
            .is_none_or(|needles| needles.iter().any(|n| entry.text.contains(n)));
        let extra = self.shell_argv.is_some() || self.path_objects.is_some() || self.html_fragments;
        let text = crate::rules::macros::expand(lang, &entry.text);
        if self.writes.reads_input(&text) {
            return true;
        }
        if !worded && !extra {
            return false;
        }
        let grep = lang.ast_grep(text);
        let index = super::scan::FileIndex::new(grep.root());
        if worded {
            let [sources, sinks, ..] = patterns.scan(&index);
            if !sources.is_empty() || !sinks.is_empty() {
                return true;
            }
        }
        extra && !self.extra_sinks(&index).is_empty()
    }
}
