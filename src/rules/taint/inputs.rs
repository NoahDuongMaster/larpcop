//! Where request data can enter. A file none of whose code takes input
//! (no source, no request parameter) and none of whose imports, within the
//! import depth, does either, has nothing for a taint walk to follow: no
//! summary of what it imports returns source data, so its check finds
//! nothing. Telling so from the files' text is far cheaper than summarizing
//! the whole import closure once per rule only to find that out.

use super::TaintRule;
use super::reach::{Entry, IMPORT_DEPTH, entry};
use super::scan::FileIndex;
use ast_grep_core::{Doc, Language};
use ast_grep_language::{LanguageExt, SupportLang};
use std::path::Path;

/// The node kind of a destructuring pattern, as destructure.rs reads it.
const PATTERN: &str = "object_pattern";

impl TaintRule {
    /// Can request data start in this file's own code: `sources` (a source
    /// matched, or a name that is one), a source spelled in a destructuring, a
    /// call that reads input, and if `params` a function whose parameters
    /// carry request data?
    pub(super) fn input_here<D: Doc>(
        &self,
        lang: SupportLang,
        index: &FileIndex<D>,
        (content, text): (&str, &str),
        (sources, params): (bool, bool),
    ) -> bool {
        sources
            || (self.may_destructure(lang, content) && index.has_kind(lang.kind_to_id(PATTERN)))
            || self.writes.reads_input(text)
            || (params && index.all_functions().any(|f| !self.own_names(f).is_empty()))
    }

    /// Could the file destructure a source (`const { query } = req`, for the
    /// source `req.query`)? It spells the last segment of one and its grammar
    /// has object patterns, the one construct that binds names from a source
    /// object (destructure.rs).
    fn may_destructure(&self, lang: SupportLang, content: &str) -> bool {
        lang.kind_to_id(PATTERN) != 0
            && self
                .source_texts
                .iter()
                .any(|s| s.rsplit('.').next().is_some_and(|p| content.contains(p)))
    }

    /// Could a function of the file have parameters that carry request data
    /// (handlers.rs, services.rs, destructure.rs)? Wider than
    /// [`TaintRule::decorated_input`], which also leaves out resolvers taking
    /// their arguments as `{ id }` or as `input` and `variables`.
    fn may_take_params(&self, lang: SupportLang, content: &str) -> bool {
        self.may_destructure(lang, content)
            || self.decorated_input(content)
            || (self.resolver_args
                && (lang.kind_to_id(PATTERN) != 0
                    || ["args", "input", "variables", "info"]
                        .iter()
                        .any(|w| content.contains(w))))
    }

    /// Can what the file at `rel` imports, within the import depth, take input?
    pub(super) fn imports_take_input<D: Doc>(
        &self,
        lang: SupportLang,
        index: &FileIndex<D>,
        rel: &str,
    ) -> bool {
        index
            .imports(lang, &self.root.join(rel), &self.root)
            .iter()
            .any(|imp| self.takes_input(&imp.path, IMPORT_DEPTH - 1))
    }

    /// Can `path`, or what it imports within `budget` more levels, take input?
    /// A file the rule does not read is not summarized, nor what it imports.
    pub(super) fn takes_input(&self, path: &Path, budget: usize) -> bool {
        let key = (path.to_path_buf(), budget);
        if let Some(known) = self.inputs.lock().ok().and_then(|m| m.get(&key).copied()) {
            return known;
        }
        let Some(entry) = entry(path, &self.root) else {
            return false;
        };
        let found = self.takes_input_alone(path, &entry)
            || (budget > 0
                && entry
                    .imports
                    .iter()
                    .any(|i| self.takes_input(i, budget - 1)));
        if let Ok(mut m) = self.inputs.lock() {
            m.insert(key, found);
        }
        found
    }

    /// Kept with the depths, under a depth no walk asks for.
    fn takes_input_alone(&self, path: &Path, entry: &Entry) -> bool {
        let key = (path.to_path_buf(), usize::MAX);
        if let Some(known) = self.inputs.lock().ok().and_then(|m| m.get(&key).copied()) {
            return known;
        }
        let found = self.scan_input(path, entry);
        if let Ok(mut m) = self.inputs.lock() {
            m.insert(key, found);
        }
        found
    }

    /// Parses the file only when its text allows a source or a request
    /// parameter; the answer errs towards yes (the patterns' filters, which
    /// only remove sources, are left out).
    fn scan_input(&self, path: &Path, entry: &Entry) -> bool {
        let Some(lang) = SupportLang::from_path(path) else {
            return false;
        };
        let Some(patterns) = self.patterns(lang) else {
            return false;
        };
        let text = crate::rules::macros::expand(lang, &entry.text);
        // A name that is a source (`$_SERVER['HTTP_`) is spelled through its start.
        let may_name = self
            .source_names
            .iter()
            .any(|n| text.contains(n.split('[').next().unwrap_or(n)));
        let may_source = patterns.may_source(&text) || may_name;
        let params = self.may_take_params(lang, &entry.text);
        if !may_source && !params {
            return self.writes.reads_input(&text);
        }
        let grep = lang.ast_grep(text);
        let index = FileIndex::new(grep.root());
        let sources = may_source
            && (!patterns.scan(&index)[0].is_empty()
                || !index.named(&self.source_names).is_empty());
        self.input_here(
            lang,
            &index,
            (&entry.text, &index.root.text()),
            (sources, params),
        )
    }
}
