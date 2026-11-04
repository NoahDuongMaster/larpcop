//! The rules on one file: one parse of the tree, handed to every rule set.

use super::Engine;
use super::{Violation, macros, scripts, taint};
use crate::files::SourceFile;

impl Engine {
    /// Every built-in rule on one file. A minified bundle (a vendored library
    /// nobody edits) is only searched for secrets, which do ship in bundles.
    pub(super) fn check_file(&self, file: &SourceFile) -> Vec<Violation> {
        let mut v = self.secrets(file);
        if crate::files::minified(&file.content) {
            return v;
        }
        // One parse for every rule that walks the tree: the parse is a third
        // of the cost of a file that has taint rules to run.
        use ast_grep_language::{Language, LanguageExt, SupportLang};
        // Nothing to walk the tree for: no parse at all (most of a repository
        // is files no rule is written for).
        let ast_rules = self.ast.rules_for_path(&file.rel);
        let wanted = SupportLang::from_path(&file.rel).filter(|lang| {
            !ast_rules.is_empty()
                || self.metrics.iter().any(|m| m.applies(&file.rel))
                || self.taint.iter().any(|t| t.handles(*lang))
        });
        if let Some(lang) = wanted {
            let grep = lang.ast_grep(macros::expand(lang, &file.content));
            let root = &grep.root();
            v.extend(self.ast.check_root(&ast_rules, file, root));
            v.extend(self.metrics.iter().flat_map(|m| m.check_root(file, root)));
            v.extend(self.taint_check_root(file, lang, root));
        }
        v.extend(self.max_lines.as_ref().and_then(|m| m.check(file)));
        v.extend(self.text.iter().flat_map(|t| t.check(file)));
        v.extend(self.page_scripts(file));
        v
    }

    /// The JavaScript rules on a page's `<script>` blocks (scripts.rs),
    /// reported at the page's path and lines.
    fn page_scripts(&self, file: &SourceFile) -> Vec<Violation> {
        let Some((view, ts)) = scripts::view(&file.rel, &file.content) else {
            return Vec::new();
        };
        let suffix = if ts {
            scripts::SUFFIX_TS
        } else {
            scripts::SUFFIX_JS
        };
        let page = SourceFile {
            rel: format!("{}{suffix}", file.rel),
            content: view,
        };
        // The script is JavaScript or TypeScript by its suffix: parsed once for
        // the rules that walk it.
        use ast_grep_language::{Language, LanguageExt, SupportLang};
        let ast_rules = self.ast.rules_for_path(&page.rel);
        let lang = SupportLang::from_path(&page.rel)
            .filter(|l| !ast_rules.is_empty() || self.taint.iter().any(|t| t.handles(*l)));
        let Some(lang) = lang else {
            return Vec::new();
        };
        let grep = lang.ast_grep(macros::expand(lang, &page.content));
        let root = &grep.root();
        let mut found = self.ast.check_root(&ast_rules, &page, root);
        found.extend(self.taint_check_root(&page, lang, root));
        for v in &mut found {
            v.file.clone_from(&file.rel);
        }
        found
    }

    /// Taint rules on a tree that has already been parsed.
    fn taint_check_root<D: ast_grep_core::Doc>(
        &self,
        file: &SourceFile,
        lang: ast_grep_language::SupportLang,
        root: &ast_grep_core::Node<D>,
    ) -> Vec<Violation> {
        if !self.taint.iter().any(|t| t.handles(lang)) {
            return Vec::new();
        }
        let index = taint::FileIndex::new(root.clone());
        taint::check_indexed_multi(&self.taint, file, lang, &index)
    }

    fn secrets(&self, file: &SourceFile) -> Vec<Violation> {
        match &self.secrets {
            Some((s, exclude)) if !exclude.is_match(&file.rel) => s.check(&file.rel, &file.content),
            _ => Vec::new(),
        }
    }
}
