//! Rule engine: built-in rules, ast-grep rules and delegated linters.

mod ast;
mod complexity;
mod linters;
pub mod macros;
mod max_lines;
pub mod metrics;
mod pattern_fixes;
pub(crate) mod php_html;
pub mod secrets;
mod settings;
mod taint;
pub mod testing;
mod text;
pub mod values;
#[cfg(test)]
mod values_tests;

/// ast-grep rules defined in `dirs` (for `larpcop learn`).
pub fn ast_rules(
    dirs: &[std::path::PathBuf],
) -> Result<Vec<ast_grep_config::RuleConfig<ast_grep_language::SupportLang>>> {
    ast::load_all(dirs)
}

pub use max_lines::ID as MAX_LINES_ID;
pub use metrics::{COMPLEXITY_ID, LENGTH_ID};

use crate::config::Config;
use crate::files::SourceFile;
use anyhow::Result;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Hint,
    Info,
    Warning,
    #[default]
    Error,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hint => "hint",
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Violation {
    pub rule: String,
    pub level: Level,
    /// Repo-relative path; empty for project-wide findings (linters).
    pub file: String,
    /// 1-based; 0 when the finding has no position.
    pub line: usize,
    pub column: usize,
    pub message: String,
    /// How to fix it — written for the agent that has to act on it.
    pub note: Option<String>,
    pub snippet: Option<String>,
}

/// Human/agent-facing description of an active rule (used for AGENTS.md).
#[derive(Debug, Clone)]
pub struct RuleInfo {
    pub id: String,
    pub level: Level,
    pub scope: String,
    pub message: String,
    pub note: Option<String>,
}

pub struct Engine {
    max_lines: Option<max_lines::MaxLines>,
    metrics: Option<metrics::Metrics>,
    secrets: Option<(secrets::Secrets, globset::GlobSet)>,
    taint: Vec<taint::TaintRule>,
    text: Vec<text::TextRule>,
    ast: ast::AstRules,
    linters: Vec<linters::Linter>,
    deps: Option<crate::deps::Deps>,
}

impl Engine {
    pub fn new(cfg: &Config) -> Result<Self> {
        let max_lines = match &cfg.max_lines {
            Some(m) if !cfg.disabled.contains(MAX_LINES_ID) => Some(max_lines::MaxLines::new(m)?),
            _ => None,
        };
        let ast = ast::AstRules::load(&cfg.rule_dirs, &cfg.disabled, &cfg.root)?;
        let linters = cfg
            .linters
            .iter()
            .filter(|l| !cfg.disabled.contains(&l.id))
            .map(linters::Linter::new)
            .collect::<Result<_>>()?;
        let metrics = cfg
            .metrics
            .as_ref()
            .map(metrics::Metrics::new)
            .transpose()?;
        let secrets = match &cfg.secrets {
            Some(s) if !cfg.disabled.contains(secrets::ID) => {
                Some((secrets::Secrets::new()?, crate::files::globset(&s.exclude)?))
            }
            _ => None,
        };
        let taint = cfg
            .taint
            .iter()
            .filter(|t| !cfg.disabled.contains(&t.id))
            .map(|t| {
                let servers = cfg.language_servers.clone();
                let typed =
                    taint::typed::Typed::new(&t.id, &t.sink_types, cfg.root.clone(), servers)?;
                taint::TaintRule::new(t, typed, cfg.root.clone())
            })
            .collect::<Result<_>>()?;
        let text = cfg
            .text
            .iter()
            .filter(|t| !cfg.disabled.contains(&t.id))
            .map(|t| text::TextRule::new(t, &cfg.root))
            .collect::<Result<_>>()?;
        Ok(Self {
            max_lines,
            metrics,
            secrets,
            taint,
            text,
            ast,
            linters,
            deps: crate::deps::Deps::new(cfg)?,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.max_lines.is_none()
            && self.metrics.is_none()
            && self.secrets.is_none()
            && self.taint.is_empty()
            && self.text.is_empty()
            && self.ast.is_empty()
            && self.linters.is_empty()
            && self.deps.is_none()
    }

    pub fn deps(&self) -> Option<&crate::deps::Deps> {
        self.deps.as_ref()
    }

    pub fn check(&self, root: &Path, files: &[SourceFile]) -> Result<Vec<Violation>> {
        let mut found: Vec<Violation> = files
            .par_iter()
            .flat_map_iter(|file| self.check_file(file))
            .collect();
        for linter in &self.linters {
            found.extend(linter.run(root, files)?);
        }
        Ok(found)
    }

    /// Built-in and ast-grep rules on one file's content (no external linters,
    /// which only see the disk).
    pub fn check_source(&self, file: &SourceFile) -> Vec<Violation> {
        let mut v = self.check_file(file);
        sort(&mut v);
        v
    }

    /// Every built-in rule on one file. A minified bundle (a vendored library
    /// nobody edits) is only searched for secrets, which do ship in bundles.
    fn check_file(&self, file: &SourceFile) -> Vec<Violation> {
        let mut v = self.secrets(file);
        if crate::files::minified(&file.content) {
            return v;
        }
        v.extend(self.ast.check(file));
        v.extend(self.max_lines.as_ref().and_then(|m| m.check(file)));
        v.extend(self.metrics.iter().flat_map(|m| m.check(file)));
        v.extend(self.taint_check(file));
        v.extend(self.text.iter().flat_map(|t| t.check(file)));
        v
    }

    /// Taint rules on one parse and one walk of the file: each rule only
    /// matches its patterns against the nodes of the kinds they can match.
    fn taint_check(&self, file: &SourceFile) -> Vec<Violation> {
        use ast_grep_language::{Language, LanguageExt, SupportLang};
        let Some(lang) =
            SupportLang::from_path(&file.rel).filter(|l| self.taint.iter().any(|t| t.handles(*l)))
        else {
            return Vec::new();
        };
        let grep = lang.ast_grep(macros::expand(lang, &file.content));
        let index = taint::FileIndex::new(grep.root());
        self.taint
            .iter()
            .flat_map(|t| t.check_indexed(file, lang, &index))
            .collect()
    }

    fn secrets(&self, file: &SourceFile) -> Vec<Violation> {
        match &self.secrets {
            Some((s, exclude)) if !exclude.is_match(&file.rel) => s.check(&file.rel, &file.content),
            _ => Vec::new(),
        }
    }

    /// Auto-fixes from ast-grep rules: `(file, new content, fixes applied)`.
    pub fn fix(&self, files: &[SourceFile]) -> Vec<(String, String, usize)> {
        files
            .par_iter()
            .filter_map(|f| self.ast.fix(f).map(|(text, n)| (f.rel.clone(), text, n)))
            .collect()
    }

    /// Rules that apply to one root-relative path (language and `files` globs).
    pub fn rules_for(&self, rel: &str) -> Vec<RuleInfo> {
        let mut out: Vec<RuleInfo> = self.max_lines.iter().map(|m| m.info()).collect();
        out.extend(self.metrics.iter().flat_map(|m| m.infos()));
        out.extend(self.secrets.iter().map(|_| secrets::Secrets::info()));
        out.extend(self.taint.iter().map(|t| t.info()));
        out.extend(
            self.text
                .iter()
                .filter(|t| t.applies_to(rel))
                .map(|t| t.info()),
        );
        out.extend(self.ast.infos_for(rel));
        out.extend(self.linters.iter().map(|l| l.info()));
        out
    }

    pub fn rules(&self) -> Vec<RuleInfo> {
        let mut out: Vec<RuleInfo> = self.max_lines.iter().map(|m| m.info()).collect();
        out.extend(self.metrics.iter().flat_map(|m| m.infos()));
        out.extend(self.secrets.iter().map(|_| secrets::Secrets::info()));
        out.extend(self.taint.iter().map(|t| t.info()));
        out.extend(self.text.iter().map(|t| t.info()));
        out.extend(self.ast.infos().iter().cloned());
        out.extend(self.linters.iter().map(|l| l.info()));
        out.extend(self.deps.iter().flat_map(|d| d.rules()));
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }
}

/// Report order: by file, then position, then rule.
pub fn sort(violations: &mut [Violation]) {
    violations.sort_by(|a, b| {
        (&a.file, a.line, a.column, &a.rule).cmp(&(&b.file, b.line, b.column, &b.rule))
    });
}
