//! Fixtures for taint and text rules: each snippet is checked as a file of
//! the rule's language (or the fixture's `file:` name), without a language
//! server, so a sink that needs a type counts.

use crate::config::{TaintConfig, TextRuleConfig};
use crate::files::SourceFile;
use crate::rules::taint::{TaintRule, typed::Typed};
use crate::rules::text::TextRule;
use anyhow::{Result, bail};
use ast_grep_language::SupportLang;
use std::path::Path;

pub enum FlowRule {
    Taint(TaintRule),
    Text(TextRule),
}

impl FlowRule {
    pub fn taint(cfg: &TaintConfig, root: &Path) -> Result<Self> {
        Ok(Self::Taint(TaintRule::new(
            cfg,
            Typed::default(),
            root.to_path_buf(),
        )?))
    }

    pub fn text(cfg: &TextRuleConfig) -> Result<Self> {
        Ok(Self::Text(TextRule::new(cfg)?))
    }

    /// File names to check a snippet as: one per language, or the fixture's own.
    pub fn files(&self, file: Option<&str>) -> Result<Vec<String>> {
        match (self, file) {
            (_, Some(f)) => Ok(vec![f.to_string()]),
            (Self::Taint(t), None) => Ok(t
                .languages()
                .into_iter()
                .map(|l| format!("case.{}", ext(l)))
                .collect()),
            (Self::Text(_), None) => {
                bail!("fixtures of text rules need `file:` (a path the rule's globs match)")
            }
        }
    }

    pub fn hits(&self, rel: &str, src: &str) -> usize {
        let file = SourceFile {
            rel: rel.to_string(),
            content: src.to_string(),
        };
        match self {
            Self::Taint(t) => t.check(&file).len(),
            Self::Text(t) => t.check(&file).len(),
        }
    }
}

fn ext(lang: SupportLang) -> &'static str {
    match lang {
        SupportLang::TypeScript => "ts",
        SupportLang::Tsx => "tsx",
        SupportLang::JavaScript => "js",
        SupportLang::Python => "py",
        SupportLang::Go => "go",
        SupportLang::Rust => "rs",
        SupportLang::Java => "java",
        SupportLang::Kotlin => "kt",
        SupportLang::CSharp => "cs",
        SupportLang::Ruby => "rb",
        SupportLang::Php => "php",
        SupportLang::Swift => "swift",
        SupportLang::Scala => "scala",
        SupportLang::C => "c",
        SupportLang::Cpp => "cpp",
        _ => "txt",
    }
}
