//! Built-in `max-lines` rule: language-agnostic file length limit.

use super::{Level, RuleInfo, Violation};
use crate::config::MaxLinesConfig;
use crate::files::{SourceFile, globset};
use anyhow::Result;
use ast_grep_core::Language;
use ast_grep_language::SupportLang;
use globset::GlobSet;

pub const ID: &str = "max-lines";

const NOTE: &str = "Split the file along responsibility boundaries into smaller modules. \
Do not compress code, join lines or delete comments just to get under the limit.";

pub struct MaxLines {
    max: usize,
    level: Level,
    include: Option<GlobSet>,
    include_desc: String,
    exclude: GlobSet,
}

impl MaxLines {
    pub fn new(cfg: &MaxLinesConfig) -> Result<Self> {
        let include = (!cfg.include.is_empty())
            .then(|| globset(&cfg.include))
            .transpose()?;
        let include_desc = if cfg.include.is_empty() {
            "source files".to_string()
        } else {
            cfg.include.join(", ")
        };
        Ok(Self {
            max: cfg.max,
            level: cfg.level,
            include,
            include_desc,
            exclude: globset(&cfg.exclude)?,
        })
    }

    fn applies(&self, rel: &str) -> bool {
        if self.exclude.is_match(rel) {
            return false;
        }
        match &self.include {
            Some(globs) => globs.is_match(rel),
            None => is_source(rel),
        }
    }

    pub fn check(&self, file: &SourceFile) -> Option<Violation> {
        if !self.applies(&file.rel) {
            return None;
        }
        let lines = file.content.lines().count();
        (lines > self.max).then(|| Violation {
            rule: ID.to_string(),
            level: self.level,
            file: file.rel.clone(),
            line: self.max + 1,
            column: 1,
            message: format!("File has {lines} lines; the limit is {}.", self.max),
            note: Some(NOTE.to_string()),
            snippet: None,
        })
    }

    pub fn info(&self) -> RuleInfo {
        RuleInfo {
            id: ID.to_string(),
            level: self.level,
            scope: self.include_desc.clone(),
            message: format!("Files must not exceed {} lines.", self.max),
            note: Some(NOTE.to_string()),
        }
    }
}

/// Code files only: data and docs formats are not subject to a length limit by default.
fn is_source(rel: &str) -> bool {
    use SupportLang::{Html, Json, Markdown, Yaml};
    SupportLang::from_path(rel).is_some_and(|l| !matches!(l, Json | Yaml | Markdown | Html))
}
