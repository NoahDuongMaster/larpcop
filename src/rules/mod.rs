//! Rule engine: built-in rules, ast-grep rules and delegated linters.

mod ast;
mod linters;
mod max_lines;

pub use max_lines::ID as MAX_LINES_ID;

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
    ast: ast::AstRules,
    linters: Vec<linters::Linter>,
}

impl Engine {
    pub fn new(cfg: &Config) -> Result<Self> {
        let max_lines = match &cfg.max_lines {
            Some(m) if !cfg.disabled.contains(MAX_LINES_ID) => Some(max_lines::MaxLines::new(m)?),
            _ => None,
        };
        let ast = ast::AstRules::load(&cfg.rule_dirs, &cfg.disabled)?;
        let linters = cfg
            .linters
            .iter()
            .filter(|l| !cfg.disabled.contains(&l.id))
            .map(linters::Linter::new)
            .collect::<Result<_>>()?;
        Ok(Self {
            max_lines,
            ast,
            linters,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.max_lines.is_none() && self.ast.is_empty() && self.linters.is_empty()
    }

    pub fn check(&self, root: &Path, files: &[SourceFile]) -> Result<Vec<Violation>> {
        let mut found: Vec<Violation> = files
            .par_iter()
            .flat_map_iter(|file| {
                let mut v = self.ast.check(file);
                v.extend(self.max_lines.as_ref().and_then(|m| m.check(file)));
                v
            })
            .collect();
        for linter in &self.linters {
            found.extend(linter.run(root, files)?);
        }
        found.sort_by(|a, b| {
            (&a.file, a.line, a.column, &a.rule).cmp(&(&b.file, b.line, b.column, &b.rule))
        });
        Ok(found)
    }

    pub fn rules(&self) -> Vec<RuleInfo> {
        let mut out: Vec<RuleInfo> = self.max_lines.iter().map(|m| m.info()).collect();
        out.extend(self.ast.infos().iter().cloned());
        out.extend(self.linters.iter().map(|l| l.info()));
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }
}
