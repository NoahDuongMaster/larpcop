//! `complexity` and `function-length` rules plus the `larpcop metrics` report.

use super::complexity::{self, Function};
use super::{Level, RuleInfo, Violation};
use crate::config::MetricsConfig;
use crate::files::{SourceFile, globset};
use anyhow::Result;
use ast_grep_core::Language;
use ast_grep_language::SupportLang;
use globset::GlobSet;
use serde::Serialize;
use std::fmt::Write;

pub const COMPLEXITY_ID: &str = "complexity";
pub const LENGTH_ID: &str = "function-length";

pub struct Metrics {
    max_complexity: Option<usize>,
    max_lines: Option<usize>,
    exclude: GlobSet,
}

impl Metrics {
    pub fn new(cfg: &MetricsConfig) -> Result<Self> {
        Ok(Self {
            max_complexity: cfg.max_complexity,
            max_lines: cfg.max_function_lines,
            exclude: globset(&cfg.exclude)?,
        })
    }

    pub fn infos(&self) -> Vec<RuleInfo> {
        let mut out = Vec::new();
        if let Some(max) = self.max_complexity {
            out.push(RuleInfo {
                id: COMPLEXITY_ID.into(),
                level: Level::Error,
                scope: "functions, any language".into(),
                message: format!("Cyclomatic complexity of a function must not exceed {max}."),
                note: Some(SPLIT.into()),
            });
        }
        if let Some(max) = self.max_lines {
            out.push(RuleInfo {
                id: LENGTH_ID.into(),
                level: Level::Error,
                scope: "functions, any language".into(),
                message: format!("Functions must not exceed {max} lines."),
                note: Some(SPLIT.into()),
            });
        }
        out
    }

    pub fn check(&self, file: &SourceFile) -> Vec<Violation> {
        let Some(lang) = SupportLang::from_path(&file.rel) else {
            return Vec::new();
        };
        if self.exclude.is_match(&file.rel) {
            return Vec::new();
        }
        let mut out = Vec::new();
        for f in complexity::functions(lang, &file.content) {
            if let Some(max) = self.max_complexity.filter(|m| f.complexity > *m) {
                out.push(self.violation(
                    file,
                    &f,
                    COMPLEXITY_ID,
                    format!(
                        "`{}` has cyclomatic complexity {} (max {max}).",
                        f.name, f.complexity
                    ),
                ));
            }
            if let Some(max) = self.max_lines.filter(|m| f.lines > *m) {
                out.push(self.violation(
                    file,
                    &f,
                    LENGTH_ID,
                    format!("`{}` is {} lines long (max {max}).", f.name, f.lines),
                ));
            }
        }
        out
    }

    fn violation(&self, file: &SourceFile, f: &Function, rule: &str, message: String) -> Violation {
        Violation {
            rule: rule.into(),
            level: Level::Error,
            file: file.rel.clone(),
            line: f.line,
            column: 1,
            message,
            note: Some(SPLIT.into()),
            snippet: file
                .content
                .lines()
                .nth(f.line - 1)
                .map(|l| l.trim().chars().take(120).collect()),
        }
    }
}

const SPLIT: &str = "Extract cohesive steps into well-named functions, replace branching on \
type/flags with lookup or polymorphism, and return early. Do not just move code into a helper that \
takes the same flags.";

#[derive(Serialize)]
pub struct FunctionRow {
    pub file: String,
    pub name: String,
    pub line: usize,
    pub lines: usize,
    pub complexity: usize,
}

#[derive(Serialize)]
pub struct Summary {
    pub files: usize,
    pub code_lines: usize,
    pub functions: usize,
    pub mean_complexity: f64,
    pub most_complex: Vec<FunctionRow>,
}

/// Size and complexity of a set of files; `top` most complex functions listed.
pub fn summarize(files: &[SourceFile], top: usize) -> Summary {
    let mut rows = Vec::new();
    let mut code_lines = 0;
    let mut measured = 0;
    for file in files {
        let Some(lang) = SupportLang::from_path(&file.rel) else {
            continue;
        };
        measured += 1;
        code_lines += file
            .content
            .lines()
            .filter(|l| !l.trim().is_empty())
            .count();
        rows.extend(
            complexity::functions(lang, &file.content)
                .into_iter()
                .map(|f| FunctionRow {
                    file: file.rel.clone(),
                    name: f.name,
                    line: f.line,
                    lines: f.lines,
                    complexity: f.complexity,
                }),
        );
    }
    let total: usize = rows.iter().map(|r| r.complexity).sum();
    let mean = if rows.is_empty() {
        0.0
    } else {
        total as f64 / rows.len() as f64
    };
    let functions = rows.len();
    rows.sort_by(|a, b| b.complexity.cmp(&a.complexity).then(b.lines.cmp(&a.lines)));
    rows.truncate(top);
    Summary {
        files: measured,
        code_lines,
        functions,
        mean_complexity: (mean * 100.0).round() / 100.0,
        most_complex: rows,
    }
}

pub fn render(s: &Summary) -> String {
    let mut out = format!(
        "{} source file(s), {} non-blank line(s), {} function(s), mean complexity {:.2}\n\n",
        s.files, s.code_lines, s.functions, s.mean_complexity
    );
    out.push_str("complexity  lines  function\n");
    for r in &s.most_complex {
        let _ = writeln!(
            out,
            "{:>10}  {:>5}  {} ({}:{})",
            r.complexity, r.lines, r.name, r.file, r.line
        );
    }
    out
}
