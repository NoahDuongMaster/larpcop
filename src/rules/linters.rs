//! Delegation to stack-specific tools (eslint, ruff, golangci-lint, …).

use super::{RuleInfo, Violation};
use crate::config::LinterConfig;
use crate::files::{SourceFile, globset};
use anyhow::{Context, Result};
use globset::GlobSet;
use std::path::Path;
use std::process::Command;

const OUTPUT_TAIL_LINES: usize = 40;

pub struct Linter {
    cfg: LinterConfig,
    include: Option<GlobSet>,
}

impl Linter {
    pub fn new(cfg: &LinterConfig) -> Result<Self> {
        let include = (!cfg.include.is_empty())
            .then(|| globset(&cfg.include))
            .transpose()?;
        Ok(Self {
            cfg: cfg.clone(),
            include,
        })
    }

    /// Runs once over all matching files; a non-zero exit is one violation
    /// carrying the tool's own output so the agent sees exact locations.
    pub fn run(&self, root: &Path, files: &[SourceFile]) -> Result<Option<Violation>> {
        let matched: Vec<&str> = files
            .iter()
            .map(|f| f.rel.as_str())
            .filter(|rel| self.include.as_ref().is_none_or(|g| g.is_match(rel)))
            .collect();
        if matched.is_empty() {
            return Ok(None);
        }
        let quoted: Vec<String> = matched.iter().map(|r| shell_quote(r)).collect();
        let cmd = self.cfg.run.replace("{files}", &quoted.join(" "));
        let shell = crate::shell::posix_shell();
        let out = Command::new(&shell)
            .arg("-c")
            .arg(&cmd)
            .current_dir(root)
            .output()
            .with_context(|| {
                format!(
                    "running linter `{}` with {} (install Git, or set AGENTKIT_SHELL to a POSIX sh)",
                    self.cfg.id,
                    shell.display()
                )
            })?;
        if out.status.success() {
            return Ok(None);
        }
        let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
        text.push_str(&String::from_utf8_lossy(&out.stderr));
        let code = out
            .status
            .code()
            .map_or("signal".to_string(), |c| c.to_string());
        Ok(Some(Violation {
            rule: self.cfg.id.clone(),
            level: self.cfg.level,
            file: String::new(),
            line: 0,
            column: 0,
            message: format!(
                "`{}` failed (exit {code}) on {} file(s).",
                self.cfg.run,
                matched.len()
            ),
            note: Some(tail(&text, OUTPUT_TAIL_LINES)),
            snippet: None,
        }))
    }

    pub fn info(&self) -> RuleInfo {
        RuleInfo {
            id: self.cfg.id.clone(),
            level: self.cfg.level,
            scope: if self.cfg.include.is_empty() {
                "all files".into()
            } else {
                self.cfg.include.join(", ")
            },
            message: format!("`{}` must pass.", self.cfg.run),
            note: None,
        }
    }
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

fn tail(text: &str, n: usize) -> String {
    let lines: Vec<&str> = text.trim_end().lines().collect();
    lines[lines.len().saturating_sub(n)..].join("\n")
}
