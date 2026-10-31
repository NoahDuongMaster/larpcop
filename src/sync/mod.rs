//! `agentkit sync`: generates the committed, agent-facing files from the resolved rules.

mod agents;
mod agents_md;
mod hooks;

use crate::config::Config;
use crate::rules::RuleInfo;
use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// Line endings are normalized: with git `autocrlf` (Windows default) a checked-out
/// file has CRLF, which must not count as drift against the LF we generate.
fn read_opt(path: &Path) -> Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(s) => Ok(Some(s.replace("\r\n", "\n"))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

type Render = fn(Option<&str>) -> Result<String>;

/// Agent files: path relative to the root → how to update its current content.
const AGENT_FILES: [(&str, Render); 5] = [
    ("CLAUDE.md", |c| Ok(agents::claude_md(c))),
    (".claude/settings.json", agents::claude_settings),
    (".codex/hooks.json", agents::codex_hooks),
    (".gemini/settings.json", agents::gemini_settings),
    (".cursor/hooks.json", agents::cursor_hooks),
];

/// Desired content of every managed file. Existing content outside the managed
/// parts (other AGENTS.md sections, other settings and hooks) is preserved.
fn plan(cfg: &Config, rules: &[RuleInfo]) -> Result<Vec<(PathBuf, String)>> {
    let agents_path = cfg.root.join("AGENTS.md");
    let block = agents_md::render(cfg, rules);
    let mut out = vec![(
        agents_path.clone(),
        agents_md::upsert(read_opt(&agents_path)?.as_deref(), &block),
    )];
    for (rel, render) in AGENT_FILES {
        let path = cfg.root.join(rel);
        let content = render(read_opt(&path)?.as_deref())
            .with_context(|| format!("updating {}", path.display()))?;
        out.push((path, content));
    }
    Ok(out)
}

/// Returns the files that were (or, with `check_only`, would be) changed.
pub fn run(cfg: &Config, rules: &[RuleInfo], check_only: bool) -> Result<Vec<PathBuf>> {
    let mut changed = Vec::new();
    for (path, desired) in plan(cfg, rules)? {
        if read_opt(&path)?.as_deref() == Some(desired.as_str()) {
            continue;
        }
        if !check_only {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&path, &desired).with_context(|| format!("writing {}", path.display()))?;
        }
        changed.push(path.strip_prefix(&cfg.root).unwrap_or(&path).to_path_buf());
    }
    Ok(changed)
}
