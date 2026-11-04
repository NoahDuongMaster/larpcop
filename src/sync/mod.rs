//! `larpcop sync`: generates the committed, agent-facing files from the resolved rules.

mod agents;
mod agents_md;
mod hooks;
pub mod managed;

use crate::config::Config;
use crate::rules::RuleInfo;
use anyhow::{Context, Result, bail};
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

type Render = fn(Option<&str>, &str) -> Result<String>;

/// Agent id (as in `larpcop hook <id>` and the `agents:` config) → repo file → renderer.
pub const AGENT_FILES: [(&str, &str, Render); 11] = [
    ("claude-code", "CLAUDE.md", |c, _| Ok(agents::claude_md(c))),
    (
        "claude-code",
        ".claude/settings.json",
        agents::claude_settings,
    ),
    ("claude-code", ".mcp.json", agents::mcp_json),
    ("codex", ".codex/hooks.json", agents::codex_hooks),
    ("gemini", ".gemini/settings.json", agents::gemini_settings),
    ("cursor", ".cursor/hooks.json", agents::cursor_hooks),
    ("cursor", ".cursor/mcp.json", agents::mcp_json),
    (
        "copilot",
        ".github/hooks/larpcop.json",
        agents::copilot_hooks,
    ),
    ("droid", ".factory/hooks.json", agents::droid_hooks),
    ("kiro", ".kiro/hooks/larpcop.json", agents::kiro_hooks),
    ("kiro", ".kiro/settings/mcp.json", agents::mcp_json),
];

pub fn known_agent(id: &str) -> bool {
    AGENT_FILES.iter().any(|(a, ..)| *a == id)
}

/// Desired content of every managed file. Existing content outside the managed
/// parts (other AGENTS.md sections, other settings and hooks) is preserved.
/// A file to bring up to date: where, what it holds now, what it should hold.
type Planned = (PathBuf, Option<String>, String);

fn plan(cfg: &Config, rules: &[RuleInfo]) -> Result<Vec<Planned>> {
    if let Some(unknown) = cfg.agents.iter().flatten().find(|a| !known_agent(a)) {
        let ids: Vec<_> = AGENT_FILES.iter().map(|(a, ..)| *a).collect();
        bail!(
            "unknown agent `{unknown}` in `agents`; known: {}",
            ids.join(", ")
        );
    }
    let agents_path = cfg.root.join("AGENTS.md");
    let block = agents_md::render(cfg, rules);
    let current = read_opt(&agents_path)?;
    let desired = agents_md::upsert(current.as_deref(), &block);
    let mut out = vec![(agents_path, current, desired)];
    let wanted = |id: &str| {
        cfg.agents
            .as_ref()
            .is_none_or(|list| list.iter().any(|a| a == id))
    };
    for (agent, rel, render) in AGENT_FILES.iter().filter(|(a, ..)| wanted(a)) {
        let path = cfg.root.join(rel);
        let cmd = format!("larpcop hook {agent}");
        let current = read_opt(&path)?;
        let content = render(current.as_deref(), &cmd)
            .with_context(|| format!("updating {}", path.display()))?;
        out.push((path, current, content));
    }
    Ok(out)
}

/// Returns the files that were (or, with `check_only`, would be) changed.
pub fn run(cfg: &Config, rules: &[RuleInfo], check_only: bool) -> Result<Vec<PathBuf>> {
    let mut changed = Vec::new();
    for (path, current, desired) in plan(cfg, rules)? {
        if current.as_deref() == Some(desired.as_str()) {
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
