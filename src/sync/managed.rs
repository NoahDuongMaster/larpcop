//! `agentkit sync --managed`: machine-wide hook policies for MDM / config
//! management. They force the company standards on every repository a developer
//! opens, configured or not, and users cannot switch them off.
//!
//! Locations, from each vendor's managed-configuration docs:
//! Claude Code `managed-settings.json`, Codex `requirements.toml`, Gemini CLI
//! system `settings.json`, Cursor enterprise `hooks.json`, Copilot CLI `policy.d`.
//! Kiro and Factory Droid have no machine-wide file (dashboard / per user).

use super::agents::{self, CODEX_EVENTS, TIMEOUT_SECS};
use anyhow::{Context, Result, bail};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Platform {
    Macos,
    Linux,
    Windows,
}

impl Platform {
    pub fn current() -> Self {
        match std::env::consts::OS {
            "macos" => Self::Macos,
            "windows" => Self::Windows,
            _ => Self::Linux,
        }
    }
}

/// `(agent, path relative to the filesystem root / system drive)`.
fn locations(p: Platform) -> [(&'static str, &'static str); 5] {
    match p {
        Platform::Macos => [
            (
                "claude-code",
                "Library/Application Support/ClaudeCode/managed-settings.json",
            ),
            ("codex", "etc/codex/requirements.toml"),
            (
                "gemini",
                "Library/Application Support/GeminiCli/settings.json",
            ),
            ("cursor", "Library/Application Support/Cursor/hooks.json"),
            ("copilot", "etc/github-copilot/policy.d/agentkit.json"),
        ],
        Platform::Linux => [
            ("claude-code", "etc/claude-code/managed-settings.json"),
            ("codex", "etc/codex/requirements.toml"),
            ("gemini", "etc/gemini-cli/settings.json"),
            ("cursor", "etc/cursor/hooks.json"),
            ("copilot", "etc/github-copilot/policy.d/agentkit.json"),
        ],
        Platform::Windows => [
            (
                "claude-code",
                "Program Files/ClaudeCode/managed-settings.json",
            ),
            ("codex", "ProgramData/OpenAI/Codex/requirements.toml"),
            ("gemini", "ProgramData/gemini-cli/settings.json"),
            ("cursor", "ProgramData/Cursor/hooks.json"),
            (
                "copilot",
                "ProgramData/GitHub/Copilot/policy.d/agentkit.json",
            ),
        ],
    }
}

pub struct Options<'a> {
    pub out: &'a Path,
    pub platform: Platform,
    /// Absolute path of the agentkit binary on managed machines.
    pub bin: &'a str,
    pub extends: &'a [String],
}

/// Writes the policy files under `out` (use `/` or `C:\` to install directly);
/// returns their paths.
pub fn write(opts: &Options) -> Result<Vec<PathBuf>> {
    if opts.extends.iter().all(|s| s.trim().is_empty()) {
        bail!("--managed needs the company standards: pass --extends <git URL#tag>");
    }
    if !Path::new(opts.bin).is_absolute() && !opts.bin.contains(":\\") {
        bail!("--bin must be absolute: managed hooks run with a minimal PATH");
    }
    let standards = opts.extends.join(",");
    let mut written = Vec::new();
    for (agent, rel) in locations(opts.platform) {
        let cmd = format!("\"{}\" hook {agent} --extends \"{standards}\"", opts.bin);
        let content = match agent {
            "claude-code" => agents::claude_settings(None, &cmd)?,
            "codex" => codex_requirements(&cmd, opts)?,
            "gemini" => agents::gemini_settings(None, &cmd)?,
            "cursor" => agents::cursor_hooks(None, &cmd)?,
            _ => agents::copilot_hooks(None, &cmd)?,
        };
        let path = opts.out.join(rel);
        fs::create_dir_all(path.parent().expect("nested path"))?;
        fs::write(&path, content).with_context(|| format!("writing {}", path.display()))?;
        written.push(path);
    }
    Ok(written)
}

/// Codex managed hooks must live under `managed_dir`; the binary's directory is it.
fn codex_requirements(cmd: &str, opts: &Options) -> Result<String> {
    let dir = Path::new(opts.bin)
        .parent()
        .map(|d| d.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut hooks = toml::Table::new();
    let key = if opts.platform == Platform::Windows {
        "windows_managed_dir"
    } else {
        "managed_dir"
    };
    hooks.insert(key.into(), dir.into());
    for (event, matcher) in CODEX_EVENTS {
        let mut handler = toml::Table::new();
        handler.insert("type".into(), "command".into());
        handler.insert("command".into(), cmd.into());
        handler.insert("timeout".into(), (TIMEOUT_SECS as i64).into());
        let mut group = toml::Table::new();
        if let Some(m) = matcher {
            group.insert("matcher".into(), m.into());
        }
        group.insert("hooks".into(), vec![toml::Value::Table(handler)].into());
        hooks.insert(event.into(), vec![toml::Value::Table(group)].into());
    }
    let mut features = toml::Table::new();
    features.insert("hooks".into(), true.into());
    let mut doc = toml::Table::new();
    doc.insert("features".into(), features.into());
    doc.insert("hooks".into(), hooks.into());
    Ok(format!(
        "# Generated by `agentkit sync --managed`.\n{}",
        toml::to_string(&doc)?
    ))
}
