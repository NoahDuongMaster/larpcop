//! Per-agent files: each agent gets its instruction file wired to AGENTS.md and
//! hooks that call `larpcop hook <agent>`. Event and tool names match each
//! agent's hook protocol (see `hook::event` for the payload side).
//!
//! Renderers take the hook command so `sync --managed` can reuse them with an
//! absolute binary path and forced standards.

use super::hooks::{merge_flat, merge_grouped, parse, render};
use anyhow::{Context, Result};
use serde_json::{Value, json};

pub const TIMEOUT_SECS: u64 = 120;

/// Claude Code reads CLAUDE.md, not AGENTS.md; an import keeps one source of truth.
pub fn claude_md(current: Option<&str>) -> String {
    match current {
        None => "@AGENTS.md\n".to_string(),
        Some(c) if c.contains("@AGENTS.md") => c.to_string(),
        Some(c) => format!("{}\n\n@AGENTS.md\n", c.trim_end()),
    }
}

/// `.mcp.json`-style registration of `larpcop mcp` (Claude Code, Cursor, Kiro).
pub fn mcp_json(current: Option<&str>, _cmd: &str) -> Result<String> {
    let mut doc = parse(current)?;
    let servers = doc
        .as_object_mut()
        .expect("parse() guarantees an object")
        .entry("mcpServers")
        .or_insert_with(|| json!({}));
    anyhow::ensure!(servers.is_object(), "`mcpServers` must be an object");
    servers["larpcop"] = json!({ "command": "larpcop", "args": ["mcp"] });
    render(&doc)
}

/// `.claude/settings.json`. PreToolUse guards bypasses, PostToolUse gives
/// feedback after each edit or shell command, Stop refuses to let the agent
/// finish with violations.
pub fn claude_settings(current: Option<&str>, cmd: &str) -> Result<String> {
    let mut doc = parse(current)?;
    let edit = "Edit|Write|MultiEdit|NotebookEdit";
    let events = [
        ("PreToolUse", Some("Bash|Edit|Write|MultiEdit|NotebookEdit")),
        ("PostToolUse", Some(&format!("Bash|{edit}"))),
        ("Stop", None),
        ("SubagentStop", None),
    ];
    let handler = json!({ "type": "command", "command": cmd, "timeout": TIMEOUT_SECS });
    merge_grouped(&mut doc, &events, &handler)?;
    render(&doc)
}

/// `.codex/hooks.json`. Codex reads AGENTS.md natively; file edits arrive as
/// `apply_patch`. Each developer trusts the hooks once via `/hooks` (or the org
/// ships them as managed hooks through `requirements.toml`).
pub fn codex_hooks(current: Option<&str>, cmd: &str) -> Result<String> {
    let mut doc = parse(current)?;
    let handler = json!({
        "type": "command",
        "command": cmd,
        "timeout": TIMEOUT_SECS,
        "statusMessage": "larpcop: checking rules",
    });
    merge_grouped(&mut doc, &CODEX_EVENTS, &handler)?;
    render(&doc)
}

pub const CODEX_EVENTS: [(&str, Option<&str>); 4] = [
    ("PreToolUse", Some("^(Bash|apply_patch)$")),
    ("PostToolUse", Some("^(Bash|apply_patch)$")),
    ("Stop", None),
    ("SubagentStop", None),
];

/// `.gemini/settings.json`: hooks plus `context.fileName`, so Gemini CLI loads
/// AGENTS.md (its default is GEMINI.md). Gemini timeouts are in milliseconds.
pub fn gemini_settings(current: Option<&str>, cmd: &str) -> Result<String> {
    let mut doc = parse(current)?;
    let events = [
        (
            "BeforeTool",
            Some("^(run_shell_command|write_file|replace)$"),
        ),
        (
            "AfterTool",
            Some("^(run_shell_command|write_file|replace)$"),
        ),
        ("AfterAgent", None),
    ];
    let handler = json!({
        "type": "command",
        "name": "larpcop",
        "command": cmd,
        "timeout": TIMEOUT_SECS * 1000,
    });
    merge_grouped(&mut doc, &events, &handler)?;
    let obj = doc.as_object_mut().expect("parse() guarantees an object");
    let servers = obj.entry("mcpServers").or_insert_with(|| json!({}));
    anyhow::ensure!(servers.is_object(), "`mcpServers` must be an object");
    servers["larpcop"] = json!({ "command": "larpcop", "args": ["mcp"] });
    let context = obj.entry("context").or_insert_with(|| json!({}));
    let ctx = context
        .as_object_mut()
        .context("`context` must be an object")?;
    let names = match ctx.remove("fileName") {
        Some(Value::Array(list)) => list,
        Some(Value::String(one)) => vec![json!(one)],
        _ => vec![json!("GEMINI.md")],
    };
    let mut names: Vec<Value> = names.into_iter().filter(|n| n != "AGENTS.md").collect();
    names.insert(0, json!("AGENTS.md"));
    ctx.insert("fileName".into(), Value::Array(names));
    render(&doc)
}

/// `.cursor/hooks.json` in Cursor's native format. Cursor also imports
/// `.claude/settings.json`; the Claude adapter stands down inside Cursor.
/// `loop_limit: 1` mirrors the block-the-first-stop-only policy.
pub fn cursor_hooks(current: Option<&str>, cmd: &str) -> Result<String> {
    let mut doc = parse(current)?;
    if let Some(obj) = doc.as_object_mut() {
        obj.entry("version").or_insert(json!(1));
    }
    let stop = json!({ "command": cmd, "timeout": TIMEOUT_SECS, "loop_limit": 1 });
    let entries = [
        (
            "preToolUse",
            json!({ "command": cmd, "matcher": "Shell|Write|Delete", "timeout": TIMEOUT_SECS }),
        ),
        (
            "postToolUse",
            json!({ "command": cmd, "matcher": "Shell|Write", "timeout": TIMEOUT_SECS }),
        ),
        ("stop", stop.clone()),
        ("subagentStop", stop),
    ];
    merge_flat(&mut doc, &entries)?;
    render(&doc)
}

/// `.github/hooks/larpcop.json` for Copilot CLI (and the Copilot cloud agent).
/// PascalCase events get Claude-format payloads; verdicts are JSON on stdout.
pub fn copilot_hooks(_current: Option<&str>, cmd: &str) -> Result<String> {
    let entry = |matcher: Option<&str>| {
        let mut e = json!({ "type": "command", "bash": cmd, "powershell": cmd, "timeoutSec": TIMEOUT_SECS });
        if let Some(m) = matcher {
            e["matcher"] = json!(m);
        }
        json!([e])
    };
    let doc = json!({
        "version": 1,
        "hooks": {
            "PreToolUse": entry(Some("Bash|Edit|Write")),
            "PostToolUse": entry(Some("Bash|Edit|Write")),
            "Stop": entry(None),
        }
    });
    render(&doc)
}

/// `.factory/hooks.json`: Factory Droid's standalone file is keyed by event at
/// the top level, with Claude Code's grouped shape underneath.
pub fn droid_hooks(current: Option<&str>, cmd: &str) -> Result<String> {
    let mut wrapper = json!({ "hooks": parse(current)? });
    let events = [
        ("PreToolUse", Some("Execute|Create|Edit|ApplyPatch")),
        ("PostToolUse", Some("Execute|Create|Edit|ApplyPatch")),
        ("Stop", None),
        ("SubagentStop", None),
    ];
    let handler = json!({ "type": "command", "command": cmd, "timeout": TIMEOUT_SECS });
    merge_grouped(&mut wrapper, &events, &handler)?;
    render(&wrapper["hooks"])
}

/// `.kiro/hooks/larpcop.json` (Kiro IDE 1.0 / CLI V3 standalone hook file).
pub fn kiro_hooks(_current: Option<&str>, cmd: &str) -> Result<String> {
    let hook = |name: &str, trigger: &str, matcher: Option<&str>| {
        let mut h = json!({
            "name": name,
            "trigger": trigger,
            "action": { "type": "command", "command": cmd },
            "timeout": TIMEOUT_SECS,
        });
        if let Some(m) = matcher {
            h["matcher"] = json!(m);
        }
        h
    };
    let doc = json!({
        "version": "v1",
        "hooks": [
            hook("larpcop-shell", "PreToolUse", Some("shell")),
            hook("larpcop-write", "PreToolUse", Some("write")),
            hook("larpcop-stop", "Stop", None),
        ]
    });
    render(&doc)
}
