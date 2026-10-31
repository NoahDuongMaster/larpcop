//! Per-agent files: each agent gets its instruction file wired to AGENTS.md and
//! hooks that call `agentkit hook <agent>`. Event and tool names match each
//! agent's hook protocol (see `hook::event` for the payload side).

use super::hooks::{merge_flat, merge_grouped, parse, render};
use anyhow::Result;
use serde_json::{Value, json};

const TIMEOUT_SECS: u64 = 120;

/// Claude Code reads CLAUDE.md, not AGENTS.md; an import keeps one source of truth.
pub fn claude_md(current: Option<&str>) -> String {
    match current {
        None => "@AGENTS.md\n".to_string(),
        Some(c) if c.contains("@AGENTS.md") => c.to_string(),
        Some(c) => format!("{}\n\n@AGENTS.md\n", c.trim_end()),
    }
}

/// `.claude/settings.json`. PreToolUse guards bypasses, PostToolUse gives
/// per-edit feedback, Stop refuses to let the agent finish with violations.
pub fn claude_settings(current: Option<&str>) -> Result<String> {
    let mut doc = parse(current)?;
    let edit = "Edit|Write|MultiEdit|NotebookEdit";
    let events = [
        ("PreToolUse", Some("Bash|Edit|Write|MultiEdit|NotebookEdit")),
        ("PostToolUse", Some(edit)),
        ("Stop", None),
        ("SubagentStop", None),
    ];
    let handler = json!({ "type": "command", "command": "agentkit hook claude-code", "timeout": TIMEOUT_SECS });
    merge_grouped(&mut doc, &events, &handler)?;
    render(&doc)
}

/// `.codex/hooks.json`. Codex reads AGENTS.md natively; file edits arrive as
/// `apply_patch`. Each developer trusts the hooks once via `/hooks` (or the org
/// ships them as managed hooks through `requirements.toml`).
pub fn codex_hooks(current: Option<&str>) -> Result<String> {
    let mut doc = parse(current)?;
    let events = [
        ("PreToolUse", Some("^(Bash|apply_patch)$")),
        ("PostToolUse", Some("^apply_patch$")),
        ("Stop", None),
        ("SubagentStop", None),
    ];
    let handler = json!({
        "type": "command",
        "command": "agentkit hook codex",
        "timeout": TIMEOUT_SECS,
        "statusMessage": "agentkit: checking rules",
    });
    merge_grouped(&mut doc, &events, &handler)?;
    render(&doc)
}

/// `.gemini/settings.json`: hooks plus `context.fileName`, so Gemini CLI loads
/// AGENTS.md (its default is GEMINI.md). Gemini timeouts are in milliseconds.
pub fn gemini_settings(current: Option<&str>) -> Result<String> {
    let mut doc = parse(current)?;
    let events = [
        (
            "BeforeTool",
            Some("^(run_shell_command|write_file|replace)$"),
        ),
        ("AfterTool", Some("^(write_file|replace)$")),
        ("AfterAgent", None),
    ];
    let handler = json!({
        "type": "command",
        "name": "agentkit",
        "command": "agentkit hook gemini",
        "timeout": TIMEOUT_SECS * 1000,
    });
    merge_grouped(&mut doc, &events, &handler)?;
    let context = doc
        .as_object_mut()
        .expect("parse() guarantees an object")
        .entry("context")
        .or_insert_with(|| json!({}));
    if let Some(ctx) = context.as_object_mut() {
        let names = match ctx.remove("fileName") {
            Some(Value::Array(list)) => list,
            Some(Value::String(one)) => vec![json!(one)],
            _ => vec![json!("GEMINI.md")],
        };
        let mut names: Vec<Value> = names.into_iter().filter(|n| n != "AGENTS.md").collect();
        names.insert(0, json!("AGENTS.md"));
        ctx.insert("fileName".into(), Value::Array(names));
    }
    render(&doc)
}

/// `.cursor/hooks.json` in Cursor's native format. Cursor also imports
/// `.claude/settings.json`; the Claude adapter stands down inside Cursor.
/// `loop_limit: 1` mirrors the block-the-first-stop-only policy.
pub fn cursor_hooks(current: Option<&str>) -> Result<String> {
    let mut doc = parse(current)?;
    if let Some(obj) = doc.as_object_mut() {
        obj.entry("version").or_insert(json!(1));
    }
    let cmd = "agentkit hook cursor";
    let entries = [
        (
            "preToolUse",
            json!({ "command": cmd, "matcher": "Shell|Write|Delete", "timeout": TIMEOUT_SECS }),
        ),
        (
            "postToolUse",
            json!({ "command": cmd, "matcher": "Write", "timeout": TIMEOUT_SECS }),
        ),
        (
            "stop",
            json!({ "command": cmd, "timeout": TIMEOUT_SECS, "loop_limit": 1 }),
        ),
        (
            "subagentStop",
            json!({ "command": cmd, "timeout": TIMEOUT_SECS, "loop_limit": 1 }),
        ),
    ];
    merge_flat(&mut doc, &entries)?;
    render(&doc)
}
