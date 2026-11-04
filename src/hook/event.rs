//! Normalizes each agent's hook payload into one agent-independent event.
//! Payload shapes verified against real runs (Codex 0.163, Claude Code) or the
//! agent's own source/docs (Cursor CLI 2026.10, Gemini CLI hooks reference).

use super::Agent;
use serde_json::Value;
use std::path::{Path, PathBuf};

pub enum Event {
    /// About to run a shell command.
    Shell(String),
    /// A shell command finished; the uncommitted files before it ran (if recorded).
    AfterShell(Option<super::shell_run::Snapshot>),
    /// About to create, modify or delete these files.
    BeforeEdit(Vec<PathBuf>),
    /// About to write this content to this file (agents without post-edit
    /// feedback get it checked before it is written).
    Proposed(PathBuf, String),
    /// These files were just written.
    AfterEdit(Vec<PathBuf>),
    /// The agent wants to end its turn; `continued` = it was already sent back once.
    Stop {
        continued: bool,
    },
    Ignore,
}

fn str_field<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

fn file_path(input: &Value, cwd: &Path) -> Vec<PathBuf> {
    let tool_input = input.get("tool_input").unwrap_or(&Value::Null);
    // `path`: Copilot CLI maps its tools to Claude names but keeps their own arguments.
    ["file_path", "notebook_path", "path"]
        .iter()
        .map(|k| str_field(tool_input, k))
        .find(|p| !p.is_empty())
        .map(|p| vec![cwd.join(p)])
        .unwrap_or_default()
}

fn command(input: &Value) -> String {
    str_field(input.get("tool_input").unwrap_or(&Value::Null), "command").to_string()
}

pub fn parse(agent: Agent, input: &Value, cwd: &Path) -> Event {
    let event = str_field(input, "hook_event_name");
    let tool = str_field(input, "tool_name");
    let stop_active = input
        .get("stop_hook_active")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    match agent {
        // Cursor also runs `.claude/settings.json` hooks (third-party import); its
        // native adapter handles the session, so the Claude one stands down.
        Agent::ClaudeCode if input.get("cursor_version").is_some() => Event::Ignore,
        Agent::ClaudeCode | Agent::Copilot => match (event, tool) {
            ("PreToolUse", "Bash") => Event::Shell(command(input)),
            ("PostToolUse", "Bash") => Event::AfterShell(None),
            ("PreToolUse", t) if is_claude_edit(t) => Event::BeforeEdit(file_path(input, cwd)),
            ("PostToolUse", t) if is_claude_edit(t) => Event::AfterEdit(file_path(input, cwd)),
            ("Stop" | "SubagentStop" | "agentStop" | "subagentStop", _) => Event::Stop {
                continued: stop_active,
            },
            _ => Event::Ignore,
        },
        // Factory Droid speaks Claude Code's protocol with its own tool names.
        Agent::Droid => match (event, tool) {
            ("PreToolUse", "Execute") => Event::Shell(command(input)),
            ("PostToolUse", "Execute") => Event::AfterShell(None),
            ("PreToolUse", "Create" | "Edit") => Event::BeforeEdit(file_path(input, cwd)),
            ("PostToolUse", "Create" | "Edit") => Event::AfterEdit(file_path(input, cwd)),
            ("PreToolUse", "ApplyPatch") => Event::BeforeEdit(patch_paths(&patch(input), cwd)),
            ("PostToolUse", "ApplyPatch") => Event::AfterEdit(patch_paths(&patch(input), cwd)),
            ("Stop" | "SubagentStop", _) => Event::Stop {
                continued: stop_active,
            },
            _ => Event::Ignore,
        },
        // Kiro CLI V3 (payloads recorded from kiro-cli 2.37 `--v3`). Its PostToolUse
        // output never reaches the model, so writes are checked before they land.
        Agent::Kiro => match (event, tool) {
            ("PreToolUse", "execute_bash" | "execute_pwsh") => Event::Shell(command(input)),
            ("PreToolUse", t) if is_kiro_write(t) => kiro_proposed(input, cwd),
            ("Stop", _) => Event::Stop { continued: false },
            _ => Event::Ignore,
        },
        Agent::Codex => match (event, tool) {
            ("PreToolUse", "Bash") => Event::Shell(command(input)),
            ("PostToolUse", "Bash") => Event::AfterShell(None),
            ("PreToolUse", "apply_patch") => Event::BeforeEdit(patch_paths(&command(input), cwd)),
            ("PostToolUse", "apply_patch") => Event::AfterEdit(patch_paths(&command(input), cwd)),
            ("Stop" | "SubagentStop", _) => Event::Stop {
                continued: stop_active,
            },
            _ => Event::Ignore,
        },
        Agent::Gemini => match (event, tool) {
            ("BeforeTool", "run_shell_command") => Event::Shell(command(input)),
            ("AfterTool", "run_shell_command") => Event::AfterShell(None),
            ("BeforeTool", "write_file" | "replace") => Event::BeforeEdit(file_path(input, cwd)),
            ("AfterTool", "write_file" | "replace") => Event::AfterEdit(file_path(input, cwd)),
            ("AfterAgent", _) => Event::Stop {
                continued: stop_active,
            },
            _ => Event::Ignore,
        },
        Agent::Cursor => match (event, tool) {
            ("preToolUse", "Shell") => Event::Shell(command(input)),
            ("postToolUse", "Shell") => Event::AfterShell(None),
            ("preToolUse", "Write" | "Delete") => Event::BeforeEdit(file_path(input, cwd)),
            ("postToolUse", "Write") => Event::AfterEdit(file_path(input, cwd)),
            // A user abort must end the turn at once, never be turned into a follow-up.
            ("stop" | "subagentStop", _) if str_field(input, "status") != "completed" => {
                Event::Ignore
            }
            ("stop" | "subagentStop", _) => Event::Stop {
                continued: input.get("loop_count").and_then(Value::as_u64).unwrap_or(0) > 0,
            },
            _ => Event::Ignore,
        },
    }
}

fn is_claude_edit(tool: &str) -> bool {
    matches!(tool, "Edit" | "Write" | "MultiEdit" | "NotebookEdit")
}

fn patch(input: &Value) -> String {
    let tool_input = input.get("tool_input").unwrap_or(&Value::Null);
    match tool_input {
        Value::String(s) => s.clone(),
        v => ["patch", "input", "command"]
            .iter()
            .map(|k| str_field(v, k))
            .find(|s| !s.is_empty())
            .unwrap_or("")
            .to_string(),
    }
}

fn is_kiro_write(tool: &str) -> bool {
    matches!(
        tool,
        "fs_write" | "fs_append" | "str_replace" | "write_file" | "delete_file"
    )
}

/// The file content a Kiro write would produce; unknown shapes only get the
/// protected-path check. Accepts V3 (`text`, `oldStr`) and V2 (`file_text`, `old_str`) fields.
fn kiro_proposed(input: &Value, cwd: &Path) -> Event {
    let ti = input.get("tool_input").unwrap_or(&Value::Null);
    let field = |keys: &[&str]| -> String {
        keys.iter()
            .map(|k| str_field(ti, k))
            .find(|s| !s.is_empty())
            .unwrap_or("")
            .to_string()
    };
    let rel = field(&["path", "file_path"]);
    if rel.is_empty() {
        return Event::Ignore;
    }
    let path = cwd.join(rel);
    // A file that is not there yet is empty; one that cannot be read is not judged
    // by the part of it we would see.
    let current = || match std::fs::read_to_string(&path) {
        Ok(text) => Some(text),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Some(String::new()),
        Err(e) => {
            eprintln!(
                "larpcop: warning: cannot read {} to check this write: {e}",
                path.display()
            );
            None
        }
    };
    let (old, new) = (field(&["oldStr", "old_str"]), field(&["newStr", "new_str"]));
    let all = ti
        .get("replace_all")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let content = match (str_field(input, "tool_name"), str_field(ti, "command")) {
        ("fs_write" | "write_file", "" | "create") => {
            Some(field(&["text", "file_text", "content"]))
        }
        ("fs_append", _) | (_, "append") => current().map(|cur| cur + &field(&["text", "new_str"])),
        ("str_replace", _) | (_, "str_replace") if !old.is_empty() => current().and_then(|cur| {
            cur.contains(&old).then(|| match all {
                true => cur.replace(&old, &new),
                false => cur.replacen(&old, &new, 1),
            })
        }),
        _ => None,
    };
    match content {
        Some(c) => Event::Proposed(path, c),
        None => Event::BeforeEdit(vec![path]),
    }
}

/// Files named in a Codex `apply_patch` body (`*** Add/Update/Delete File:` and
/// `*** Move to:` headers). Paths may be absolute or relative to the session cwd.
pub fn patch_paths(patch: &str, cwd: &Path) -> Vec<PathBuf> {
    const HEADERS: [&str; 4] = [
        "*** Add File: ",
        "*** Update File: ",
        "*** Delete File: ",
        "*** Move to: ",
    ];
    patch
        .lines()
        .filter_map(|line| HEADERS.iter().find_map(|h| line.strip_prefix(h)))
        .map(|p| cwd.join(p.trim()))
        .collect()
}

/// Working directory of the session: payload `cwd`, else the agent's project env.
pub fn session_dir(input: &Value) -> Option<PathBuf> {
    let from_input = Some(str_field(input, "cwd"))
        .filter(|s| !s.is_empty())
        .map(PathBuf::from);
    let from_roots = input
        .get("workspace_roots")
        .and_then(|r| r.get(0))
        .and_then(Value::as_str)
        .map(PathBuf::from);
    let env_dirs = [
        "CLAUDE_PROJECT_DIR",
        "CURSOR_PROJECT_DIR",
        "GEMINI_PROJECT_DIR",
    ];
    let from_env = env_dirs
        .iter()
        .find_map(std::env::var_os)
        .map(PathBuf::from);
    from_input.or(from_roots).or(from_env)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codex_patch_paths_cover_every_header() {
        let patch = "*** Begin Patch\n*** Add File: src/new.ts\n+x\n*** Update File: /abs/old.ts\n\
*** Move to: src/renamed.ts\n@@\n-a\n+b\n*** Delete File: gone.ts\n*** End Patch";
        let paths = patch_paths(patch, Path::new("/repo"));
        let expected = [
            "/repo/src/new.ts",
            "/abs/old.ts",
            "/repo/src/renamed.ts",
            "/repo/gone.ts",
        ];
        assert_eq!(
            paths,
            expected.iter().map(PathBuf::from).collect::<Vec<_>>()
        );
    }
}
