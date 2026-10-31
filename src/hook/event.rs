//! Normalizes each agent's hook payload into one agent-independent event.
//! Payload shapes verified against real runs (Codex 0.163, Claude Code) or the
//! agent's own source/docs (Cursor CLI 2026.10, Gemini CLI hooks reference).

use super::Agent;
use serde_json::Value;
use std::path::{Path, PathBuf};

pub enum Event {
    /// About to run a shell command.
    Shell(String),
    /// About to create, modify or delete these files.
    BeforeEdit(Vec<PathBuf>),
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
    ["file_path", "notebook_path"]
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
        Agent::ClaudeCode => match (event, tool) {
            ("PreToolUse", "Bash") => Event::Shell(command(input)),
            ("PreToolUse", t) if is_claude_edit(t) => Event::BeforeEdit(file_path(input, cwd)),
            ("PostToolUse", t) if is_claude_edit(t) => Event::AfterEdit(file_path(input, cwd)),
            ("Stop" | "SubagentStop", _) => Event::Stop {
                continued: stop_active,
            },
            _ => Event::Ignore,
        },
        Agent::Codex => match (event, tool) {
            ("PreToolUse", "Bash") => Event::Shell(command(input)),
            ("PreToolUse", "apply_patch") => Event::BeforeEdit(patch_paths(&command(input), cwd)),
            ("PostToolUse", "apply_patch") => Event::AfterEdit(patch_paths(&command(input), cwd)),
            ("Stop" | "SubagentStop", _) => Event::Stop {
                continued: stop_active,
            },
            _ => Event::Ignore,
        },
        Agent::Gemini => match (event, tool) {
            ("BeforeTool", "run_shell_command") => Event::Shell(command(input)),
            ("BeforeTool", "write_file" | "replace") => Event::BeforeEdit(file_path(input, cwd)),
            ("AfterTool", "write_file" | "replace") => Event::AfterEdit(file_path(input, cwd)),
            ("AfterAgent", _) => Event::Stop {
                continued: stop_active,
            },
            _ => Event::Ignore,
        },
        Agent::Cursor => match (event, tool) {
            ("preToolUse", "Shell") => Event::Shell(command(input)),
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
