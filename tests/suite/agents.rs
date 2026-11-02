//! Codex, Gemini CLI and Cursor adapters, driven with each agent's real payload shape.

use crate::common::{BAD_TS, GOOD_TS, Repo};
use serde_json::{Value, json};

fn payload(repo: &Repo, fields: Value) -> String {
    let mut base = json!({ "session_id": "t", "cwd": repo.path() });
    base.as_object_mut()
        .unwrap()
        .extend(fields.as_object().unwrap().clone());
    base.to_string()
}

/// Captured from `codex exec` 0.163: edits arrive as `apply_patch` with the patch in `command`.
fn codex_patch(event: &str, file: &str) -> Value {
    json!({
        "hook_event_name": event,
        "tool_name": "apply_patch",
        "tool_input": { "command": format!("*** Begin Patch\n*** Add File: {file}\n+x\n*** End Patch") },
    })
}

#[test]
fn codex_guards_feeds_back_and_blocks_stop_once() {
    let repo = Repo::with_standards();
    let hook = ["hook", "codex"];
    let bash = json!({ "hook_event_name": "PreToolUse", "tool_name": "Bash",
                       "tool_input": { "command": "git commit -n -m x" } });
    assert_eq!(repo.run_stdin(&hook, &payload(&repo, bash)).code(), 2);
    let cfg = codex_patch("PreToolUse", ".larpcop.yaml");
    assert_eq!(repo.run_stdin(&hook, &payload(&repo, cfg)).code(), 2);

    repo.write("src/a.ts", BAD_TS);
    let post = repo.run_stdin(
        &hook,
        &payload(&repo, codex_patch("PostToolUse", "src/a.ts")),
    );
    assert_eq!(post.code(), 2);
    assert!(
        post.stderr().contains("no-explicit-any"),
        "{}",
        post.stderr()
    );

    let stop = |active: bool| json!({ "hook_event_name": "Stop", "stop_hook_active": active, "last_assistant_message": "done" });
    assert_eq!(
        repo.run_stdin(&hook, &payload(&repo, stop(false))).code(),
        2
    );
    assert_eq!(repo.run_stdin(&hook, &payload(&repo, stop(true))).code(), 0);
    repo.write("src/a.ts", GOOD_TS);
    assert_eq!(
        repo.run_stdin(&hook, &payload(&repo, stop(false))).code(),
        0
    );
}

#[test]
fn gemini_uses_its_own_event_and_tool_names() {
    let repo = Repo::with_standards();
    let hook = ["hook", "gemini"];
    let shell = json!({ "hook_event_name": "BeforeTool", "tool_name": "run_shell_command",
                        "tool_input": { "command": "HUSKY=0 git commit -m x" } });
    assert_eq!(repo.run_stdin(&hook, &payload(&repo, shell)).code(), 2);

    repo.write("src/a.ts", BAD_TS);
    let write = json!({ "hook_event_name": "AfterTool", "tool_name": "write_file",
                        "tool_input": { "file_path": "src/a.ts", "content": BAD_TS } });
    let run = repo.run_stdin(&hook, &payload(&repo, write));
    assert_eq!(run.code(), 2);
    assert!(run.stderr().contains("no-console"));

    let after_agent = json!({ "hook_event_name": "AfterAgent", "prompt": "p", "prompt_response": "r",
                              "stop_hook_active": false });
    assert_eq!(
        repo.run_stdin(&hook, &payload(&repo, after_agent)).code(),
        2
    );
}

fn cursor(repo: &Repo, fields: Value) -> Value {
    let mut fields = fields;
    fields["cursor_version"] = json!("2026.10.22");
    fields["workspace_roots"] = json!([repo.path()]);
    let run = repo.run_stdin(&["hook", "cursor"], &payload(repo, fields));
    assert_eq!(
        run.code(),
        0,
        "Cursor hooks answer in JSON: {}",
        run.stderr()
    );
    serde_json::from_str(&run.stdout()).expect("valid JSON on stdout")
}

#[test]
fn cursor_answers_in_its_json_protocol() {
    let repo = Repo::with_standards();
    let shell = json!({ "hook_event_name": "preToolUse", "tool_name": "Shell",
                        "tool_input": { "command": "git commit --no-verify -m x", "cwd": "" } });
    let out = cursor(&repo, shell);
    assert_eq!(out["permission"], "deny");
    assert!(
        out["agent_message"]
            .as_str()
            .unwrap()
            .contains("--no-verify")
    );

    let ok = json!({ "hook_event_name": "preToolUse", "tool_name": "Write",
                     "tool_input": { "file_path": "src/a.ts", "content": "" } });
    assert_eq!(cursor(&repo, ok)["permission"], "allow");

    repo.write("src/a.ts", BAD_TS);
    let post = json!({ "hook_event_name": "postToolUse", "tool_name": "Write",
                       "tool_input": { "file_path": "src/a.ts" }, "tool_output": "{}" });
    assert!(
        cursor(&repo, post)["additional_context"]
            .as_str()
            .unwrap()
            .contains("no-explicit-any")
    );

    let stop = |status: &str, loops: u64| json!({ "hook_event_name": "stop", "status": status, "loop_count": loops });
    assert!(cursor(&repo, stop("completed", 0))["followup_message"].is_string());
    assert_eq!(cursor(&repo, stop("completed", 1)), json!({}));
    assert_eq!(
        cursor(&repo, stop("aborted", 0)),
        json!({}),
        "a user abort ends the turn"
    );
}

#[test]
fn claude_adapter_stands_down_inside_cursor() {
    let repo = Repo::with_standards();
    repo.write("src/a.ts", BAD_TS);
    let imported = json!({ "hook_event_name": "PostToolUse", "tool_name": "Write",
                           "tool_input": { "file_path": "src/a.ts" }, "cursor_version": "2026.10.22" });
    let run = repo.run_stdin(&["hook", "claude-code"], &payload(&repo, imported));
    assert_eq!(
        run.code(),
        0,
        "Cursor runs its native adapter; no double feedback"
    );
}

#[test]
fn sync_wires_every_agent() {
    let repo = Repo::with_standards();
    repo.write(
        ".gemini/settings.json",
        r#"{"context":{"fileName":"CONTEXT.md"},"ui":{"theme":"x"}}"#,
    );
    repo.write(
        ".cursor/hooks.json",
        r#"{"version":1,"hooks":{"stop":[{"command":"./mine.sh"}]}}"#,
    );
    assert_eq!(repo.run(&["sync"]).code(), 0);

    let read = |f: &str| -> Value { serde_json::from_str(&repo.read(f)).unwrap() };
    let codex = read(".codex/hooks.json");
    assert_eq!(
        codex["hooks"]["PreToolUse"][0]["matcher"],
        "^(Bash|apply_patch)$"
    );
    assert_eq!(
        codex["hooks"]["Stop"][0]["hooks"][0]["command"],
        "larpcop hook codex"
    );

    let gemini = read(".gemini/settings.json");
    assert_eq!(
        gemini["context"]["fileName"],
        json!(["AGENTS.md", "CONTEXT.md"])
    );
    assert_eq!(gemini["ui"]["theme"], "x", "user settings kept");
    assert_eq!(
        gemini["hooks"]["AfterAgent"][0]["hooks"][0]["timeout"],
        120_000
    );

    let cursor = read(".cursor/hooks.json");
    let stops = cursor["hooks"]["stop"].as_array().unwrap();
    assert_eq!(stops.len(), 2, "user hook kept: {stops:?}");
    assert_eq!(stops[1]["loop_limit"], 1);

    let again = repo.run(&["sync", "--check"]);
    assert_eq!(again.code(), 0, "idempotent: {}", again.stdout());
}
