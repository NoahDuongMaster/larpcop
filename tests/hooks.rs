mod common;

use common::{BAD_TS, GOOD_TS, Repo, hook_input};
use serde_json::json;

const HOOK: [&str; 2] = ["hook", "claude-code"];

#[test]
fn pre_tool_use_blocks_hook_bypass() {
    let repo = Repo::with_standards();
    let input = hook_input(
        "PreToolUse",
        "Bash",
        &repo.path(),
        json!({"command": "git commit --no-verify -m wip"}),
    );
    let run = repo.run_stdin(&HOOK, &input);
    assert_eq!(run.code(), 2);
    assert!(run.stderr().contains("--no-verify"), "{}", run.stderr());

    let ok = hook_input(
        "PreToolUse",
        "Bash",
        &repo.path(),
        json!({"command": "git commit -m 'add new'"}),
    );
    assert_eq!(repo.run_stdin(&HOOK, &ok).code(), 0);
}

#[test]
fn pre_tool_use_protects_config_and_rule_files() {
    let repo = Repo::with_standards();
    repo.write("team-rules/r.yml", "");
    repo.write(
        ".agentkit.yaml",
        &format!("{}rule_dirs: [team-rules]\n", repo.read(".agentkit.yaml")),
    );
    let root = repo.path();
    for (path, blocked) in [
        (root.join(".agentkit.yaml"), true),
        (root.join("team-rules/r.yml"), true),
        (root.join("team-rules/new.yml"), true),
        (root.join(".claude/settings.local.json"), true),
        (root.join("src/app.ts"), false),
    ] {
        let input = hook_input("PreToolUse", "Write", &root, json!({"file_path": path}));
        let run = repo.run_stdin(&HOOK, &input);
        assert_eq!(
            run.code() == 2,
            blocked,
            "{}: {}",
            path.display(),
            run.stderr()
        );
    }
}

#[test]
fn post_tool_use_feeds_violations_back() {
    let repo = Repo::with_standards();
    repo.write("src/a.ts", BAD_TS);
    let input = hook_input(
        "PostToolUse",
        "Write",
        &repo.path(),
        json!({"file_path": "src/a.ts"}),
    );
    let run = repo.run_stdin(&HOOK, &input);
    assert_eq!(run.code(), 2);
    assert!(run.stderr().contains("no-explicit-any") && run.stderr().contains("Fix them now"));

    repo.write("src/a.ts", GOOD_TS);
    assert_eq!(repo.run_stdin(&HOOK, &input).code(), 0);
}

#[test]
fn stop_refuses_to_finish_with_violations() {
    let repo = Repo::with_standards();
    repo.write("legacy.ts", BAD_TS);
    repo.commit_all("legacy"); // committed debt does not block the agent
    let input = hook_input("Stop", "", &repo.path(), json!({}));
    assert_eq!(repo.run_stdin(&HOOK, &input).code(), 0);

    repo.write("new.ts", BAD_TS);
    let run = repo.run_stdin(&HOOK, &input);
    assert_eq!(run.code(), 2);
    assert!(run.stderr().contains("cannot finish yet") && run.stderr().contains("new.ts"));
    assert!(!run.stderr().contains("legacy.ts"));

    // Second stop in the same cycle is let through (no infinite loop).
    let mut again: serde_json::Value = serde_json::from_str(&input).unwrap();
    again["stop_hook_active"] = json!(true);
    assert_eq!(repo.run_stdin(&HOOK, &again.to_string()).code(), 0);
}

#[test]
fn broken_config_does_not_block_the_agent() {
    let repo = Repo::new();
    repo.write(".agentkit.yaml", "extends: [./missing]\n");
    repo.write("a.ts", BAD_TS);
    let input = hook_input(
        "PostToolUse",
        "Write",
        &repo.path(),
        json!({"file_path": "a.ts"}),
    );
    let run = repo.run_stdin(&HOOK, &input);
    assert_eq!(run.code(), 3, "non-blocking error expected");
}
