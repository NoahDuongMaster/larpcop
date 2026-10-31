//! Adapters added for Kiro, Copilot CLI and Factory Droid, the `agents:` filter
//! and `sync --managed`. Kiro payloads are the ones recorded from kiro-cli 2.37 `--v3`.

mod common;

use common::*;
use serde_json::{Value, json};

fn kiro(event: &str, tool: &str, dir: &std::path::Path, input: Value) -> String {
    json!({ "hook_event_name": event, "cwd": dir, "session_id": "kiro-s1",
            "tool_name": tool, "tool_input": input })
    .to_string()
}

#[test]
fn kiro_checks_writes_before_they_land_and_continues_once_on_stop() {
    let repo = Repo::with_standards();
    repo.write("src/ok.ts", GOOD_TS);
    repo.commit_all("base");
    let dir = repo.path();
    let file = dir.join("src/new.ts");

    // fs_write with violations: blocked, nothing written.
    let input = kiro(
        "PreToolUse",
        "fs_write",
        &dir,
        json!({ "path": file, "text": BAD_TS }),
    );
    let out = repo.run_stdin(&["hook", "kiro"], &input);
    assert_eq!(out.code(), 2, "{}", out.stdout());
    assert!(
        out.stderr().contains("this write was not applied")
            && out.stderr().contains("no-explicit-any")
    );

    // A partial fix of an already-broken file goes through.
    repo.write(
        "src/broken.ts",
        "export const d = (x: any) => console.log(x);\n",
    );
    let fix =
        json!({ "path": dir.join("src/broken.ts"), "oldStr": "x: any", "newStr": "x: unknown" });
    let out = repo.run_stdin(
        &["hook", "kiro"],
        &kiro("PreToolUse", "str_replace", &dir, fix),
    );
    assert_eq!(out.code(), 0, "{}", out.stderr());

    let bypass = kiro(
        "PreToolUse",
        "execute_bash",
        &dir,
        json!({ "command": "git commit --no-verify -am x" }),
    );
    assert_eq!(repo.run_stdin(&["hook", "kiro"], &bypass).code(), 2);

    // Stop: continue once with the report as JSON, then let the agent stop.
    let stop =
        json!({ "hook_event_name": "Stop", "cwd": dir, "session_id": "kiro-s1" }).to_string();
    let first = repo.run_stdin(&["hook", "kiro"], &stop);
    assert_eq!(first.code(), 0);
    let verdict: Value = serde_json::from_str(&first.stdout()).unwrap();
    assert_eq!(verdict["decision"], "block");
    assert!(
        verdict["reason"]
            .as_str()
            .unwrap()
            .contains("src/broken.ts")
    );
    let second = repo.run_stdin(&["hook", "kiro"], &stop);
    assert_eq!((second.code(), second.stdout().trim()), (0, ""));
}

#[test]
fn copilot_answers_in_json_and_droid_by_exit_code() {
    let repo = Repo::with_standards();
    repo.commit_all("base");
    let dir = repo.path();
    let deny = repo.run_stdin(
        &["hook", "copilot"],
        &hook_input(
            "PreToolUse",
            "Bash",
            &dir,
            json!({ "command": "git commit -n -m x" }),
        ),
    );
    assert_eq!(deny.code(), 0);
    let v: Value = serde_json::from_str(&deny.stdout()).unwrap();
    assert_eq!(v["permissionDecision"], "deny");

    // Copilot keeps its own argument names (`path`) under Claude tool names.
    repo.write("src/bad.ts", BAD_TS);
    let post = hook_input("PostToolUse", "Edit", &dir, json!({ "path": "src/bad.ts" }));
    let v: Value =
        serde_json::from_str(&repo.run_stdin(&["hook", "copilot"], &post).stdout()).unwrap();
    assert!(
        v["additionalContext"]
            .as_str()
            .unwrap()
            .contains("no-console")
    );

    let droid = hook_input(
        "PreToolUse",
        "Execute",
        &dir,
        json!({ "command": "HUSKY=0 git commit -m x" }),
    );
    assert_eq!(repo.run_stdin(&["hook", "droid"], &droid).code(), 2);
    let created = hook_input(
        "PostToolUse",
        "Create",
        &dir,
        json!({ "file_path": dir.join("src/bad.ts") }),
    );
    let out = repo.run_stdin(&["hook", "droid"], &created);
    assert_eq!(out.code(), 2);
    assert!(out.stderr().contains("no-explicit-any"));
}

#[test]
fn sync_generates_files_only_for_the_chosen_agents() {
    let repo = Repo::with_standards();
    assert_eq!(repo.run(&["sync"]).code(), 0);
    for f in [
        ".github/hooks/larpcop.json",
        ".factory/hooks.json",
        ".kiro/hooks/larpcop.json",
    ] {
        assert!(repo.path().join(f).is_file(), "{f}");
    }
    let kiro: Value = serde_json::from_str(&repo.read(".kiro/hooks/larpcop.json")).unwrap();
    assert_eq!(kiro["hooks"][0]["action"]["command"], "larpcop hook kiro");

    let only = Repo::new();
    only.write(
        ".larpcop.yaml",
        &format!("{}agents: [kiro, codex]\n", extends_yaml(STANDARDS)),
    );
    assert_eq!(only.run(&["sync"]).code(), 0);
    assert!(only.path().join(".codex/hooks.json").is_file());
    assert!(!only.path().join(".claude/settings.json").exists());

    only.write(".larpcop.yaml", "agents: [vscode]\n");
    let bad = only.run(&["sync"]);
    assert_eq!(bad.code(), 3);
    assert!(bad.stderr().contains("unknown agent `vscode`"));
}

#[test]
fn managed_policies_force_the_standards_with_an_absolute_binary() {
    let repo = Repo::new();
    let out = repo.path().join("pkg");
    let url = "https://github.com/acme/standards.git#v2.0.0";
    let run = repo.run(&[
        "sync",
        "--managed",
        "--out",
        out.to_str().unwrap(),
        "--platform",
        "linux",
        "--bin",
        "/opt/larpcop/bin/larpcop",
        "--extends",
        url,
    ]);
    assert_eq!(run.code(), 0, "{}", run.stderr());
    let cmd = format!("\"/opt/larpcop/bin/larpcop\" hook claude-code --extends \"{url}\"");
    let claude: Value = serde_json::from_str(
        &std::fs::read_to_string(out.join("etc/claude-code/managed-settings.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(claude["hooks"]["PreToolUse"][0]["hooks"][0]["command"], cmd);
    let codex: toml::Table = std::fs::read_to_string(out.join("etc/codex/requirements.toml"))
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(codex["features"]["hooks"].as_bool(), Some(true));
    assert_eq!(
        codex["hooks"]["managed_dir"].as_str(),
        Some("/opt/larpcop/bin")
    );
    assert!(
        codex["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
            .as_str()
            .unwrap()
            .contains("hook codex")
    );
    for f in [
        "etc/gemini-cli/settings.json",
        "etc/cursor/hooks.json",
        "etc/github-copilot/policy.d/larpcop.json",
    ] {
        assert!(out.join(f).is_file(), "{f}");
    }

    let no_standards = repo.run(&["sync", "--managed", "--out", out.to_str().unwrap()]);
    assert_eq!(no_standards.code(), 3);
}

#[test]
fn files_written_through_the_shell_are_checked_before_the_command_runs() {
    let repo = Repo::with_standards();
    repo.write("src/ok.ts", GOOD_TS);
    repo.commit_all("base");
    let dir = repo.path();
    let bash = |cmd: &str| {
        let input = hook_input("PreToolUse", "Bash", &dir, json!({ "command": cmd }));
        repo.run_stdin(&["hook", "claude-code"], &input)
    };
    // A heredoc dodges Write/Edit hooks; its content is checked all the same.
    let run = bash("cd src && cat > new.ts <<'EOF'\nconsole.log(1);\nEOF\n");
    assert_eq!(run.code(), 2, "{}", run.stdout());
    assert!(
        run.stderr().contains("no-console") && run.stderr().contains("src/new.ts"),
        "{}",
        run.stderr()
    );
    assert!(!dir.join("src/new.ts").exists());
    // Appending is judged on the whole resulting file; clean content passes.
    assert_eq!(bash("echo 'console.log(2);' >> src/ok.ts").code(), 2);
    assert_eq!(
        bash("cat > src/clean.ts <<'EOF'\nexport const a = 1;\nEOF\n").code(),
        0
    );
    assert_eq!(bash("npm test > log.txt").code(), 0);
}
