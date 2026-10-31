mod common;

use common::deps::{APPROVAL, repo};
use common::{extends_yaml, hook_input};
use serde_json::json;

#[test]
fn new_direct_dependencies_need_approval() {
    let repo = repo(APPROVAL);
    repo.write("package.json", r#"{"dependencies": {"lodash": "^4"}}"#);
    repo.write(
        "Cargo.toml",
        "[package]\nname = \"t\"\n\n[dependencies]\nanyhow = \"1\"\n",
    );
    repo.commit_all("base");

    repo.write(
        "package.json",
        r#"{"dependencies": {"lodash": "^4", "left-pad": "^1"}}"#,
    );
    // A new workspace package reusing lodash adds only zod.
    repo.write(
        "packages/web/package.json",
        r#"{"dependencies": {"lodash": "^4", "zod": "^3"}}"#,
    );
    repo.write(
        "Cargo.toml",
        "[package]\nname = \"t\"\n\n[dependencies]\nanyhow = \"1\"\nserde = \"1\"\n",
    );
    let run = repo.run(&["check", "--changed"]);
    let out = run.stdout();
    assert_eq!(run.code(), 1, "{out}");
    for dep in ["`left-pad` (npm)", "`zod` (npm)", "`serde` (cargo)"] {
        assert!(
            out.contains(&format!("New dependency {dep} has not been approved")),
            "{out}"
        );
    }
    assert!(!out.contains("lodash") && !out.contains("anyhow"), "{out}");
    assert!(
        out.contains("add `npm:zod` to `dependencies.approved`"),
        "{out}"
    );

    repo.write(
        ".larpcop.yaml",
        &format!("{APPROVAL}  approved: [left-pad, 'npm:zod', 'cargo:serde']\n"),
    );
    let run = repo.run(&["check", "--changed"]);
    assert_eq!(run.code(), 0, "{}", run.stdout());
}

#[test]
fn hook_stops_unapproved_installs_before_they_run() {
    let repo = repo(&format!("{APPROVAL}  min_release_age: 14\n"));
    repo.write("package.json", r#"{"dependencies": {"lodash": "^4"}}"#);
    repo.commit_all("base");
    let hook = |command: &str| {
        let input = hook_input(
            "PreToolUse",
            "Bash",
            &repo.path(),
            json!({"command": command}),
        );
        repo.run_stdin(&["hook", "claude-code"], &input)
    };

    let run = hook("npm install left-pad");
    assert_eq!(run.code(), 2);
    assert!(
        run.stderr()
            .contains("installing `left-pad` (npm) needs a human's approval"),
        "{}",
        run.stderr()
    );
    let run = hook("npm config set min-release-age 0 && npm i lodash@latest");
    assert_eq!(run.code(), 2);
    assert!(
        run.stderr().contains("minimum release age"),
        "{}",
        run.stderr()
    );
    for allowed in ["npm install lodash@latest", "npm ci && npm test", "ls -la"] {
        assert_eq!(hook(allowed).code(), 0, "{allowed}");
    }

    repo.write(
        ".larpcop.yaml",
        &format!("{APPROVAL}  min_release_age: 14\n  approved: [left-pad]\n"),
    );
    assert_eq!(hook("npm install left-pad").code(), 0);
}

#[test]
fn locked_dependency_rules_can_only_tighten() {
    let standards = tempfile::tempdir().unwrap();
    std::fs::write(
        standards.path().join("larpcop.yaml"),
        "dependencies:\n  min_release_age: 14\n  require_approval: true\n\
         locked: [dependency-release-age, dependency-approval]\n",
    )
    .unwrap();
    let base = extends_yaml(&standards.path().display().to_string());
    let repo = repo(&base);
    let with = |extra: &str| {
        repo.write(".larpcop.yaml", &format!("{base}dependencies:\n{extra}"));
        repo.run(&["rules"])
    };

    for (extra, error) in [
        (
            "  min_release_age: 7\n",
            "cannot lower the minimum age of rule `dependency-release-age`",
        ),
        (
            "  require_approval: false\n",
            "cannot turn off rule `dependency-approval`",
        ),
        (
            "  exempt: ['*']\n",
            "cannot add exemptions to rule `dependency-release-age`",
        ),
    ] {
        let run = with(extra);
        assert_eq!(run.code(), 3, "{extra}");
        assert!(run.stderr().contains(error), "{}", run.stderr());
    }
    let run = with("  min_release_age: 30\n  approved: [left-pad]\n");
    assert_eq!(run.code(), 0, "{}", run.stderr());
    assert!(
        run.stdout().contains("at least 30 days"),
        "{}",
        run.stdout()
    );

    assert_eq!(repo.run(&["sync"]).code(), 0);
    let agents = repo.read("AGENTS.md");
    assert!(
        agents.contains("`dependency-approval`") && agents.contains("`dependency-release-age`")
    );
}
