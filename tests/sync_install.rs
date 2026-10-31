mod common;

use common::{BAD_TS, GOOD_TS, Repo, STANDARDS, copy_dir, extends_yaml};
use std::fs;
use std::path::Path;

/// git `autocrlf` (default on Windows) turns checked-out files into CRLF,
/// both in the repo and in fetched standards. Neither may count as drift.
#[test]
fn crlf_checkouts_are_not_drift() {
    let standards = tempfile::tempdir().unwrap();
    copy_dir(Path::new(STANDARDS), standards.path());
    let guidelines = standards.path().join("guidelines.md");
    let lf = fs::read_to_string(&guidelines)
        .unwrap()
        .replace("\r\n", "\n");
    fs::write(&guidelines, lf.replace('\n', "\r\n")).unwrap();

    let repo = Repo::new();
    repo.write(
        ".larpcop.yaml",
        &extends_yaml(&standards.path().display().to_string()),
    );
    assert_eq!(repo.run(&["sync"]).code(), 0);
    assert!(
        !repo.read("AGENTS.md").contains('\r'),
        "generated files are LF"
    );

    for file in ["AGENTS.md", "CLAUDE.md", ".claude/settings.json"] {
        let content = repo.read(file).replace('\n', "\r\n");
        repo.write(file, &content);
    }
    let check = repo.run(&["sync", "--check"]);
    assert_eq!(check.code(), 0, "{}", check.stdout());
}

#[test]
fn sync_generates_agent_files_and_detects_drift() {
    let repo = Repo::with_standards();
    let user_settings = r#"{"permissions":{"allow":["Bash(npm test)"]},"hooks":{"Stop":[{"hooks":[{"type":"command","command":"say done"}]}]}}"#;
    repo.write(".claude/settings.json", user_settings);
    repo.write("AGENTS.md", "# Project\n\nRun `npm test` before pushing.\n");

    let run = repo.run(&["sync"]);
    assert_eq!(run.code(), 0, "{}", run.stderr());

    let agents = repo.read("AGENTS.md");
    assert!(
        agents.starts_with("# Project\n\nRun `npm test`"),
        "user content kept:\n{agents}"
    );
    assert!(
        agents.contains("| `no-explicit-any` | error | TypeScript |"),
        "{agents}"
    );
    assert!(
        agents.contains("One responsibility per file"),
        "guidelines inlined"
    );
    assert_eq!(repo.read("CLAUDE.md"), "@AGENTS.md\n");

    let settings: serde_json::Value =
        serde_json::from_str(&repo.read(".claude/settings.json")).unwrap();
    assert_eq!(settings["permissions"]["allow"][0], "Bash(npm test)");
    let stop = settings["hooks"]["Stop"].as_array().unwrap();
    assert_eq!(stop.len(), 2, "user hook kept, ours added: {stop:?}");
    assert_eq!(
        settings["hooks"]["PostToolUse"][0]["hooks"][0]["command"],
        "larpcop hook claude-code"
    );

    let again = repo.run(&["sync", "--check"]);
    assert_eq!(again.code(), 0, "idempotent: {}", again.stdout());

    let tampered = repo
        .read("AGENTS.md")
        .replace("| `no-explicit-any` |", "| `removed` |");
    repo.write("AGENTS.md", &tampered);
    let drift = repo.run(&["sync", "--check"]);
    assert_eq!(drift.code(), 1);
    assert!(drift.stdout().contains("AGENTS.md"));
}

#[test]
fn pre_commit_hook_rejects_bad_commits() {
    let repo = Repo::with_standards();
    let run = repo.run(&["install"]);
    assert_eq!(run.code(), 0, "{}", run.stderr());

    repo.write("a.ts", BAD_TS);
    repo.git(&["add", "-A"]);
    let rejected = repo.git_commit("bad");
    assert_ne!(rejected.code(), 0, "commit must be rejected");
    // git redirects hook stdout to stderr
    assert!(
        rejected.stderr().contains("no-explicit-any"),
        "{}",
        rejected.stderr()
    );

    repo.write("a.ts", GOOD_TS);
    repo.git(&["add", "-A"]);
    let accepted = repo.git_commit("good");
    assert_eq!(
        accepted.code(),
        0,
        "{}{}",
        accepted.stdout(),
        accepted.stderr()
    );
}

#[test]
fn install_refuses_to_clobber_foreign_hooks() {
    let repo = Repo::with_standards();
    repo.write(".git/hooks/pre-commit", "#!/bin/sh\nnpm run lint\n");
    let run = repo.run(&["install"]);
    assert_eq!(run.code(), 3);
    assert!(run.stderr().contains("not managed by larpcop"));
    assert_eq!(repo.run(&["install", "--force"]).code(), 0);
}
