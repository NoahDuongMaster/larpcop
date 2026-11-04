//! Shell commands in agent hooks: what a command changed is checked right after
//! it runs; dependency code does not run while the lockfile fails the checks;
//! package managers without their own age gate must use resolve-only forms.

use crate::common::deps::{fake_deps_dev, npm_lock, repo};
use crate::common::*;
use serde_json::json;

pub fn bash(event: &str, dir: &std::path::Path, call: &str, command: &str) -> String {
    json!({ "session_id": "s1", "tool_use_id": call, "hook_event_name": event,
            "tool_name": "Bash", "tool_input": { "command": command }, "cwd": dir })
    .to_string()
}

#[test]
fn files_a_command_changed_are_checked_right_after_it() {
    let repo = Repo::with_standards();
    repo.write("src/ok.ts", GOOD_TS);
    repo.commit_all("base");
    let dir = repo.path();
    let hook = |event: &str, call: &str, cmd: &str| {
        repo.run_stdin(&["hook", "claude-code"], &bash(event, &dir, call, cmd))
    };

    // A script `sed` cannot run safely on a copy (it writes a file) is judged
    // right after it runs.
    let cmd = "sed -i.bak 's/x/y/w /dev/null' src/ok.ts";
    assert_eq!(hook("PreToolUse", "t1", cmd).code(), 0);
    repo.write("src/ok.ts", BAD_TS);
    let after = hook("PostToolUse", "t1", cmd);
    assert_eq!(after.code(), 2, "{}", after.stdout());
    assert!(
        after
            .stderr()
            .contains("the command you just ran changed files")
            && after.stderr().contains("no-explicit-any"),
        "{}",
        after.stderr()
    );

    // A command that changed nothing passes, even with the broken file around.
    assert_eq!(hook("PreToolUse", "t2", "ls").code(), 0);
    assert_eq!(hook("PostToolUse", "t2", "ls").code(), 0);
}

#[test]
fn dependency_code_does_not_run_while_the_lockfile_fails_the_checks() {
    let repo = repo("dependencies:\n  min_release_age: 14\n");
    repo.write(".npmrc", "min-release-age=14\n");
    repo.write("package-lock.json", &npm_lock(&[("left-pad", "1.3.0")]));
    repo.commit_all("base");
    repo.seed_published("npm", "left-pad", "1.3.0", 400);
    repo.seed_published("npm", "zod", "3.99.0", 1);
    repo.write(
        "package-lock.json",
        &npm_lock(&[("left-pad", "1.3.0"), ("zod", "3.99.0")]),
    );
    let dir = repo.path();
    let hook = |cmd: &str| {
        repo.run_stdin(
            &["hook", "claude-code"],
            &bash("PreToolUse", &dir, "c", cmd),
        )
    };

    let run = hook("npm test");
    assert_eq!(run.code(), 2, "{}", run.stdout());
    assert!(
        run.stderr().contains("can run dependency code") && run.stderr().contains("zod@3.99.0"),
        "{}",
        run.stderr()
    );
    for inert in [
        "cat package-lock.json",
        "npm install --ignore-scripts",
        "git diff",
    ] {
        assert_eq!(hook(inert).code(), 0, "{inert}");
    }
    // Fixed: everything runs again.
    repo.write("package-lock.json", &npm_lock(&[("left-pad", "1.3.0")]));
    assert_eq!(hook("npm test").code(), 0);
}

#[test]
fn installs_without_an_age_gate_need_their_resolve_only_form() {
    let repo = repo("dependencies:\n  min_release_age: 14\n");
    repo.commit_all("base");
    let dir = repo.path();
    let hook = |cmd: &str| {
        repo.run_stdin(
            &["hook", "claude-code"],
            &bash("PreToolUse", &dir, "c", cmd),
        )
    };
    for (cmd, needs) in [
        ("poetry add requests", "--lock"),
        ("pip install requests", "--uploaded-prior-to"),
        ("bundle add rack", "--skip-install"),
        ("bundle install", "BUNDLE_FROZEN=true"),
        ("bundle update rack", "bundle lock --update"),
        ("cargo install ripgrep", "--locked"),
        ("uvx ruff check", "--exclude-newer"),
    ] {
        let run = hook(cmd);
        assert_eq!(run.code(), 2, "{cmd}");
        assert!(run.stderr().contains(needs), "{cmd}: {}", run.stderr());
    }
    for cmd in [
        "pip install --uploaded-prior-to 2020-01-01 requests",
        "BUNDLE_FROZEN=true bundle install",
        "uv lock --exclude-newer '30 days'",
    ] {
        let run = hook(cmd);
        assert_eq!(run.code(), 0, "{cmd}: {}", run.stderr());
    }
    // A stricter setting is fine; a weaker one is not.
    assert_eq!(hook("npm i --min-release-age=30").code(), 0);
    assert_eq!(hook("npm i --min-release-age=1").code(), 2);
}

#[test]
fn installs_check_the_version_they_would_fetch() {
    let old = (jiff::Timestamp::now() - jiff::SignedDuration::from_hours(100 * 24)).to_string();
    let new = (jiff::Timestamp::now() - jiff::SignedDuration::from_hours(24)).to_string();
    let versions = json!({ "versions": [
        { "versionKey": { "version": "1.0.200" }, "publishedAt": old, "isDefault": false },
        { "versionKey": { "version": "1.0.230" }, "publishedAt": new, "isDefault": true },
    ]});
    let api = fake_deps_dev(vec![(
        "/v3/systems/cargo/packages/serde".into(),
        versions.to_string(),
    )]);
    let repo = repo("dependencies:\n  min_release_age: 14\n");
    repo.commit_all("base");
    let dir = repo.path();
    let env = [("LARPCOP_DEPS_API", api.as_str())];
    let run = repo.run_stdin_env(
        &["hook", "claude-code"],
        &bash("PreToolUse", &dir, "c", "cargo add serde"),
        &env,
    );
    assert_eq!(run.code(), 2, "{}", run.stdout());
    assert!(
        run.stderr().contains("`serde@1.0.230`")
            && run
                .stderr()
                .contains("cargo add serde@1.0.200` then `cargo update -p serde --precise 1.0.200"),
        "{}",
        run.stderr()
    );
    repo.seed_published("cargo", "serde", "1.0.200", 100);
    let pinned = repo.run_stdin_env(
        &["hook", "claude-code"],
        &bash("PreToolUse", &dir, "c", "cargo add serde@1.0.200"),
        &env,
    );
    assert_eq!(pinned.code(), 0, "{}", pinned.stderr());
}

#[test]
fn yarn_1_has_no_age_gate_so_its_installs_are_checked() {
    let new = (jiff::Timestamp::now() - jiff::SignedDuration::from_hours(24)).to_string();
    let versions = json!({ "versions": [
        { "versionKey": { "version": "2.0.0" }, "publishedAt": new, "isDefault": true },
    ]});
    let api = fake_deps_dev(vec![(
        "/v3/systems/npm/packages/left-pad".into(),
        versions.to_string(),
    )]);
    let repo = repo("dependencies:\n  min_release_age: 14\n");
    repo.write("yarn.lock", "# yarn lockfile v1\n");
    repo.commit_all("base");
    let dir = repo.path();
    let env = [("LARPCOP_DEPS_API", api.as_str())];
    let run = repo.run_stdin_env(
        &["hook", "claude-code"],
        &bash("PreToolUse", &dir, "c", "yarn add left-pad"),
        &env,
    );
    assert_eq!(run.code(), 2, "{}", run.stdout());
    assert!(
        run.stderr().contains("`left-pad@2.0.0`"),
        "{}",
        run.stderr()
    );
}

#[test]
fn copies_and_substitutions_are_judged_before_they_run() {
    let repo = Repo::with_standards();
    repo.write("src/ok.ts", GOOD_TS);
    repo.write("drafts/bad.ts", BAD_TS);
    repo.commit_all("base");
    let dir = repo.path();
    let pre = |cmd: &str| {
        repo.run_stdin(
            &["hook", "claude-code"],
            &bash("PreToolUse", &dir, "c", cmd),
        )
    };
    let copy = pre("cp drafts/bad.ts src/new.ts");
    assert_eq!(copy.code(), 2, "{}", copy.stdout());
    assert!(
        copy.stderr().contains("no-explicit-any"),
        "{}",
        copy.stderr()
    );
    assert_eq!(pre("mkdir -p lib && mv drafts/bad.ts src/").code(), 2);
    assert_eq!(pre("cp src/ok.ts src/copy.ts").code(), 0);
    let sed = std::process::Command::new("sed")
        .arg("s/a/b/")
        .stdin(std::process::Stdio::null())
        .output();
    if sed.is_ok_and(|o| o.status.success()) {
        let sed = pre("sed -i.bak -e 's/x: string/x: any/' src/ok.ts");
        assert_eq!(sed.code(), 2, "{}{}", sed.stdout(), sed.stderr());
        assert_eq!(pre("sed -i.bak 's/trim/trimEnd/g' src/ok.ts").code(), 0);
    } else {
        eprintln!("skipped: no sed");
    }
}
