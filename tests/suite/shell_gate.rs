//! The shell gate of the agent hook under adverse conditions: large files, lookups
//! that fail, policy changes, a broken config, a snapshot that cannot be saved.

use super::shell_hook::bash;
use crate::common::deps::{fake_osv, npm_lock, repo};
use crate::common::*;

#[test]
fn a_substitution_on_a_large_file_does_not_hang_the_hook() {
    let sed = std::process::Command::new("sed")
        .arg("s/a/b/")
        .stdin(std::process::Stdio::null())
        .output();
    if !sed.is_ok_and(|o| o.status.success()) {
        eprintln!("skipped: no sed");
        return;
    }
    let repo = Repo::with_standards();
    // Larger than the pipe buffers in both directions.
    repo.write(
        "data/big.txt",
        &"lorem ipsum dolor sit amet\n".repeat(45_000),
    );
    repo.commit_all("base");
    let input = bash(
        "PreToolUse",
        &repo.path(),
        "c",
        "sed -i.bak 's/ipsum/IPSUM/g' data/big.txt",
    );
    // On a thread, so that a hook that hangs fails the test instead of the run.
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let started = std::time::Instant::now();
        let run = repo.run_stdin(&["hook", "claude-code"], &input);
        tx.send((run, started.elapsed())).ok();
    });
    let (run, took) = rx
        .recv_timeout(std::time::Duration::from_secs(60))
        .expect("the hook hangs on a large file");
    assert_eq!(run.code(), 0, "{}{}", run.stdout(), run.stderr());
    assert!(took < std::time::Duration::from_secs(30), "{took:?}");
}

#[test]
fn the_dependency_gate_does_not_remember_a_failed_lookup_or_an_old_policy() {
    let repo = repo("dependencies:\n  min_release_age: 14\n");
    repo.write(".npmrc", "min-release-age=14\n");
    repo.write("package-lock.json", &npm_lock(&[("left-pad", "1.3.0")]));
    repo.commit_all("base");
    repo.seed_published("npm", "left-pad", "1.3.0", 400);
    repo.write(
        "package-lock.json",
        &npm_lock(&[("left-pad", "1.3.0"), ("zod", "3.99.0")]),
    );
    let dir = repo.path();
    let test = || {
        repo.run_stdin(
            &["hook", "claude-code"],
            &bash("PreToolUse", &dir, "c", "npm test"),
        )
    };

    // deps.dev cannot be reached (the tests are offline): the gate fails closed...
    let offline = test();
    assert_eq!(offline.code(), 2, "{}", offline.stdout());
    assert!(
        offline.stderr().contains("could not look up"),
        "{}",
        offline.stderr()
    );
    // ...and as soon as the date is known the next command runs, not ten minutes later.
    repo.seed_published("npm", "zod", "3.99.0", 400);
    let known = test();
    assert_eq!(known.code(), 0, "{}", known.stderr());

    // A verdict belongs to the policy it was reached under.
    repo.seed_published("npm", "yup", "1.0.0", 5);
    repo.write(
        "package-lock.json",
        &npm_lock(&[("left-pad", "1.3.0"), ("zod", "3.99.0"), ("yup", "1.0.0")]),
    );
    let young = test();
    assert_eq!(young.code(), 2, "{}", young.stdout());
    assert!(young.stderr().contains("yup@1.0.0"), "{}", young.stderr());
    repo.write(".larpcop.yaml", "dependencies:\n  min_release_age: 3\n");
    let relaxed = test();
    assert_eq!(relaxed.code(), 0, "{}", relaxed.stderr());
}

#[test]
fn the_dependency_gate_does_not_remember_an_osv_outage() {
    let repo = repo("dependencies:\n  vulnerabilities: high\n");
    repo.write("package-lock.json", &npm_lock(&[("left-pad", "1.3.0")]));
    repo.commit_all("base");
    repo.write(
        "package-lock.json",
        &npm_lock(&[("left-pad", "1.3.0"), ("zod", "3.99.0")]),
    );
    let dir = repo.path();
    let test = |osv: &str| {
        repo.run_stdin_env(
            &["hook", "claude-code"],
            &bash("PreToolUse", &dir, "c", "npm test"),
            &[("LARPCOP_OSV_API", osv)],
        )
    };

    let down = test("http://127.0.0.1:9/v1");
    assert_eq!(down.code(), 2, "{}", down.stdout());
    assert!(
        down.stderr().contains("could not query OSV"),
        "{}",
        down.stderr()
    );
    // The next command runs as soon as OSV answers, not ten minutes later.
    let clean = fake_osv(vec![], vec![]);
    let up = test(&clean);
    assert_eq!(up.code(), 0, "{}", up.stderr());
}

#[test]
fn code_does_not_run_when_the_uncommitted_files_cannot_be_listed() {
    let repo = repo("dependencies:\n  min_release_age: 14\n");
    repo.commit_all("base");
    // `git status` fails on an index it cannot read.
    repo.write(".git/index", "not an index");
    let dir = repo.path();
    let hook = |cmd: &str| {
        repo.run_stdin(
            &["hook", "claude-code"],
            &bash("PreToolUse", &dir, "c", cmd),
        )
    };

    let code = hook("npm test");
    assert_eq!(code.code(), 2, "{}", code.stdout());
    assert!(
        code.stderr()
            .contains("could not list the uncommitted files"),
        "{}",
        code.stderr()
    );
    // What cannot run dependency code is not held up by it.
    let inert = hook("ls");
    assert_eq!(inert.code(), 0, "{}", inert.stderr());
}

#[test]
fn a_broken_config_lets_the_command_through_but_says_the_gate_is_off() {
    let repo = Repo::new();
    repo.write(".larpcop.yaml", "extends: [./missing]\n");
    let input = bash("PreToolUse", &repo.path(), "c", "npm test");
    let run = repo.run_stdin(&["hook", "claude-code"], &input);
    assert_eq!(run.code(), 0, "{}", run.stderr());
    assert!(
        run.stderr()
            .contains("the dependency gate is off for this command")
            && run.stderr().contains("missing"),
        "{}",
        run.stderr()
    );
}

#[test]
fn a_snapshot_that_cannot_be_saved_is_reported() {
    let repo = Repo::with_standards();
    repo.write("cache-is-a-file", "x");
    let not_a_dir = repo.path().join("cache-is-a-file");
    let env = [("LARPCOP_CACHE_DIR", not_a_dir.to_str().unwrap())];
    let input = bash("PreToolUse", &repo.path(), "c", "ls");
    let run = repo.run_stdin_env(&["hook", "claude-code"], &input, &env);
    assert_eq!(run.code(), 0, "{}", run.stderr());
    assert!(
        run.stderr().contains("will not be checked afterwards"),
        "{}",
        run.stderr()
    );
}

#[test]
fn the_after_shell_check_works_in_a_project_below_the_repository_top() {
    let repo = Repo::new();
    repo.write("app/.larpcop.yaml", &extends_yaml(STANDARDS));
    repo.write("app/src/ok.ts", GOOD_TS);
    repo.commit_all("base");
    let dir = repo.path().join("app");
    let hook = |event: &str| {
        repo.run_stdin(
            &["hook", "claude-code"],
            &bash(event, &dir, "c1", "./generate.sh"),
        )
    };
    assert_eq!(hook("PreToolUse").code(), 0);
    repo.write("app/src/ok.ts", BAD_TS);
    let after = hook("PostToolUse");
    assert_eq!(after.code(), 2, "{}{}", after.stdout(), after.stderr());
    assert!(
        after.stderr().contains("no-explicit-any"),
        "{}",
        after.stderr()
    );
}
