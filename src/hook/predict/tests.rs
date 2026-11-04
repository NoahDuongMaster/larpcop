//! `predict` against the real `sed` and a shell standing in for it.

use super::*;
use std::time::Instant;

fn sed_works() -> bool {
    let sed = crate::shell::which("sed");
    Process::new(sed)
        .arg("s/a/b/")
        .stdin(Stdio::null())
        .output()
        .is_ok_and(|o| o.status.success())
}

#[test]
fn a_file_larger_than_the_pipe_buffers_does_not_deadlock() {
    if !sed_works() {
        return;
    }
    let input = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n".repeat(40_000);
    assert!(input.len() > 2_000_000);
    let args = ["-e".to_string(), "s/a/b/".to_string()];
    let started = Instant::now();
    let out = run(
        &crate::shell::which("sed"),
        &args,
        &input,
        Duration::from_secs(30),
    )
    .unwrap()
    .unwrap();
    assert_eq!(out.len(), input.len());
    assert!(out.starts_with("baaaa"));
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "{:?}",
        started.elapsed()
    );
}

fn script(body: &str) -> [String; 2] {
    ["-c".to_string(), body.to_string()]
}

/// A program that reads everything and then fails: no prediction, no
/// error. Shown with the POSIX shell instead of `sed`, whose dialects differ
/// (msys sed drops the backslash of `\(`, so one script is an error on one
/// OS and fine on another).
#[test]
fn a_rejected_script_predicts_nothing() {
    let rejected = run(
        &crate::shell::posix_shell(),
        &script("cat >/dev/null; exit 3"),
        "text\n".repeat(100_000).as_str(),
        Duration::from_secs(30),
    );
    assert_eq!(rejected.unwrap(), None);
}

/// A program that never reads its stdin or answers: the deadline has to
/// stop it. Unix only: Git for Windows' `bin/sh.exe` is a launcher whose
/// real shell is a child, so killing it leaves the pipes open. `sed.exe`,
/// which is what the hook runs, is not wrapped.
#[cfg(unix)]
#[test]
fn a_hung_sed_is_killed() {
    let started = Instant::now();
    let hung = run(
        &crate::shell::posix_shell(),
        &script("exec sleep 30"),
        "x",
        Duration::from_millis(300),
    );
    assert!(hung.is_err());
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[test]
fn only_plain_substitutions_are_run() {
    use super::substitutions_only as ok;
    assert!(ok("s/a/b/") && ok("s|a/b|c|g; s/x/y/2") && ok("s/a\\/b/c/"));
    assert!(
        !ok("s/a/b/w /tmp/x") && !ok("s/a/b/e") && !ok("1d") && !ok("/x/s/a/b/") && !ok("s/a/b")
    );
}
