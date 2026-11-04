//! The git plumbing behind file selection: one runner, NUL-separated listings,
//! and every blob of a scope read through a single `git cat-file --batch`.

use anyhow::{Context, Result, bail};
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

/// Stdout of `git args` run in `root`; a failure names the command and git's complaint.
pub fn git(root: &Path, args: &[&str]) -> Result<Vec<u8>> {
    let out = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .context("running git")?;
    if !out.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(out.stdout)
}

pub(super) fn git_list(root: &Path, args: &[&str]) -> Result<Vec<String>> {
    Ok(String::from_utf8_lossy(&git(root, args)?)
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect())
}

/// A `.git` (directory, or file for worktrees and submodules) sits at or above `root`.
pub fn in_repo(root: &Path) -> bool {
    root.ancestors().any(|dir| dir.join(".git").exists())
}

/// Content of `rel` at commit `rev`; `None` if it did not exist there.
pub fn show(root: &Path, rev: &str, rel: &str) -> Option<String> {
    show_bytes(root, &format!("{rev}:./{rel}")).and_then(|b| String::from_utf8(b).ok())
}

fn show_bytes(root: &Path, object: &str) -> Option<Vec<u8>> {
    git(root, &["show", object]).ok()
}

/// Every file path at commit `rev`, relative to the root. A failure is reported
/// on stderr and gives an empty list: the callers (dependency approval) can only
/// treat every dependency as new, which fails safe.
pub fn tree(root: &Path, rev: &str) -> Vec<String> {
    git_list(root, &["ls-tree", "-r", "--name-only", "-z", rev]).unwrap_or_else(|e| {
        eprintln!("larpcop: warning: cannot list the files at {rev}: {e:#}");
        Vec::new()
    })
}

/// Contents of git objects (`:./path` for the index, `rev:./path`), in order;
/// `None` for an object that is missing or is not a blob. One `git cat-file
/// --batch` serves all of them: a process per file dominates a large commit.
pub fn blobs(root: &Path, specs: &[String]) -> Result<Vec<Option<Vec<u8>>>> {
    // The protocol is one object name per line: a name with a newline goes through `git show`.
    let batched: Vec<&String> = specs.iter().filter(|s| !s.contains('\n')).collect();
    let mut found = if batched.is_empty() {
        Vec::new()
    } else {
        cat_file(root, &batched)?
    }
    .into_iter();
    Ok(specs
        .iter()
        .map(|spec| {
            if spec.contains('\n') {
                show_bytes(root, spec)
            } else {
                found.next().flatten()
            }
        })
        .collect())
}

fn cat_file(root: &Path, specs: &[&String]) -> Result<Vec<Option<Vec<u8>>>> {
    let mut child = Command::new("git")
        .args(["cat-file", "--batch"])
        .current_dir(root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("running git cat-file")?;
    let mut stdin = child.stdin.take().context("git cat-file stdin")?;
    let stdout = child.stdout.take().context("git cat-file stdout")?;
    // git answers while it reads: writing every request before reading the first
    // answer would deadlock once both pipes are full.
    let (answers, written) = std::thread::scope(|scope| -> Result<_> {
        let writer = scope.spawn(move || -> std::io::Result<()> {
            for spec in specs {
                writeln!(stdin, "{spec}")?;
            }
            Ok(())
        });
        let answers = read_answers(BufReader::new(stdout), specs.len());
        if answers.is_err() {
            // Nobody reads git's output any more: stop it so the writer is not stuck.
            child.kill().context("stopping git cat-file")?;
        }
        Ok((answers, writer.join()))
    })?;
    let out = child
        .wait_with_output()
        .context("waiting for git cat-file")?;
    let answers = answers.with_context(|| {
        format!(
            "reading git cat-file output: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )
    })?;
    match written {
        Ok(result) => result.context("sending names to git cat-file")?,
        Err(_) => bail!("the thread feeding git cat-file panicked"),
    }
    Ok(answers)
}

/// `<oid> <type> <size>\n<content>\n` per object, `<name> missing\n` for the absent.
fn read_answers(mut out: impl BufRead, count: usize) -> Result<Vec<Option<Vec<u8>>>> {
    let mut answers = Vec::with_capacity(count);
    for _ in 0..count {
        let mut header = String::new();
        if out.read_line(&mut header)? == 0 {
            bail!(
                "git cat-file ended after {} of {count} objects",
                answers.len()
            );
        }
        let header = header.trim_end_matches('\n');
        if header.ends_with(" missing") {
            answers.push(None);
            continue;
        }
        let mut fields = header.rsplitn(3, ' ');
        let (Some(size), Some(kind)) = (fields.next(), fields.next()) else {
            bail!("unexpected git cat-file answer `{header}`");
        };
        let size: u64 = size
            .parse()
            .with_context(|| format!("unexpected git cat-file answer `{header}`"))?;
        let mut content = Vec::new();
        out.by_ref().take(size).read_to_end(&mut content)?;
        if content.len() as u64 != size {
            bail!("git cat-file ended inside an object");
        }
        let mut newline = [0u8; 1];
        out.read_exact(&mut newline)?;
        answers.push((kind == "blob").then_some(content));
    }
    Ok(answers)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo() -> tempfile::TempDir {
        let tmp = tempfile::tempdir().unwrap();
        for args in [
            &["init", "-q", "-b", "main"][..],
            &["config", "core.autocrlf", "false"],
        ] {
            git(tmp.path(), args).unwrap();
        }
        tmp
    }

    #[test]
    fn staged_blobs_are_the_bytes_git_show_prints() {
        let tmp = repo();
        let big = "x".repeat(300_000);
        let files = [
            ("crlf.txt", b"a\r\nb\r\n".to_vec()),
            ("big.txt", big.into_bytes()),
            ("binary.bin", vec![0xff, 0xfe, 0, 1]),
            ("sp ace.txt", b"spaced".to_vec()),
            ("empty.txt", Vec::new()),
        ];
        for (name, bytes) in &files {
            std::fs::write(tmp.path().join(name), bytes).unwrap();
        }
        git(tmp.path(), &["add", "-A"]).unwrap();
        let mut specs: Vec<String> = files.iter().map(|(n, _)| format!(":./{n}")).collect();
        specs.insert(2, ":./gone.txt".into());
        let got = blobs(tmp.path(), &specs).unwrap();
        assert_eq!(got.len(), specs.len());
        assert_eq!(got[2], None);
        for (spec, got) in specs.iter().zip(&got) {
            let shown = git(tmp.path(), &["show", spec]).ok();
            assert_eq!(got, &shown, "{spec}");
        }
        // No line-ending conversion on the way out.
        assert_eq!(got[0].as_deref(), Some(&b"a\r\nb\r\n"[..]));
    }

    #[test]
    fn a_name_with_a_newline_is_read_through_git_show() {
        let tmp = repo();
        // Not creatable on every file system.
        if std::fs::write(tmp.path().join("a\nb.txt"), "odd").is_err() {
            return;
        }
        std::fs::write(tmp.path().join("c.txt"), "plain").unwrap();
        git(tmp.path(), &["add", "-A"]).unwrap();
        let specs = vec![":./a\nb.txt".to_string(), ":./c.txt".to_string()];
        let got = blobs(tmp.path(), &specs).unwrap();
        assert_eq!(got, [Some(b"odd".to_vec()), Some(b"plain".to_vec())]);
    }

    #[test]
    fn git_failing_is_an_error_not_missing_objects() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(blobs(tmp.path(), &[":./a".to_string()]).is_err());
    }
}
