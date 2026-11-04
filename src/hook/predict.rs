//! Content a command will give a file, worked out before it runs, so the hook
//! can refuse it instead of cleaning up after: `cp`/`mv`/`install` of files,
//! and `sed -i` whose script only substitutes (run on a copy, through the same
//! `sed`). Anything else is judged right after it runs (`shell_run`).

use crate::shell_ast::{Command, Script};
use anyhow::{Context, Result, bail};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command as Process, Stdio};
use std::sync::mpsc;
use std::time::Duration;

/// Longest a prediction may take: the hook runs before every tool call.
const SED_TIMEOUT: Duration = Duration::from_secs(5);

/// (file, content it will have) for every write this script's commands predict.
pub fn predicted(script: &Script, dir: &Path) -> Vec<(PathBuf, String)> {
    script
        .commands
        .iter()
        .flat_map(|c| match c.words.first().map(String::as_str) {
            Some("cp" | "mv" | "install") => copies(c, dir),
            Some("sed") => sed_in_place(c, dir),
            _ => Vec::new(),
        })
        .collect()
}

fn copies(c: &Command, dir: &Path) -> Vec<(PathBuf, String)> {
    let mut operands = Vec::new();
    let mut words = c.words[1..].iter();
    while let Some(w) = words.next() {
        match w.as_str() {
            // `install -m 644 a b`: options with a value.
            "-m" | "-o" | "-g" | "--mode" | "--owner" | "--group" => {
                words.next();
            }
            "-t" | "--target-directory" => return Vec::new(),
            w if w.starts_with('-') => {}
            w => operands.push(dir.join(w)),
        }
    }
    let Some((dest, sources)) = operands.split_last() else {
        return Vec::new();
    };
    let into_dir = dest.is_dir();
    if sources.is_empty() || (sources.len() > 1 && !into_dir) {
        return Vec::new();
    }
    sources
        .iter()
        .filter(|s| s.is_file())
        .filter_map(|s| {
            let target = if into_dir {
                dest.join(s.file_name()?)
            } else {
                dest.clone()
            };
            Some((target, std::fs::read_to_string(s).ok()?))
        })
        .collect()
}

fn sed_in_place(c: &Command, dir: &Path) -> Vec<(PathBuf, String)> {
    let mut args = Vec::new();
    let mut scripts = Vec::new();
    let mut files = Vec::new();
    let mut in_place = false;
    let mut words = c.words[1..].iter().peekable();
    while let Some(w) = words.next() {
        match w.as_str() {
            // BSD `-i ''` / `-i .bak` take the suffix as the next word.
            "-i" => {
                in_place = true;
                if words
                    .peek()
                    .is_some_and(|n| n.is_empty() || n.starts_with('.'))
                {
                    words.next();
                }
            }
            w if w.starts_with("-i") || w.starts_with("--in-place") => in_place = true,
            "-e" | "--expression" => scripts.extend(words.next().cloned()),
            w if w.starts_with("--expression=") => {
                scripts.push(w["--expression=".len()..].to_string())
            }
            "-E" | "-r" | "-n" | "-s" | "-z" | "--posix" | "--regexp-extended" | "--quiet"
            | "--silent" => args.push(w.to_string()),
            w if w.starts_with('-') => return Vec::new(),
            w if scripts.is_empty() => scripts.push(w.to_string()),
            w => files.push(dir.join(w)),
        }
    }
    if !in_place || scripts.is_empty() || !scripts.iter().all(|s| substitutions_only(s)) {
        return Vec::new();
    }
    let sed = crate::shell::which("sed");
    for s in &scripts {
        args.extend(["-e".to_string(), s.clone()]);
    }
    files
        .into_iter()
        .filter_map(|f| {
            // A file that cannot be read as text (missing, binary) has nothing to predict;
            // the real `sed` will say what is wrong with it.
            let old = std::fs::read_to_string(&f).ok()?;
            match run(&sed, &args, &old, SED_TIMEOUT) {
                Ok(new) => Some((f, new?)),
                Err(e) => {
                    eprintln!(
                        "larpcop: warning: not predicting `sed` on {}: {e:#}",
                        f.display()
                    );
                    None
                }
            }
        })
        .collect()
}

/// `input` through `sed`; `None` when sed rejects the script or answers in
/// something other than UTF-8. Errors when sed cannot run or outlasts `timeout`.
fn run(sed: &Path, args: &[String], input: &str, timeout: Duration) -> Result<Option<String>> {
    let mut child = Process::new(sed)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("starting {}", sed.display()))?;
    let mut stdin = child.stdin.take().context("sed stdin")?;
    let mut stdout = child.stdout.take().context("sed stdout")?;
    // Both pipes are served at once: a file larger than the pipe buffers would
    // otherwise leave sed blocked writing while the hook is blocked writing.
    let output = std::thread::scope(|scope| -> Result<Vec<u8>> {
        let feeder = scope.spawn(move || stdin.write_all(input.as_bytes()));
        let (tx, rx) = mpsc::channel();
        scope.spawn(move || {
            let mut out = Vec::new();
            let read = stdout.read_to_end(&mut out).map(|_| out);
            // The receiver is gone only after the deadline passed.
            tx.send(read).ok();
        });
        let read = rx.recv_timeout(timeout);
        if read.is_err() {
            // Killing sed closes both pipes, which ends the two threads.
            child.kill().context("stopping sed")?;
        }
        let fed = feeder.join();
        let out = read
            .map_err(|_| anyhow::anyhow!("sed did not finish within {timeout:?}"))?
            .context("reading sed's output")?;
        match fed {
            // sed left before reading everything (a script it rejects): its status says so.
            Ok(Err(e)) if e.kind() != ErrorKind::BrokenPipe => {
                return Err(e).context("sending the file to sed");
            }
            Ok(_) => {}
            Err(_) => bail!("the thread feeding sed panicked"),
        }
        Ok(out)
    });
    // Reaps sed after a kill too.
    let status = child.wait().context("waiting for sed")?;
    let output = output?;
    Ok(status
        .success()
        .then(|| String::from_utf8(output).ok())
        .flatten())
}

/// `s/a/b/g; s|c|d|` and nothing else: no addresses, no `w`/`e` flags that
/// would write a file or run a command while predicting.
fn substitutions_only(script: &str) -> bool {
    let mut chars = script.chars().peekable();
    loop {
        while chars.peek().is_some_and(|c| c.is_whitespace() || *c == ';') {
            chars.next();
        }
        match chars.next() {
            None => return true,
            Some('s') => {}
            Some(_) => return false,
        }
        let Some(delim) = chars.next().filter(|d| *d != '\\' && *d != '\n') else {
            return false;
        };
        for _ in 0..2 {
            loop {
                match chars.next() {
                    None => return false,
                    Some('\\') => {
                        chars.next();
                    }
                    Some(c) if c == delim => break,
                    Some(_) => {}
                }
            }
        }
        while chars
            .peek()
            .is_some_and(|c| matches!(c, 'g' | 'p' | 'i' | 'I' | 'm' | 'M' | '0'..='9'))
        {
            chars.next();
        }
        if chars
            .peek()
            .is_some_and(|c| !c.is_whitespace() && *c != ';')
        {
            return false;
        }
    }
}

#[cfg(test)]
mod tests {
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
        let input =
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n".repeat(40_000);
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

    /// The two ways a program can fail to answer, shown with the POSIX shell
    /// instead of `sed` itself: sed dialects differ (msys sed on Windows drops
    /// the backslash of `\(`, so one script is an error on one OS and fine on
    /// another).
    #[test]
    fn a_rejected_script_predicts_nothing_and_a_hung_sed_is_killed() {
        let sh = crate::shell::posix_shell();
        let script = |body: &str| ["-c".to_string(), body.to_string()];
        // It reads all its input, then fails: no prediction, and no error.
        let rejected = run(
            &sh,
            &script("cat >/dev/null; exit 3"),
            "text\n".repeat(100_000).as_str(),
            Duration::from_secs(30),
        );
        assert_eq!(rejected.unwrap(), None);
        // It never reads its stdin or answers: the deadline has to stop it.
        let started = Instant::now();
        let hung = run(
            &sh,
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
            !ok("s/a/b/w /tmp/x")
                && !ok("s/a/b/e")
                && !ok("1d")
                && !ok("/x/s/a/b/")
                && !ok("s/a/b")
        );
    }
}
