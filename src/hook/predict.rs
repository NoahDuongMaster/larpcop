//! Content a command will give a file, worked out before it runs, so the hook
//! can refuse it instead of cleaning up after: `cp`/`mv`/`install` of files,
//! and `sed -i` whose script only substitutes (run on a copy, through the same
//! `sed`). Anything else is judged right after it runs (`shell_run`).

use crate::shell_ast::{Command, Script};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command as Process, Stdio};

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
            let old = std::fs::read_to_string(&f).ok()?;
            Some((f, run(&sed, &args, &old)?))
        })
        .collect()
}

fn run(sed: &Path, args: &[String], input: &str) -> Option<String> {
    let mut child = Process::new(sed)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    child.stdin.take()?.write_all(input.as_bytes()).ok()?;
    let out = child.wait_with_output().ok()?;
    out.status
        .success()
        .then(|| String::from_utf8(out.stdout).ok())
        .flatten()
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
