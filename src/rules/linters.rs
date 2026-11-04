//! Delegation to stack-specific tools (eslint, ruff, golangci-lint, …).

use super::{RuleInfo, Violation};
use crate::config::LinterConfig;
use crate::files::{SourceFile, globset};
use anyhow::{Context, Result};
use globset::GlobSet;
use std::path::Path;
use std::process::{Command, Output};

const OUTPUT_TAIL_LINES: usize = 40;

/// The most bytes of file names in one command. The command is a single
/// argument of the shell, which Linux caps at 128 KiB (and all arguments at
/// `ARG_MAX`, 2 MiB or less elsewhere). On Windows the MSYS2 runtime of Git's
/// `sh.exe` silently cuts an argument at 8,186 characters, in the middle of a
/// quoted name, so the budget stays well under that. This leaves room for the
/// rest of the command.
const MAX_FILES_BYTES: usize = if cfg!(windows) { 6 * 1024 } else { 64 * 1024 };

pub struct Linter {
    cfg: LinterConfig,
    include: Option<GlobSet>,
}

impl Linter {
    pub fn new(cfg: &LinterConfig) -> Result<Self> {
        let include = (!cfg.include.is_empty())
            .then(|| globset(&cfg.include))
            .transpose()?;
        Ok(Self {
            cfg: cfg.clone(),
            include,
        })
    }

    /// Runs over all matching files; a non-zero exit is one violation
    /// carrying the tool's own output so the agent sees exact locations.
    /// The files go to the command in runs short enough for the operating
    /// system to start it (one huge command line fails to start); the first
    /// failing run decides.
    pub fn run(&self, root: &Path, files: &[SourceFile]) -> Result<Option<Violation>> {
        let matched: Vec<&str> = files
            .iter()
            .map(|f| f.rel.as_str())
            .filter(|rel| self.include.as_ref().is_none_or(|g| g.is_match(rel)))
            .collect();
        if matched.is_empty() {
            return Ok(None);
        }
        let quoted: Vec<String> = matched.iter().map(|r| shell_quote(r)).collect();
        // A command without `{files}` is the same in every run: once is enough.
        let runs = if self.cfg.run.contains("{files}") {
            chunks(&quoted, MAX_FILES_BYTES)
        } else {
            vec![&quoted[..]]
        };
        for run in runs {
            let cmd = self.cfg.run.replace("{files}", &run.join(" "));
            let out = self.shell(root, &cmd)?;
            if out.status.success() {
                continue;
            }
            let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
            text.push_str(&String::from_utf8_lossy(&out.stderr));
            let code = out
                .status
                .code()
                .map_or("signal".to_string(), |c| c.to_string());
            return Ok(Some(Violation {
                rule: self.cfg.id.clone(),
                level: self.cfg.level,
                file: String::new(),
                line: 0,
                column: 0,
                message: format!(
                    "`{}` failed (exit {code}) on {} file(s).",
                    self.cfg.run,
                    matched.len()
                ),
                note: Some(tail(&text, OUTPUT_TAIL_LINES)),
                snippet: None,
            }));
        }
        Ok(None)
    }

    fn shell(&self, root: &Path, cmd: &str) -> Result<Output> {
        let shell = crate::shell::posix_shell();
        Command::new(&shell)
            .arg("-c")
            .arg(cmd)
            .current_dir(root)
            .output()
            .with_context(|| {
                format!(
                    "running linter `{}` with {} (install Git, or set LARPCOP_SHELL to a POSIX sh)",
                    self.cfg.id,
                    shell.display()
                )
            })
    }

    pub fn info(&self) -> RuleInfo {
        RuleInfo {
            id: self.cfg.id.clone(),
            level: self.cfg.level,
            scope: if self.cfg.include.is_empty() {
                "all files".into()
            } else {
                self.cfg.include.join(", ")
            },
            message: format!("`{}` must pass.", self.cfg.run),
            note: None,
        }
    }
}

fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// `quoted` in consecutive runs whose names, joined by spaces, fit `max`
/// bytes; a name too long for that is a run of its own.
fn chunks(quoted: &[String], max: usize) -> Vec<&[String]> {
    let mut runs = Vec::new();
    let (mut from, mut size) = (0, 0);
    for (i, name) in quoted.iter().enumerate() {
        if size > 0 && size + name.len() + 1 > max {
            runs.push(&quoted[from..i]);
            (from, size) = (i, 0);
        }
        size += name.len() + 1;
    }
    runs.push(&quoted[from..]);
    runs
}

fn tail(text: &str, n: usize) -> String {
    let lines: Vec<&str> = text.trim_end().lines().collect();
    lines[lines.len().saturating_sub(n)..].join("\n")
}

#[cfg(test)]
mod tests {
    use super::{Linter, chunks};
    use crate::config::LinterConfig;
    use crate::files::SourceFile;

    fn linter(run: &str) -> Linter {
        let cfg: LinterConfig =
            serde_saphyr::from_str(&format!("id: fake\nrun: {run:?}\n")).expect("config");
        Linter::new(&cfg).expect("linter")
    }

    /// Files whose names together are over twice the longest command.
    fn many_files() -> Vec<SourceFile> {
        (0..1500)
            .map(|i| SourceFile {
                rel: format!("some/long/directory/name/to/fill/the/command/line/file-{i:05}.txt"),
                content: String::new(),
            })
            .collect()
    }

    #[test]
    fn runs_split_without_losing_or_repeating_a_name() {
        let names: Vec<String> = (0..10).map(|i| format!("'{i}{}'", "x".repeat(i))).collect();
        for max in [1, 5, 12, 40, 1000] {
            let runs = chunks(&names, max);
            assert_eq!(runs.concat(), names, "max {max}");
            for run in &runs {
                let size = run.iter().map(|n| n.len() + 1).sum::<usize>();
                assert!(run.len() == 1 || size <= max, "{run:?} for {max}");
            }
        }
        assert_eq!(chunks(&names, 1000).len(), 1);
    }

    #[test]
    fn a_command_line_too_long_for_one_run_is_run_in_several() {
        let dir = tempfile::tempdir().expect("tempdir");
        let files = many_files();
        let fake =
            linter("echo run >> runs.txt; for f in {files}; do echo \"$f\" >> seen.txt; done");
        let found = fake.run(dir.path(), &files).expect("runs");
        assert!(found.is_none(), "{found:?}");
        let runs = std::fs::read_to_string(dir.path().join("runs.txt")).expect("runs.txt");
        let seen = std::fs::read_to_string(dir.path().join("seen.txt")).expect("seen.txt");
        assert!(runs.lines().count() >= 2, "{runs}");
        let expected: Vec<&str> = files.iter().map(|f| f.rel.as_str()).collect();
        assert_eq!(seen.lines().collect::<Vec<_>>(), expected);
    }

    #[test]
    fn the_first_failing_run_gives_the_one_violation() {
        let dir = tempfile::tempdir().expect("tempdir");
        let files = many_files();
        let fake = linter("echo run >> runs.txt; echo broken; exit 3 # {files}");
        let found = fake.run(dir.path(), &files).expect("runs").expect("fails");
        assert!(found.message.contains("exit 3"), "{}", found.message);
        assert!(
            found.message.contains("on 1500 file(s)"),
            "{}",
            found.message
        );
        assert_eq!(found.note.as_deref(), Some("broken"));
        let runs = std::fs::read_to_string(dir.path().join("runs.txt")).expect("runs.txt");
        assert_eq!(runs.lines().count(), 1, "{runs}");
    }

    #[test]
    fn a_command_without_files_runs_once() {
        let dir = tempfile::tempdir().expect("tempdir");
        let fake = linter("echo run >> runs.txt");
        assert!(fake.run(dir.path(), &many_files()).expect("runs").is_none());
        let runs = std::fs::read_to_string(dir.path().join("runs.txt")).expect("runs.txt");
        assert_eq!(runs.lines().count(), 1);
    }
}
