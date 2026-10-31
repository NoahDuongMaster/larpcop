#![allow(dead_code)]

pub mod deps;

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use tempfile::TempDir;

pub const BIN: &str = env!("CARGO_BIN_EXE_larpcop");
pub const STANDARDS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/examples/standards");

pub const BAD_TS: &str = "export function f(x: any) {\n  console.log(x);\n}\n";
pub const GOOD_TS: &str = "export function f(x: string): string {\n  return x.trim();\n}\n";

pub struct Repo {
    pub tmp: TempDir,
}

impl Repo {
    /// Empty git repo with an identity, isolated from the user's config and cache.
    pub fn new() -> Self {
        let repo = Self {
            tmp: tempfile::tempdir().unwrap(),
        };
        repo.git(&["init", "-q", "-b", "main"]);
        repo.git(&["config", "user.email", "test@example.com"]);
        repo.git(&["config", "user.name", "test"]);
        repo
    }

    /// Repo whose config extends the example company standards.
    pub fn with_standards() -> Self {
        let repo = Self::new();
        repo.write(".larpcop.yaml", &extends_yaml(STANDARDS));
        repo
    }

    /// Canonical without Windows `\\?\` prefix, matching what larpcop reports.
    pub fn path(&self) -> PathBuf {
        dunce::canonicalize(self.tmp.path()).unwrap()
    }

    pub fn write(&self, rel: &str, content: &str) {
        let path = self.tmp.path().join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }

    pub fn read(&self, rel: &str) -> String {
        fs::read_to_string(self.tmp.path().join(rel)).unwrap()
    }

    pub fn git(&self, args: &[&str]) -> Output {
        Command::new("git")
            .args(args)
            .current_dir(self.tmp.path())
            .output()
            .unwrap()
    }

    pub fn commit_all(&self, msg: &str) -> Output {
        self.git(&["add", "-A"]);
        self.git(&["commit", "-q", "-m", msg])
    }

    fn command(&self, program: &str) -> Command {
        let mut cmd = Command::new(program);
        let bin_dir = Path::new(BIN).parent().unwrap().to_path_buf();
        let inherited = std::env::var_os("PATH").unwrap_or_default();
        let path =
            std::env::join_paths(std::iter::once(bin_dir).chain(std::env::split_paths(&inherited)))
                .unwrap();
        cmd.current_dir(self.tmp.path())
            .env("PATH", path)
            .env("LARPCOP_CACHE_DIR", self.tmp.path().join(".cache-larpcop"))
            // Tests never reach deps.dev: publish dates come from `seed_published`.
            .env("LARPCOP_DEPS_API", "offline://deps.dev")
            .env_remove("LARPCOP_EXTENDS");
        cmd
    }

    /// Caches `version`'s publish date as `days_ago` days back, the way a
    /// deps.dev lookup would.
    pub fn seed_published(&self, system: &str, name: &str, version: &str, days_ago: i64) {
        let encoded: String = format!("{name}@{version}")
            .bytes()
            .map(|b| {
                if b.is_ascii_alphanumeric() {
                    (b as char).to_string()
                } else {
                    format!("%{b:02X}")
                }
            })
            .collect();
        let at = jiff::Timestamp::now() - jiff::SignedDuration::from_hours(days_ago * 24);
        let rel = format!(".cache-larpcop/published/{system}/{encoded}");
        self.write(&rel, &at.to_string());
    }

    pub fn run(&self, args: &[&str]) -> Run {
        Run(self.command(BIN).args(args).output().unwrap())
    }

    pub fn run_env(&self, args: &[&str], env: &[(&str, &str)]) -> Run {
        let mut cmd = self.command(BIN);
        cmd.args(args);
        for (k, v) in env {
            cmd.env(k, v);
        }
        Run(cmd.output().unwrap())
    }

    pub fn run_stdin(&self, args: &[&str], stdin: &str) -> Run {
        self.run_stdin_env(args, stdin, &[])
    }

    pub fn run_stdin_env(&self, args: &[&str], stdin: &str, env: &[(&str, &str)]) -> Run {
        let mut cmd = self.command(BIN);
        for (k, v) in env {
            cmd.env(k, v);
        }
        let mut child = cmd
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(stdin.as_bytes())
            .unwrap();
        Run(child.wait_with_output().unwrap())
    }

    /// `git commit` with the repo's hooks active and larpcop on PATH.
    pub fn git_commit(&self, msg: &str) -> Run {
        Run(self
            .command("git")
            .args(["commit", "-q", "-m", msg])
            .output()
            .unwrap())
    }
}

pub struct Run(pub Output);

impl Run {
    pub fn code(&self) -> i32 {
        self.0.status.code().unwrap_or(-1)
    }
    pub fn stdout(&self) -> String {
        String::from_utf8_lossy(&self.0.stdout).into_owned()
    }
    pub fn stderr(&self) -> String {
        String::from_utf8_lossy(&self.0.stderr).into_owned()
    }
}

pub fn hook_input(event: &str, tool: &str, cwd: &Path, tool_input: serde_json::Value) -> String {
    serde_json::json!({
        "session_id": "test",
        "hook_event_name": event,
        "tool_name": tool,
        "tool_input": tool_input,
        "cwd": cwd,
    })
    .to_string()
}

/// Single-quoted so Windows paths (`C:\...`) stay literal YAML scalars.
pub fn extends_yaml(spec: &str) -> String {
    format!("extends:\n  - '{spec}'\n")
}

/// `file://` URL git accepts on every OS (`file:///C:/...` on Windows).
pub fn file_url(path: &Path) -> String {
    let p = path.display().to_string().replace('\\', "/");
    if p.starts_with('/') {
        format!("file://{p}")
    } else {
        format!("file:///{p}")
    }
}

pub fn copy_dir(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).unwrap();
    for entry in fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let target = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}
