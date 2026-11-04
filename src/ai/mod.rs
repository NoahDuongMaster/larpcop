//! AI review and rule learning. The model is whatever CLI the team already
//! uses (`claude -p`, `codex exec -`, `gemini`, `ollama run …`): larpcop sends
//! a prompt on stdin and reads stdout, so it holds no API key and no vendor SDK.

pub mod learn;
pub mod review;
mod run;
mod sources;

use crate::config::{LlmCommand, LlmConfig};
use anyhow::{Context, Result, bail};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

pub struct Llm {
    argv: Vec<String>,
    cache: Option<PathBuf>,
    /// How long one call may take before the model is killed.
    timeout: Duration,
}

/// CLIs tried in order when `llm.command` is not set.
const DEFAULTS: [&[&str]; 2] = [&["claude", "-p"], &["codex", "exec", "-"]];

impl Llm {
    pub fn new(cfg: &LlmConfig) -> Result<Self> {
        let shell = |s: &str| {
            let sh = crate::shell::posix_shell().to_string_lossy().into_owned();
            vec![sh, "-c".to_string(), s.to_string()]
        };
        let argv: Vec<String> = match (&cfg.command, std::env::var("LARPCOP_LLM")) {
            (_, Ok(env)) if !env.trim().is_empty() => shell(&env),
            (Some(LlmCommand::Shell(s)), _) => shell(s),
            (Some(LlmCommand::Argv(a)), _) if !a.is_empty() => a.clone(),
            _ => DEFAULTS
                .iter()
                .find(|c| crate::shell::which(c[0]).is_file())
                .map(|c| c.iter().map(|s| s.to_string()).collect())
                .context(
                    "no model CLI found: set `llm.command` (e.g. [claude, -p]) or LARPCOP_LLM",
                )?,
        };
        let cache = crate::config::cache_root().ok().map(|d| d.join("llm"));
        Ok(Self {
            argv,
            cache,
            timeout: run::timeout()?,
        })
    }

    pub fn name(&self) -> String {
        self.argv.join(" ")
    }

    fn cache_path(&self, prompt: &str) -> Option<PathBuf> {
        let mut h = DefaultHasher::new();
        (&self.argv, prompt).hash(&mut h);
        let key = format!("{:016x}", h.finish());
        self.cache.as_ref().map(|d| d.join(key))
    }

    /// Drops the cached answer to `prompt`, e.g. one that turned out unusable.
    pub fn forget(&self, prompt: &str) {
        let Some(path) = self.cache_path(prompt) else {
            return;
        };
        if let Err(e) = std::fs::remove_file(&path)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            eprintln!(
                "larpcop: cannot drop the cached answer {}: {e}",
                path.display()
            );
        }
    }

    /// The model's answer. Identical prompts are answered from the cache, so a
    /// re-run on unchanged code gives the same result and costs nothing.
    pub fn ask(&self, prompt: &str, cached: bool) -> Result<String> {
        let path = self.cache_path(prompt);
        if cached && let Some(hit) = path.as_ref().and_then(|p| std::fs::read_to_string(p).ok()) {
            return Ok(hit);
        }
        // Outside the repository: the model's CLI must not pick up the project's
        // hooks (larpcop's own) or edit files.
        let cwd = tempfile::tempdir().context("creating a scratch directory for the model")?;
        let child = Command::new(&self.argv[0])
            .args(&self.argv[1..])
            .current_dir(cwd.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("running `{}`", self.name()))?;
        let out = run::run(child, prompt, self.timeout, &self.name())?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            bail!("`{}` failed ({}): {}", self.name(), out.status, err.trim());
        }
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        if let Some(p) = &path {
            let dir = p.parent().unwrap_or(Path::new("."));
            if let Err(e) = std::fs::create_dir_all(dir).and_then(|()| std::fs::write(p, &text)) {
                eprintln!(
                    "larpcop: cannot cache the model's answer in {}: {e}",
                    p.display()
                );
            }
        }
        Ok(text)
    }
}

/// The JSON value in a model's answer, which may wrap it in prose or a fence.
pub fn extract_json(text: &str) -> Option<serde_json::Value> {
    let start = text.find(['[', '{'])?;
    let close = if text[start..].starts_with('[') {
        ']'
    } else {
        '}'
    };
    let end = text.rfind(close)?;
    serde_json::from_str(text.get(start..=end)?).ok()
}

#[cfg(test)]
mod tests {
    #[test]
    fn json_inside_prose_and_fences() {
        let a = super::extract_json("Here:\n```json\n[{\"line\": 3}]\n```\nDone.").unwrap();
        assert_eq!(a[0]["line"], 3);
        assert!(super::extract_json("no findings").is_none());
    }
}
