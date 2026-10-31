//! AI review and rule learning. The model is whatever CLI the team already
//! uses (`claude -p`, `codex exec -`, `gemini`, `ollama run …`): agentkit sends
//! a prompt on stdin and reads stdout, so it holds no API key and no vendor SDK.

pub mod learn;
pub mod review;
mod sources;

use crate::config::{LlmCommand, LlmConfig};
use anyhow::{Context, Result, bail};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub struct Llm {
    argv: Vec<String>,
    cache: Option<PathBuf>,
}

/// CLIs tried in order when `llm.command` is not set.
const DEFAULTS: [&[&str]; 2] = [&["claude", "-p"], &["codex", "exec", "-"]];

impl Llm {
    pub fn new(cfg: &LlmConfig) -> Result<Self> {
        let shell = |s: &str| {
            let sh = crate::shell::posix_shell().to_string_lossy().into_owned();
            vec![sh, "-c".to_string(), s.to_string()]
        };
        let argv: Vec<String> = match (&cfg.command, std::env::var("AGENTKIT_LLM")) {
            (_, Ok(env)) if !env.trim().is_empty() => shell(&env),
            (Some(LlmCommand::Shell(s)), _) => shell(s),
            (Some(LlmCommand::Argv(a)), _) if !a.is_empty() => a.clone(),
            _ => DEFAULTS
                .iter()
                .find(|c| on_path(c[0]))
                .map(|c| c.iter().map(|s| s.to_string()).collect())
                .context(
                    "no model CLI found: set `llm.command` (e.g. [claude, -p]) or AGENTKIT_LLM",
                )?,
        };
        let cache = std::env::var_os("AGENTKIT_CACHE_DIR")
            .map(PathBuf::from)
            .or_else(|| dirs::cache_dir().map(|d| d.join("agentkit")))
            .map(|d| d.join("llm"));
        Ok(Self { argv, cache })
    }

    pub fn name(&self) -> String {
        self.argv.join(" ")
    }

    /// The model's answer. Identical prompts are answered from the cache, so a
    /// re-run on unchanged code gives the same result and costs nothing.
    pub fn ask(&self, prompt: &str, cached: bool) -> Result<String> {
        let key = {
            let mut h = DefaultHasher::new();
            (&self.argv, prompt).hash(&mut h);
            format!("{:016x}", h.finish())
        };
        let path = self.cache.as_ref().map(|d| d.join(&key));
        if cached && let Some(hit) = path.as_ref().and_then(|p| std::fs::read_to_string(p).ok()) {
            return Ok(hit);
        }
        // Outside the repository: the model's CLI must not pick up the project's
        // hooks (agentkit's own) or edit files.
        let cwd = std::env::temp_dir().join("agentkit-llm");
        std::fs::create_dir_all(&cwd)?;
        let mut child = Command::new(&self.argv[0])
            .args(&self.argv[1..])
            .current_dir(&cwd)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("running `{}`", self.name()))?;
        child
            .stdin
            .take()
            .context("stdin")?
            .write_all(prompt.as_bytes())?;
        let out = child.wait_with_output()?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            bail!("`{}` failed ({}): {}", self.name(), out.status, err.trim());
        }
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        if let Some(p) = &path {
            let _ = std::fs::create_dir_all(p.parent().unwrap_or(Path::new(".")));
            let _ = std::fs::write(p, &text);
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

fn on_path(bin: &str) -> bool {
    let exts: &[&str] = if cfg!(windows) {
        &["", ".exe", ".cmd"]
    } else {
        &[""]
    };
    std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths)
            .any(|d| exts.iter().any(|e| d.join(format!("{bin}{e}")).is_file()))
    })
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
