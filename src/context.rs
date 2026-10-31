//! Locates the project root and runs a full check.

use crate::baseline::{self, Baseline};
use crate::config::{self, Config, REPO_CONFIG};
use crate::files::{self, Scope};
use crate::rules::{Engine, Level, Violation};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Options shared by every command (CLI flags, env, hook input).
pub struct Ctx {
    pub root: PathBuf,
    pub extends: Vec<String>,
    pub refresh: bool,
}

#[derive(Default)]
pub struct Outcome {
    pub files: usize,
    pub violations: Vec<Violation>,
    /// No config and no forced standards: nothing is enforced here.
    pub unconfigured: bool,
    /// Known violations hidden by `.larpcop-baseline.json`.
    pub baselined: usize,
}

impl Outcome {
    pub fn errors(&self) -> usize {
        self.violations
            .iter()
            .filter(|v| v.level == Level::Error)
            .count()
    }
}

impl Ctx {
    pub fn new(start: &Path, extends: Vec<String>, refresh: bool) -> Result<Self> {
        Ok(Self {
            root: find_root(start)?,
            extends,
            refresh,
        })
    }

    pub fn load(&self) -> Result<(Config, Engine)> {
        let cfg = config::resolve(&self.root, &self.extends, self.refresh)?;
        let engine = Engine::new(&cfg)?;
        Ok((cfg, engine))
    }

    /// Every violation in scope, before the baseline is applied.
    pub fn raw(&self, cfg: &Config, engine: &Engine, scope: &Scope) -> Result<Outcome> {
        let exclude = files::globset(&cfg.exclude)?;
        let files = files::collect(&cfg.root, scope, &exclude)?;
        let mut violations = engine.check(&cfg.root, &files)?;
        if let Some(deps) = engine.deps() {
            violations.extend(deps.check(&cfg.root, scope)?);
        }
        crate::rules::sort(&mut violations);
        Ok(Outcome {
            files: files.len(),
            violations,
            ..Outcome::default()
        })
    }

    /// The buffer as a source file of this project, unless excluded or unconfigured.
    fn buffer(
        &self,
        path: &Path,
        content: &str,
    ) -> Result<Option<(Config, Engine, files::SourceFile)>> {
        let (cfg, engine) = self.load()?;
        let rel = files::rel_of_new(&cfg.root, path).unwrap_or_default();
        let exclude = files::globset(&cfg.exclude)?;
        if engine.is_empty() || rel.is_empty() || exclude.is_match(&rel) {
            return Ok(None);
        }
        let file = files::SourceFile {
            rel,
            content: content.to_string(),
        };
        Ok(Some((cfg, engine, file)))
    }

    /// Every violation in content that is not on disk (an editor buffer).
    pub fn check_buffer(&self, path: &Path, content: &str) -> Result<Outcome> {
        let Some((cfg, engine, file)) = self.buffer(path, content)? else {
            return Ok(Outcome::default());
        };
        let mut outcome = Outcome {
            files: 1,
            violations: engine.check_source(&file),
            ..Outcome::default()
        };
        if let Some(known) = Baseline::load(&cfg.root, false)? {
            outcome.baselined = known.apply(&mut outcome.violations);
        }
        Ok(outcome)
    }

    /// The buffer with every rule fix applied; `None` when nothing changes.
    pub fn fix_buffer(&self, path: &Path, content: &str) -> Result<Option<String>> {
        let Some((_, engine, file)) = self.buffer(path, content)? else {
            return Ok(None);
        };
        Ok(engine.fix(&[file]).pop().map(|(_, text, _)| text))
    }

    /// Checks a write an agent is about to make. Only what it adds is reported:
    /// a partial fix of a file that is already broken must go through (seen
    /// live: Kiro could not swap `any` for `unknown` on a line that still had `console`).
    pub fn check_content(&self, path: &Path, content: &str) -> Result<Outcome> {
        let mut outcome = self.check_buffer(path, content)?;
        let Ok(before) = std::fs::read_to_string(path) else {
            return Ok(outcome);
        };
        let before = self.check_buffer(path, &before)?.violations;
        let count = |v: &[Violation], rule: &str| v.iter().filter(|x| x.rule == rule).count();
        let grown: Vec<String> = outcome
            .violations
            .iter()
            .map(|v| v.rule.clone())
            .filter(|r| count(&outcome.violations, r) > count(&before, r))
            .collect();
        outcome.violations.retain(|v| grown.contains(&v.rule));
        Ok(outcome)
    }

    pub fn check(&self, scope: &Scope) -> Result<Outcome> {
        let (cfg, engine) = self.load()?;
        if engine.is_empty() {
            return Ok(Outcome {
                unconfigured: true,
                ..Outcome::default()
            });
        }
        let mut outcome = self.raw(&cfg, &engine, scope)?;
        let staged = matches!(scope, Scope::Staged);
        if let Some(known) = Baseline::load(&cfg.root, staged)? {
            outcome.baselined = known.apply(&mut outcome.violations);
            let before = files::base(&cfg.root, scope)
                .filter(|_| !matches!(scope, Scope::All | Scope::Paths(_)))
                .and_then(|rev| files::show(&cfg.root, &rev, baseline::FILE));
            if let Some(before) = before {
                let before = Baseline::parse(&before).unwrap_or_default();
                outcome.violations.extend(known.grown(&before, &cfg.locked));
            }
        }
        Ok(outcome)
    }
}

/// Nearest ancestor holding `.larpcop.yaml`, else the git top-level, else `start`.
/// `dunce` avoids Windows `\\?\` verbatim paths, which break prefix matching and some tools.
pub fn find_root(start: &Path) -> Result<PathBuf> {
    let start = dunce::canonicalize(start)
        .with_context(|| format!("{} does not exist", start.display()))?;
    if let Some(dir) = start.ancestors().find(|d| d.join(REPO_CONFIG).is_file()) {
        return Ok(dir.to_path_buf());
    }
    let top = Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(&start)
        .output();
    match top {
        Ok(out) if out.status.success() => Ok(dunce::canonicalize(
            String::from_utf8_lossy(&out.stdout).trim(),
        )?),
        _ => Ok(start),
    }
}
