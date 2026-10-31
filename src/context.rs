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
    /// Known violations hidden by `.agentkit-baseline.json`.
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

/// Nearest ancestor holding `.agentkit.yaml`, else the git top-level, else `start`.
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
