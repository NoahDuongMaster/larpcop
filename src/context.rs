//! Locates the project root and runs a full check.

use crate::baseline::{self, Baseline};
use crate::config::{self, Config, REPO_CONFIG};
use crate::files::{self, Scope};
use crate::rules::{Engine, Level, Violation};
use anyhow::{Context, Result};
use std::collections::{HashMap, HashSet};
use std::io::ErrorKind::{InvalidData, IsADirectory, NotFound};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, OnceLock};

/// Options shared by every command (CLI flags, env, hook input), and what they
/// resolve to: loaded once, then reused by every check made through this value.
pub struct Ctx {
    pub root: PathBuf,
    pub extends: Vec<String>,
    pub refresh: bool,
    config: OnceLock<Arc<Config>>,
    engine: OnceLock<Arc<Engine>>,
    baseline: OnceLock<Option<Baseline>>,
}

/// A buffer as a source file, with the configuration and engine that judge it.
type Buffer = (Arc<Config>, Arc<Engine>, files::SourceFile);

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
            config: OnceLock::new(),
            engine: OnceLock::new(),
            baseline: OnceLock::new(),
        })
    }

    /// The resolved configuration alone: callers that never run a rule skip the
    /// cost of building the engine (parsing every rule file).
    pub fn config(&self) -> Result<&Config> {
        Ok(self.resolved()?)
    }

    fn resolved(&self) -> Result<&Arc<Config>> {
        if let Some(cfg) = self.config.get() {
            return Ok(cfg);
        }
        let cfg = config::resolve(&self.root, &self.extends, self.refresh)?;
        Ok(self.config.get_or_init(|| Arc::new(cfg)))
    }

    /// The configuration and the engine built from it, built once per `Ctx`.
    pub fn load(&self) -> Result<(Arc<Config>, Arc<Engine>)> {
        let cfg = self.resolved()?;
        let engine = match self.engine.get() {
            Some(engine) => engine,
            None => {
                let engine = Engine::new(cfg)?;
                self.engine.get_or_init(|| Arc::new(engine))
            }
        };
        Ok((Arc::clone(cfg), Arc::clone(engine)))
    }

    /// The worktree baseline, read once per `Ctx`.
    fn baseline(&self, cfg: &Config) -> Result<Option<&Baseline>> {
        if let Some(known) = self.baseline.get() {
            return Ok(known.as_ref());
        }
        let known = Baseline::load(&cfg.root, false)?;
        Ok(self.baseline.get_or_init(|| known).as_ref())
    }

    /// Every violation in scope, before the baseline is applied, and the files
    /// that were read to find them.
    pub fn raw(
        &self,
        cfg: &Config,
        engine: &Engine,
        scope: &Scope,
    ) -> Result<(Outcome, Vec<files::SourceFile>)> {
        let exclude = files::globset(&cfg.exclude)?;
        let listed = files::list(&cfg.root, scope)?;
        let files = files::collect_listed(&cfg.root, scope, &exclude, &listed)?;
        let mut violations = engine.check(&cfg.root, &files)?;
        if let Some(deps) = engine.deps() {
            violations.extend(deps.check_listed(&cfg.root, scope, &listed)?);
        }
        crate::rules::sort(&mut violations);
        let outcome = Outcome {
            files: files.len(),
            violations,
            ..Outcome::default()
        };
        Ok((outcome, files))
    }

    /// The buffer as a source file of this project, unless excluded or unconfigured.
    fn buffer(&self, path: &Path, content: &str) -> Result<Option<Buffer>> {
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
        if let Some(known) = self.baseline(&cfg)? {
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
        let Some((cfg, engine, file)) = self.buffer(path, content)? else {
            return Ok(Outcome::default());
        };
        let known = self.baseline(&cfg)?;
        let check = |f: &files::SourceFile| {
            let mut v = engine.check_source(f);
            let baselined = known.map_or(0, |k| k.apply(&mut v));
            (v, baselined)
        };
        let (mut violations, baselined) = check(&file);
        // A file that is new, binary or a directory has nothing to compare with.
        let before = if violations.is_empty() {
            None
        } else {
            match std::fs::read_to_string(path) {
                Ok(text) => Some(text),
                Err(e) if matches!(e.kind(), NotFound | InvalidData | IsADirectory) => None,
                Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
            }
        };
        if let Some(before) = before {
            let (before, _) = check(&files::SourceFile {
                rel: file.rel,
                content: before,
            });
            fn per_rule(found: &[Violation]) -> HashMap<&str, usize> {
                let mut counts = HashMap::new();
                for v in found {
                    *counts.entry(v.rule.as_str()).or_default() += 1;
                }
                counts
            }
            let was = per_rule(&before);
            let grown: HashSet<String> = per_rule(&violations)
                .into_iter()
                .filter(|(rule, n)| *n > was.get(rule).copied().unwrap_or(0))
                .map(|(rule, _)| rule.to_string())
                .collect();
            violations.retain(|v| grown.contains(&v.rule));
        }
        Ok(Outcome {
            files: 1,
            violations,
            baselined,
            ..Outcome::default()
        })
    }

    pub fn check(&self, scope: &Scope) -> Result<Outcome> {
        let (cfg, engine) = self.load()?;
        Ok(self.check_with(&cfg, &engine, scope)?.0)
    }

    /// `check` with the configuration already loaded; also returns the files that
    /// were read, so a caller that needs them does not read the repository again.
    pub fn check_with(
        &self,
        cfg: &Config,
        engine: &Engine,
        scope: &Scope,
    ) -> Result<(Outcome, Vec<files::SourceFile>)> {
        if engine.is_empty() {
            let unconfigured = Outcome {
                unconfigured: true,
                ..Outcome::default()
            };
            return Ok((unconfigured, Vec::new()));
        }
        let (mut outcome, sources) = self.raw(cfg, engine, scope)?;
        let staged = matches!(scope, Scope::Staged);
        if let Some(known) = Baseline::load(&cfg.root, staged)? {
            outcome.baselined = known.apply(&mut outcome.violations);
            let rev = files::base(&cfg.root, scope)
                .filter(|_| !matches!(scope, Scope::All | Scope::Paths(_) | Scope::Touched(_)));
            if let Some(rev) = rev
                && let Some(text) = files::show(&cfg.root, &rev, baseline::FILE)
            {
                let before = Baseline::parse(&text)
                    .with_context(|| format!("{} at the base commit {rev}", baseline::FILE))?;
                outcome.violations.extend(known.grown(&before, &cfg.locked));
            }
        }
        Ok((outcome, sources))
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
