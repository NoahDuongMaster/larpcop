//! Resolves the layered configuration: CLI/env standards → `extends` chain → repo file.

mod fetch;
mod model;

pub use fetch::cache_root;
pub use model::{
    DependenciesConfig, ExtendSpec, LinterConfig, MaxLinesConfig, MetricsConfig, RawConfig,
    SecretsConfig, TaintConfig,
};

use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

pub const REPO_CONFIG: &str = ".agentkit.yaml";
const STANDARDS_CONFIG: [&str; 2] = ["agentkit.yaml", ".agentkit.yaml"];

/// Effective configuration after merging every layer.
#[derive(Debug, Default)]
pub struct Config {
    pub root: PathBuf,
    pub exclude: Vec<String>,
    pub max_lines: Option<MaxLinesConfig>,
    pub rule_dirs: Vec<PathBuf>,
    pub linters: Vec<LinterConfig>,
    pub disabled: BTreeSet<String>,
    /// rule id → layer that locked it
    pub locked: BTreeMap<String, String>,
    pub guidelines: Vec<String>,
    pub deps: DepsPolicy,
    /// Agents to generate files for; `None` = all.
    pub agents: Option<Vec<String>>,
    pub metrics: Option<MetricsConfig>,
    pub secrets: Option<SecretsConfig>,
    pub taint: Vec<TaintConfig>,
    /// Layers in application order, for traceability.
    pub sources: Vec<String>,
}

/// Merged `dependencies` settings; lists accumulate across layers.
#[derive(Debug, Default)]
pub struct DepsPolicy {
    pub min_release_age: Option<u32>,
    pub require_approval: bool,
    pub approved: Vec<String>,
    pub exempt: Vec<String>,
    pub vulnerabilities: Option<crate::deps::Severity>,
}

/// `forced` standards (from `--extends` / `AGENTKIT_EXTENDS`) apply first, so a repo
/// cannot opt out of them by editing or deleting its own config.
pub fn resolve(root: &Path, forced: &[String], refresh: bool) -> Result<Config> {
    let mut cfg = Config {
        root: root.to_path_buf(),
        ..Default::default()
    };
    let repo_file = root.join(REPO_CONFIG);
    let repo = if repo_file.is_file() {
        read_raw(&repo_file)?
    } else {
        RawConfig::default()
    };
    let mut seen = HashSet::new();
    // An empty AGENTKIT_EXTENDS (e.g. an unset CI input) means "nothing forced".
    let forced = forced
        .iter()
        .filter(|s| !s.trim().is_empty())
        .map(|s| ExtendSpec::parse(s));
    for spec in forced.chain(repo.extends.iter().cloned()) {
        apply_extend(&mut cfg, &spec, root, refresh, &mut seen)?;
    }
    cfg.apply(repo, root, REPO_CONFIG)?;
    Ok(cfg)
}

/// Rule directories declared by one standards directory (for `agentkit test DIR`).
pub fn rule_dirs_of(dir: &Path) -> Result<Vec<PathBuf>> {
    let file = STANDARDS_CONFIG
        .iter()
        .map(|name| dir.join(name))
        .find(|p| p.is_file())
        .with_context(|| format!("no agentkit.yaml in {}", dir.display()))?;
    Ok(read_raw(&file)?
        .rule_dirs
        .iter()
        .map(|d| dir.join(d))
        .collect())
}

fn read_raw(path: &Path) -> Result<RawConfig> {
    let text = fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    serde_saphyr::from_str(&text).with_context(|| format!("invalid config {}", path.display()))
}

/// Same standards reached twice (e.g. CI-forced and repo-declared) apply once;
/// the first occurrence wins, so the CI-pinned version takes precedence.
fn identity(spec: &ExtendSpec, base: &Path) -> String {
    match spec {
        ExtendSpec::Git { git, subdir, .. } => {
            format!("{git}//{}", subdir.as_deref().unwrap_or(""))
        }
        ExtendSpec::Path { path } => dunce::canonicalize(base.join(path))
            .map_or_else(|_| path.clone(), |p| p.display().to_string()),
        ExtendSpec::Short(_) => unreachable!("normalized before use"),
    }
}

fn apply_extend(
    cfg: &mut Config,
    spec: &ExtendSpec,
    base: &Path,
    refresh: bool,
    seen: &mut HashSet<String>,
) -> Result<()> {
    let spec = spec.normalized();
    if !seen.insert(identity(&spec, base)) {
        return Ok(());
    }
    let (dir, label) = match spec {
        ExtendSpec::Git {
            git,
            reference,
            subdir,
        } => {
            let checkout = fetch::git(&git, reference.as_deref(), refresh)?;
            let label = format!("{git}#{}", reference.as_deref().unwrap_or("HEAD"));
            (subdir.map_or(checkout.clone(), |s| checkout.join(s)), label)
        }
        ExtendSpec::Path { path } => (base.join(&path), path),
        ExtendSpec::Short(_) => unreachable!("normalized above"),
    };
    let dir =
        dunce::canonicalize(&dir).with_context(|| format!("standards `{label}` not found"))?;
    let file = STANDARDS_CONFIG
        .iter()
        .map(|name| dir.join(name))
        .find(|p| p.is_file())
        .with_context(|| format!("standards `{label}`: no agentkit.yaml in {}", dir.display()))?;
    let raw = read_raw(&file)?;
    for parent in &raw.extends {
        apply_extend(cfg, parent, &dir, refresh, seen)?;
    }
    cfg.apply(raw, &dir, &label)
}

impl Config {
    fn apply(&mut self, raw: RawConfig, dir: &Path, source: &str) -> Result<()> {
        for id in &raw.disable {
            self.ensure_unlocked(id, source, "disable")?;
        }
        if raw.max_lines.is_some() && self.max_lines.is_some() {
            self.ensure_unlocked(crate::rules::MAX_LINES_ID, source, "override")?;
        }
        for linter in &raw.linters {
            if self.linters.iter().any(|l| l.id == linter.id) {
                self.ensure_unlocked(&linter.id, source, "override")?;
            }
        }
        self.disabled.extend(raw.disable);
        if raw.max_lines.is_some() {
            self.max_lines = raw.max_lines;
        }
        for linter in raw.linters {
            self.linters.retain(|l| l.id != linter.id);
            self.linters.push(linter);
        }
        self.rule_dirs
            .extend(raw.rule_dirs.iter().map(|d| dir.join(d)));
        self.exclude.extend(raw.exclude);
        if let Some(rel) = raw.guidelines {
            let path = dir.join(rel);
            let text = fs::read_to_string(&path)
                .with_context(|| format!("{source}: reading guidelines {}", path.display()))?;
            // git autocrlf on Windows must not change the generated AGENTS.md.
            self.guidelines.push(text.replace("\r\n", "\n"));
        }
        if let Some(deps) = raw.dependencies {
            self.apply_deps(deps, source)?;
        }
        if raw.agents.is_some() {
            self.agents = raw.agents;
        }
        if let Some(m) = raw.metrics {
            if self.metrics.is_some() {
                use crate::rules::{COMPLEXITY_ID, LENGTH_ID};
                self.ensure_unlocked(COMPLEXITY_ID, source, "override")?;
                self.ensure_unlocked(LENGTH_ID, source, "override")?;
            }
            self.metrics = Some(m);
        }
        for rule in raw.taint {
            if self.taint.iter().any(|t| t.id == rule.id) {
                self.ensure_unlocked(&rule.id, source, "override")?;
            }
            self.taint.retain(|t| t.id != rule.id);
            self.taint.push(rule);
        }
        // Exclusions only accumulate; a locked `secrets` rule takes none.
        if let Some(s) = raw.secrets {
            if !s.exclude.is_empty() {
                self.ensure_unlocked(crate::rules::secrets::ID, source, "add exclusions to")?;
            }
            let cur = self.secrets.get_or_insert_with(SecretsConfig::default);
            cur.exclude.extend(s.exclude);
        }
        for id in raw.locked {
            self.locked.entry(id).or_insert_with(|| source.to_string());
        }
        self.sources.push(source.to_string());
        Ok(())
    }

    /// A locked dependency rule may still be tightened, never loosened. Approvals
    /// always accumulate: adding one is how a human approves a dependency.
    fn apply_deps(&mut self, d: DependenciesConfig, source: &str) -> Result<()> {
        use crate::deps::{AGE_ID, APPROVAL_ID};
        let p = &self.deps;
        if let Some(days) = d.min_release_age
            && p.min_release_age.is_some_and(|cur| days < cur)
        {
            self.ensure_unlocked(AGE_ID, source, "lower the minimum age of")?;
        }
        if !d.exempt.is_empty() {
            self.ensure_unlocked(AGE_ID, source, "add exemptions to")?;
        }
        if d.require_approval == Some(false) && p.require_approval {
            self.ensure_unlocked(APPROVAL_ID, source, "turn off")?;
        }
        let vulns = d
            .vulnerabilities
            .as_deref()
            .map(|s| {
                crate::deps::Severity::parse(s).with_context(|| {
                    format!("{source}: `vulnerabilities` must be low, moderate, high or critical, not `{s}`")
                })
            })
            .transpose()?;
        // A locked threshold can only go down (block more).
        if let (Some(new), Some(cur)) = (vulns, p.vulnerabilities)
            && new > cur
        {
            self.ensure_unlocked(crate::deps::VULN_ID, source, "raise the threshold of")?;
        }
        let p = &mut self.deps;
        if d.min_release_age.is_some() {
            p.min_release_age = d.min_release_age;
        }
        if let Some(on) = d.require_approval {
            p.require_approval = on;
        }
        p.approved.extend(d.approved);
        p.exempt.extend(d.exempt);
        if vulns.is_some() {
            p.vulnerabilities = vulns;
        }
        Ok(())
    }

    fn ensure_unlocked(&self, id: &str, source: &str, action: &str) -> Result<()> {
        if let Some(owner) = self.locked.get(id) {
            bail!("{source}: cannot {action} rule `{id}`: it is locked by `{owner}`");
        }
        Ok(())
    }
}
