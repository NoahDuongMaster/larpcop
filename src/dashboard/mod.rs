//! `larpcop dashboard`: one self-contained HTML page (or JSON) with what is
//! open per rule, the baseline debt and its trend, complexity hotspots, and,
//! with `--org`, which repositories actually run the gate.

mod html;

use crate::baseline::{self, Baseline};
use crate::context::Ctx;
use crate::files::{self, Scope};
use crate::rules::Level;
use crate::rules::metrics::{self, Summary};
use anyhow::{Context, Result};
use serde::Serialize;
use std::collections::BTreeMap;
use std::path::Path;

#[derive(Serialize)]
pub struct Dashboard {
    pub repo: String,
    pub generated: String,
    pub files: usize,
    pub errors: usize,
    pub warnings: usize,
    pub baselined: usize,
    pub rules: Vec<RuleRow>,
    /// Baseline size at each commit that changed it, oldest first.
    pub debt: Vec<DebtPoint>,
    pub metrics: Summary,
    pub org: Option<Vec<crate::org::Status>>,
}

#[derive(Serialize)]
pub struct RuleRow {
    pub id: String,
    pub level: Level,
    pub message: String,
    pub open: usize,
    pub baselined: usize,
}

#[derive(Serialize)]
pub struct DebtPoint {
    pub date: String,
    pub commit: String,
    pub entries: usize,
}

pub fn build(ctx: &Ctx, org: Option<&str>) -> Result<Dashboard> {
    let (cfg, engine) = ctx.load()?;
    let (outcome, read) = ctx.check_with(&cfg, &engine, &Scope::All)?;
    let known = Baseline::load(&cfg.root, false)?.unwrap_or_default();
    let per_rule = known.per_rule();
    let mut open: BTreeMap<&str, usize> = BTreeMap::new();
    for v in &outcome.violations {
        *open.entry(v.rule.as_str()).or_default() += 1;
    }
    let mut rules: Vec<RuleRow> = engine
        .rules()
        .into_iter()
        .map(|r| RuleRow {
            open: open.get(r.id.as_str()).copied().unwrap_or(0),
            baselined: per_rule.get(r.id.as_str()).copied().unwrap_or(0),
            id: r.id,
            level: r.level,
            message: r.message,
        })
        .collect();
    rules.sort_by_key(|r| std::cmp::Reverse((r.open, r.baselined)));
    // Nothing is read for a project without rules, but its metrics still count.
    let sources = if outcome.unconfigured {
        files::collect(&cfg.root, &Scope::All, &files::globset(&cfg.exclude)?)?
    } else {
        read
    };
    let org = org.map(crate::org::status).transpose()?;
    let count = |l: Level| outcome.violations.iter().filter(|v| v.level == l).count();
    Ok(Dashboard {
        repo: cfg
            .root
            .file_name()
            .map_or_else(String::new, |n| n.to_string_lossy().into_owned()),
        generated: jiff::Timestamp::now()
            .strftime("%Y-%m-%d %H:%M UTC")
            .to_string(),
        files: outcome.files,
        errors: count(Level::Error),
        warnings: count(Level::Warning),
        baselined: outcome.baselined,
        rules,
        debt: debt(&cfg.root)?,
        metrics: metrics::summarize(&sources, 15),
        org,
    })
}

pub fn render(d: &Dashboard) -> String {
    html::page(d)
}

/// Size of `.larpcop-baseline.json` at the last 60 commits that changed it.
fn debt(root: &Path) -> Result<Vec<DebtPoint>> {
    // No history yet: nothing to plot.
    if !files::in_repo(root) || files::base(root, &Scope::Changed).is_none() {
        return Ok(Vec::new());
    }
    let log = files::git(
        root,
        &["log", "-n", "60", "--format=%H %cs", "--", baseline::FILE],
    )?;
    let log = String::from_utf8_lossy(&log);
    let commits: Vec<(&str, &str)> = log.lines().filter_map(|l| l.split_once(' ')).collect();
    let specs: Vec<String> = commits
        .iter()
        .map(|(commit, _)| format!("{commit}:./{}", baseline::FILE))
        .collect();
    let mut points = Vec::with_capacity(commits.len());
    for ((commit, date), blob) in commits.iter().zip(files::blobs(root, &specs)?) {
        // The commit that deleted the baseline leaves no debt.
        let entries = match blob {
            Some(bytes) => {
                let text = String::from_utf8(bytes)
                    .with_context(|| format!("{} at commit {commit}", baseline::FILE))?;
                Baseline::parse(&text)
                    .with_context(|| format!("{} at commit {commit}", baseline::FILE))?
                    .len()
            }
            None => 0,
        };
        points.push(DebtPoint {
            date: (*date).into(),
            commit: commit[..7.min(commit.len())].into(),
            entries,
        });
    }
    points.reverse();
    Ok(points)
}
