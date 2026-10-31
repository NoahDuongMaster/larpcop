//! `larpcop dashboard`: one self-contained HTML page (or JSON) with what is
//! open per rule, the baseline debt and its trend, complexity hotspots, and,
//! with `--org`, which repositories actually run the gate.

mod html;

use crate::baseline::{self, Baseline};
use crate::context::Ctx;
use crate::files::{self, Scope};
use crate::rules::Level;
use crate::rules::metrics::{self, Summary};
use anyhow::Result;
use serde::Serialize;
use std::collections::BTreeMap;
use std::process::Command;

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
    let outcome = ctx.check(&Scope::All)?;
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
            baselined: per_rule.get(&r.id).copied().unwrap_or(0),
            id: r.id,
            level: r.level,
            message: r.message,
        })
        .collect();
    rules.sort_by_key(|r| std::cmp::Reverse((r.open, r.baselined)));
    let sources = files::collect(&cfg.root, &Scope::All, &files::globset(&cfg.exclude)?)?;
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
        debt: debt(&cfg.root),
        metrics: metrics::summarize(&sources, 15),
        org,
    })
}

pub fn render(d: &Dashboard) -> String {
    html::page(d)
}

/// Size of `.larpcop-baseline.json` at the last 60 commits that changed it.
fn debt(root: &std::path::Path) -> Vec<DebtPoint> {
    let out = Command::new("git")
        .args(["log", "-n", "60", "--format=%H %cs", "--", baseline::FILE])
        .current_dir(root)
        .output();
    let Ok(out) = out else { return Vec::new() };
    let mut points: Vec<DebtPoint> = String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| {
            let (commit, date) = l.split_once(' ')?;
            let entries = files::show(root, commit, baseline::FILE)
                .and_then(|t| Baseline::parse(&t).ok())
                .map_or(0, |b| b.len());
            Some(DebtPoint {
                date: date.into(),
                commit: commit[..7.min(commit.len())].into(),
                entries,
            })
        })
        .collect();
    points.reverse();
    points
}
