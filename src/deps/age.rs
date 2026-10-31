//! `dependency-release-age`: lockfile entries new in this change must be old enough.

use super::ecosystem::Pinned;
use super::lockfile;
use super::registry::Registry;
use super::{AGE_ID, Deps, View, unreadable};
use crate::rules::{Level, Violation};
use anyhow::Result;
use jiff::{SignedDuration, Timestamp};
use rayon::prelude::*;
use std::collections::BTreeSet;

/// A lockfile entry that this change adds or moves to another version.
pub(super) struct Fresh {
    rel: String,
    line: usize,
    pin: Pinned,
}

impl Deps {
    pub(super) fn fresh_pins(
        &self,
        rel: &str,
        name: &str,
        view: &View,
        out: &mut Vec<Violation>,
    ) -> Vec<Fresh> {
        let Some(content) = view.current(rel) else {
            return Vec::new();
        };
        let pins = match view.pins(rel, name, &content) {
            Some(Ok(p)) => p,
            Some(Err(e)) => {
                out.push(unreadable(rel, AGE_ID, &e));
                return Vec::new();
            }
            None => return Vec::new(),
        };
        let before: BTreeSet<Pinned> = view
            .old(rel)
            .and_then(|old| view.pins(rel, name, &old)?.ok())
            .unwrap_or_default()
            .into_iter()
            .collect();
        let mut seen = BTreeSet::new();
        pins.into_iter()
            .filter(|p| {
                !before.contains(p)
                    && !self.exempt.matches(p.eco, &p.name)
                    && seen.insert(p.clone())
            })
            .map(|pin| Fresh {
                rel: rel.to_string(),
                line: lockfile::line_of(name, &content, &pin),
                pin,
            })
            .collect()
    }
}

pub(super) fn too_new(days: u32, fresh: &[Fresh]) -> Result<Vec<Violation>> {
    if fresh.is_empty() {
        return Ok(Vec::new());
    }
    let registry = Registry::new();
    let now = Timestamp::now();
    let cutoff = now.checked_sub(SignedDuration::from_hours(i64::from(days) * 24))?;
    // Lookups wait on the network, not the CPU: use many more threads than cores.
    let pool = rayon::ThreadPoolBuilder::new().num_threads(32).build()?;
    Ok(pool.install(|| {
        fresh
            .par_iter()
            .filter_map(|f| judge(&registry, f, days, now, cutoff))
            .collect()
    }))
}

fn judge(
    registry: &Registry,
    f: &Fresh,
    days: u32,
    now: Timestamp,
    cutoff: Timestamp,
) -> Option<Violation> {
    let p = &f.pin;
    let (level, message, note) = match registry.published(p) {
        Ok(Some(t)) if t <= cutoff => return None,
        Ok(Some(t)) => too_young(registry, p, days, now.duration_since(t), cutoff),
        Ok(None) => (
            Level::Error,
            format!(
                "`{p}` ({}): deps.dev has no publish date for this version.",
                p.eco
            ),
            "Usually it was released in the last few hours: treat it as too new and use an older \
version. If it comes from a private registry, ask the user to add it to `dependencies.exempt`."
                .to_string(),
        ),
        Err(e) => (
            Level::Error,
            format!(
                "`{p}` ({}): could not look up its publish date: {e:#}",
                p.eco
            ),
            "This check fails closed. Retry once deps.dev is reachable; do not work around it."
                .to_string(),
        ),
    };
    Some(Violation {
        rule: AGE_ID.into(),
        level,
        file: f.rel.clone(),
        line: f.line,
        column: usize::from(f.line > 0),
        message,
        note: Some(note),
        snippet: None,
    })
}

/// A young version is an error — unless the newest release old enough is known to
/// be vulnerable and this one is not: then this is the security fix, and holding it
/// back for the age rule would be the worse risk.
fn too_young(
    registry: &Registry,
    p: &Pinned,
    days: u32,
    age: SignedDuration,
    cutoff: Timestamp,
) -> (Level, String, String) {
    let older = registry.newest_before(p, cutoff);
    if let Some((version, _)) = &older {
        let candidate = Pinned::new(p.eco, &p.name, version);
        let fixed = registry.advisories(&candidate).unwrap_or_default();
        if !fixed.is_empty() && registry.advisories(p).is_ok_and(|a| a.is_empty()) {
            return (
                Level::Warning,
                format!(
                    "`{p}` ({}) is only {} old, but allowed as a security fix: `{candidate}`, the \
newest release at least {days} days old, has known advisories ({}).",
                    p.eco,
                    ago(age),
                    fixed.join(", ")
                ),
                "Nothing to fix; reported so reviewers see a young version entering the lockfile."
                    .to_string(),
            );
        }
    }
    let instead = match older {
        Some((v, at)) => format!(
            "Use {}@{v} (published {}) or another release at least {days} days old",
            p.name,
            at.strftime("%Y-%m-%d")
        ),
        None => format!(
            "Use a release published before {}",
            cutoff.strftime("%Y-%m-%d")
        ),
    };
    (
        Level::Error,
        format!(
            "`{p}` ({}) was published {} ago; dependency versions must be at least {days} days old.",
            p.eco,
            ago(age)
        ),
        format!(
            "Brand-new releases are where compromised versions live until they are caught and \
pulled. {instead}, then regenerate the lockfile; pin a transitive dependency through its parent \
or an override. Do not exempt it yourself: if this exact version is required, stop and ask the user."
        ),
    )
}

fn ago(d: SignedDuration) -> String {
    let hours = d.as_hours();
    if hours < 48 {
        format!("{hours} hour(s)")
    } else {
        format!("{} days", hours / 24)
    }
}
