//! `dependency-release-age`: lockfile entries new in this change must be old enough.

use super::ecosystem::Pinned;
use super::lockfile;
use super::registry::Registry;
use super::{AGE_ID, Deps, View, unreadable};
use crate::rules::{Level, Violation};
use anyhow::Result;
use jiff::{SignedDuration, Timestamp};
use rayon::prelude::*;
use std::cell::OnceCell;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

pub(super) struct ParsedLock {
    pub rel: String,
    pub content: Arc<str>,
    pub pins: Vec<Pinned>,
    before: OnceCell<BTreeSet<Pinned>>,
}

/// A lockfile entry that this change adds or moves to another version.
pub(super) struct Fresh {
    rel: String,
    content: Arc<str>,
    pin: Pinned,
}

impl View<'_> {
    pub(super) fn parse_lock(&self, rel: &str, name: &str) -> Option<Result<ParsedLock>> {
        let is_pin = lockfile::parse(name, "").is_some()
            || name == "package.json"
            || (name.starts_with("requirements") && name.ends_with(".txt"));
        if !is_pin {
            return None;
        }
        let content = self.current(rel)?;
        let pins = self.pins(rel, name, &content)?;
        Some(pins.map(|pins| ParsedLock {
            rel: rel.to_string(),
            content: content.into(),
            pins,
            before: OnceCell::new(),
        }))
    }
}

impl ParsedLock {
    pub(super) fn before(&self, view: &View) -> &BTreeSet<Pinned> {
        self.before.get_or_init(|| {
            let name = super::file_name(&self.rel);
            view.old(&self.rel)
                .and_then(|old| view.pins(&self.rel, name, &old)?.ok())
                .unwrap_or_default()
                .into_iter()
                .collect()
        })
    }
}

impl Deps {
    pub(super) fn collect_fresh<'a>(
        &self,
        rel: &'a str,
        name: &str,
        view: &View,
        locks: &mut BTreeMap<&'a str, Option<ParsedLock>>,
        out: &mut Vec<Violation>,
    ) -> Vec<Fresh> {
        match view.parse_lock(rel, name) {
            Some(Ok(lock)) => {
                let fresh = self.fresh_pins_parsed(&lock, view);
                locks.insert(rel, Some(lock));
                fresh
            }
            Some(Err(e)) => {
                out.push(unreadable(rel, AGE_ID, &e));
                locks.insert(rel, None);
                Vec::new()
            }
            None => Vec::new(),
        }
    }

    pub(super) fn fresh_pins_parsed(&self, lock: &ParsedLock, view: &View) -> Vec<Fresh> {
        let before = lock.before(view);
        let mut seen = BTreeSet::new();
        lock.pins
            .iter()
            .filter(|p| {
                !before.contains(*p)
                    && !self.exempt.matches(p.eco, &p.name)
                    && seen.insert((*p).clone())
            })
            .map(|pin| Fresh {
                rel: lock.rel.clone(),
                content: Arc::clone(&lock.content),
                pin: pin.clone(),
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
    let line = lockfile::line_of(super::file_name(&f.rel), &f.content, p);
    Some(Violation {
        rule: AGE_ID.into(),
        level,
        file: f.rel.clone(),
        line,
        column: usize::from(line > 0),
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
