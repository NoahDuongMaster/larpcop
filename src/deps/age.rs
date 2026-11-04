//! `dependency-release-age`: lockfile entries new in this change must be old enough.

mod security_fix;
#[cfg(test)]
mod tests;

use super::clock::{ago, cutoff};
use super::ecosystem::Pinned;
use super::lockfile::{self, LockCache, ParsedLock};
use super::net::{self, CONCURRENCY};
use super::osv::{Osv, Severity};
use super::registry::Registry;
use super::{AGE_ID, Deps, Findings, View};
use crate::rules::{Level, Violation};
use anyhow::Result;
use jiff::{SignedDuration, Timestamp};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// A lockfile entry that this change adds or moves to another version.
pub(super) struct Fresh {
    rel: String,
    content: Arc<str>,
    pin: Pinned,
}

/// How a lookup judged a pin. `lookup_failed`: its publish date could not be found
/// out, so the verdict describes the network, not the version.
#[derive(Clone)]
struct Verdict {
    level: Level,
    message: String,
    note: String,
    lookup_failed: bool,
}

impl Deps {
    /// The entries of `listed` lockfiles this change brings in, judged by their age.
    pub(super) fn check_age(
        &self,
        days: u32,
        view: &View,
        listed: &[&str],
        locks: &LockCache,
    ) -> Result<Findings> {
        let fresh: Vec<Fresh> = listed
            .iter()
            .filter_map(|rel| locks.get(rel))
            .flat_map(|lock| self.fresh_pins(lock, view))
            .collect();
        too_new(days, self.vulns, &fresh)
    }

    fn fresh_pins(&self, lock: &ParsedLock, view: &View) -> Vec<Fresh> {
        let before = lock.before(view);
        let mut seen = HashSet::new();
        lock.pins
            .iter()
            .filter(|p| {
                !before.contains(*p) && !self.exempt.matches(p.eco, &p.name) && seen.insert(*p)
            })
            .map(|pin| Fresh {
                rel: lock.rel.clone(),
                content: Arc::clone(&lock.content),
                pin: pin.clone(),
            })
            .collect()
    }
}

/// `threshold` is the vulnerability rule's: without one, no advisory can justify a
/// young version.
fn too_new(days: u32, threshold: Option<Severity>, fresh: &[Fresh]) -> Result<Findings> {
    if fresh.is_empty() {
        return Ok(Findings::default());
    }
    let judge = Judge {
        registry: Registry::new(),
        osv: Osv::new(),
        threshold,
        days,
        now: Timestamp::now(),
        cutoff: cutoff(days)?,
    };
    // One lookup per distinct pin, however many lockfiles pin it.
    let mut slot_of: HashMap<&Pinned, usize> = HashMap::new();
    let mut distinct: Vec<&Pinned> = Vec::new();
    for f in fresh {
        slot_of.entry(&f.pin).or_insert_with(|| {
            distinct.push(&f.pin);
            distinct.len() - 1
        });
    }
    let verdicts = net::par_map(CONCURRENCY, &distinct, |p| Ok(judge.verdict(p)))?;
    let violations = fresh
        .iter()
        .filter_map(|f| {
            let v = verdicts[slot_of[&f.pin]].clone()?;
            let line = lockfile::line_of(super::file_name(&f.rel), &f.content, &f.pin);
            Some(Violation {
                rule: AGE_ID.into(),
                level: v.level,
                file: f.rel.clone(),
                line,
                column: usize::from(line > 0),
                message: v.message,
                note: Some(v.note),
                snippet: None,
            })
        })
        .collect();
    Ok(Findings {
        violations,
        lookup_failed: verdicts.iter().flatten().any(|v| v.lookup_failed),
    })
}

struct Judge {
    registry: Registry,
    osv: Osv,
    threshold: Option<Severity>,
    days: u32,
    now: Timestamp,
    /// Versions published after this are too young.
    cutoff: Timestamp,
}

impl Judge {
    /// `None`: old enough.
    fn verdict(&self, p: &Pinned) -> Option<Verdict> {
        Some(match self.registry.published(p) {
            Ok(Some(t)) if t <= self.cutoff => return None,
            Ok(Some(t)) => self.too_young(p, self.now.duration_since(t)),
            Ok(None) => Verdict {
                level: Level::Error,
                message: format!(
                    "`{p}` ({}): deps.dev has no publish date for this version.",
                    p.eco
                ),
                note: "Usually it was released in the last few hours: treat it as too new and use an older \
version. If it comes from a private registry, ask the user to add it to `dependencies.exempt`."
                    .to_string(),
                lookup_failed: false,
            },
            Err(e) => Verdict {
                level: Level::Error,
                message: format!(
                    "`{p}` ({}): could not look up its publish date: {e:#}",
                    p.eco
                ),
                note: "This check fails closed. Retry once deps.dev is reachable; do not work around it."
                    .to_string(),
                lookup_failed: true,
            },
        })
    }

    /// A young version is an error — unless it is the fix for a vulnerability of the
    /// newest release old enough (see `security_fix`): then holding it back for the
    /// age rule would be the worse risk.
    fn too_young(&self, p: &Pinned, age: SignedDuration) -> Verdict {
        let days = self.days;
        // Why the exemption could not be checked, when it could not: the version
        // stays an error, and the reader learns why.
        let mut caveat = String::new();
        let older = match self.registry.newest_before(p, self.cutoff) {
            Ok(older) => older,
            Err(e) => {
                caveat = format!(" Older releases could not be listed: {e:#}.");
                None
            }
        };
        if let (Some(min), Some((version, _))) = (self.threshold, &older) {
            let candidate = Pinned::new(p.eco, &p.name, version);
            match security_fix::advisories_fixed(&self.osv, min, p, &candidate) {
                Ok(ids) if !ids.is_empty() => {
                    return Verdict {
                        level: Level::Warning,
                        message: format!(
                            "`{p}` ({}) is only {} old, but allowed as a security fix: `{candidate}`, the \
newest release at least {days} days old, has known advisories ({}). OSV lists this version as the fix.",
                            p.eco,
                            ago(age),
                            ids.join(", ")
                        ),
                        note: "Nothing to fix; reported so reviewers see a young version entering the lockfile."
                            .to_string(),
                        lookup_failed: false,
                    };
                }
                Ok(_) => {}
                Err(e) => {
                    caveat = format!(" Whether it is a security fix could not be checked: {e:#}.");
                }
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
                self.cutoff.strftime("%Y-%m-%d")
            ),
        };
        Verdict {
            level: Level::Error,
            message: format!(
                "`{p}` ({}) was published {} ago; dependency versions must be at least {days} days old.",
                p.eco,
                ago(age)
            ),
            note: format!(
                "Brand-new releases are where compromised versions live until they are caught and \
pulled. {instead}, then regenerate the lockfile; pin a transitive dependency through its parent \
or an override. Do not exempt it yourself: if this exact version is required, stop and ask the user.{caveat}"
            ),
            lookup_failed: false,
        }
    }
}
