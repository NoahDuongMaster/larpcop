//! `dependency-vulnerability`: OSV advisories on lockfile entries and on
//! packages an agent is about to install.

use super::Findings;
use super::ecosystem::{Ecosystem, Pinned};
use super::install::Request;
use super::lockfile::LockCache;
use super::osv::{Osv, Query, Severity};
use super::{Deps, VULN_ID, View, lockfile};
use crate::rules::{Level, Violation};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// A lockfile entry and whether this change brought it in.
pub(super) struct Locked {
    rel: String,
    content: Arc<str>,
    pin: Pinned,
    fresh: bool,
}

/// Every entry of the lockfiles in `scan`. `audit` = judge all of them, not just
/// the ones this change brings in.
pub(super) fn locked_entries(
    scan: &[&str],
    view: &View,
    locks: &LockCache,
    audit: bool,
) -> Vec<Locked> {
    let mut locked = Vec::new();
    for lock in scan.iter().filter_map(|rel| locks.get(rel)) {
        let before = lock.before(view);
        let mut seen = HashSet::new();
        locked.extend(
            lock.pins
                .iter()
                .filter(|p| seen.insert(*p))
                .map(|pin| Locked {
                    rel: lock.rel.clone(),
                    content: Arc::clone(&lock.content),
                    fresh: audit || !before.contains(pin),
                    pin: pin.clone(),
                }),
        );
    }
    locked
}

impl Deps {
    /// Malware anywhere in `locked`, and vulnerabilities in the entries this change
    /// brought in. OSV's answers of the last few minutes are reused (`scan_cached`).
    pub(super) fn vulnerable(&self, osv: &Osv, threshold: Severity, locked: &[Locked]) -> Findings {
        if locked.is_empty() {
            return Findings::default();
        }
        // One query per distinct pin, however many lockfiles pin it; its details
        // are wanted if any of them brought it in.
        let mut slot_of: HashMap<&Pinned, usize> = HashMap::new();
        let mut queries: Vec<Query> = Vec::new();
        for l in locked {
            let slot = *slot_of.entry(&l.pin).or_insert_with(|| {
                queries.push(Query::pinned(&l.pin, false));
                queries.len() - 1
            });
            queries[slot].rated |= l.fresh;
        }
        let found = match osv.scan_cached(&queries) {
            Ok(f) => f,
            Err(e) => {
                return Findings {
                    violations: vec![violation(
                        &locked[0].rel,
                        0,
                        format!("could not query OSV for known vulnerabilities: {e:#}"),
                        "This check fails closed. Retry once api.osv.dev is reachable.".into(),
                    )],
                    lookup_failed: true,
                };
            }
        };
        let mut out = Vec::new();
        for l in locked {
            for a in &found[slot_of[&l.pin]] {
                let p = &l.pin;
                if a.malicious {
                    let line = lockfile::line_of(super::file_name(&l.rel), &l.content, p);
                    out.push(violation(
                        &l.rel,
                        line,
                        format!(
                            "`{p}` ({}) is a known MALICIOUS package ({}): {}",
                            p.eco, a.id, a.summary
                        ),
                        "Remove it and every package that pulled it in, then treat the machines \
that installed it as compromised: rotate the credentials they held."
                            .into(),
                    ));
                } else if l.fresh && a.severity >= threshold {
                    let line = lockfile::line_of(super::file_name(&l.rel), &l.content, p);
                    let fix = match a.fixed.as_slice() {
                        [] => "No fixed version is published: replace the package or ask the user."
                            .to_string(),
                        f => format!(
                            "Upgrade to a fixed version ({}), respecting the release-age rule.",
                            f.join(", ")
                        ),
                    };
                    out.push(violation(
                        &l.rel,
                        line,
                        format!(
                            "`{p}` ({}) has a known {:?} vulnerability {}: {}",
                            p.eco, a.severity, a.id, a.summary
                        ),
                        fix,
                    ));
                }
            }
        }
        Findings {
            violations: out,
            lookup_failed: false,
        }
    }

    /// Before an install runs: malware always blocks; a pinned version blocks
    /// at the configured severity.
    pub(super) fn gate_vulnerable(
        &self,
        osv: &Osv,
        threshold: Severity,
        requests: &[Request],
    ) -> Option<String> {
        let wanted: Vec<(Ecosystem, &str, Option<&str>)> = requests
            .iter()
            .filter_map(|r| Some((r.eco, r.name.as_deref()?, pinned_version(r.eco, &r.spec))))
            .collect();
        if wanted.is_empty() {
            return None;
        }
        // Fail closed, like the lockfile check: an install that cannot be
        // vetted does not run.
        let unreachable = |e: anyhow::Error| {
            format!(
                "could not check this install against known malware and vulnerabilities \
(OSV.dev: {e:#}). Retry when the network is back; do not install around the check."
            )
        };
        // Malware matters for every request; a version is judged by severity only
        // when the request pins one. Without it OSV answers with every advisory the
        // package ever had, which would each be fetched only to be thrown away.
        let queries: Vec<Query> = wanted
            .iter()
            .map(|(eco, name, version)| Query {
                eco: *eco,
                name,
                version: *version,
                rated: version.is_some(),
            })
            .collect();
        let found = match osv.scan(&queries) {
            Ok(found) => found,
            Err(e) => return Some(unreachable(e)),
        };
        let mut reasons = Vec::new();
        for ((eco, name, version), advisories) in wanted.iter().zip(found) {
            for a in advisories {
                if a.malicious || (version.is_some() && a.severity >= threshold) {
                    let what = if a.malicious {
                        "malicious".to_string()
                    } else {
                        format!("{:?}", a.severity)
                    };
                    reasons.push(format!(
                        "`{name}` ({eco}): {what} advisory {}: {}",
                        a.id, a.summary
                    ));
                }
            }
        }
        (!reasons.is_empty()).then(|| {
            format!(
                "this install would bring in packages with known advisories:\n- {}\nPick another \
package or a fixed version; if the user insists, stop and ask them.",
                reasons.join("\n- ")
            )
        })
    }
}

/// `left-pad@1.3.0`, `@scope/x@2`, `requests==2.31.0`, `mod@v1.2.3`,
/// `vendor/pkg:7.4.0`.
pub fn pinned_version(eco: Ecosystem, spec: &str) -> Option<&str> {
    let v = match eco {
        Ecosystem::PyPI => spec.split_once("==")?.1,
        Ecosystem::Packagist => spec.split_once(':')?.1,
        _ => {
            let (name, v) = spec.rsplit_once('@')?;
            if name.is_empty() {
                return None;
            }
            v
        }
    };
    v.trim_start_matches('v')
        .starts_with(|c: char| c.is_ascii_digit())
        .then_some(v)
}

fn violation(rel: &str, line: usize, message: String, note: String) -> Violation {
    Violation {
        rule: VULN_ID.into(),
        level: Level::Error,
        file: rel.into(),
        line,
        column: usize::from(line > 0),
        message,
        note: Some(note),
        snippet: None,
    }
}

#[cfg(test)]
mod tests;
