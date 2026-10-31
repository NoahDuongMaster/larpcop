//! `dependency-vulnerability`: OSV advisories on lockfile entries and on
//! packages an agent is about to install.

use super::ecosystem::{Ecosystem, Pinned};
use super::install::Request;
use super::osv::{Osv, Severity};
use super::{Deps, VULN_ID, View, lockfile};
use crate::rules::{Level, Violation};
use std::collections::BTreeSet;

/// A lockfile entry and whether this change brought it in.
pub(super) struct Locked {
    rel: String,
    line: usize,
    pin: Pinned,
    fresh: bool,
}

impl Deps {
    /// Every entry of a lockfile; `audit` = judge all of them, not just new ones.
    pub(super) fn locked(&self, rel: &str, name: &str, view: &View, audit: bool) -> Vec<Locked> {
        let Some(content) = view.current(rel) else {
            return Vec::new();
        };
        let Some(Ok(pins)) = view.pins(rel, name, &content) else {
            return Vec::new();
        };
        let before: BTreeSet<Pinned> = view
            .old(rel)
            .and_then(|old| view.pins(rel, name, &old)?.ok())
            .unwrap_or_default()
            .into_iter()
            .collect();
        let mut seen = BTreeSet::new();
        pins.into_iter()
            .filter(|p| seen.insert(p.clone()))
            .map(|pin| Locked {
                rel: rel.into(),
                line: lockfile::line_of(name, &content, &pin),
                fresh: audit || !before.contains(&pin),
                pin,
            })
            .collect()
    }

    pub(super) fn vulnerable(&self, threshold: Severity, locked: &[Locked]) -> Vec<Violation> {
        if locked.is_empty() {
            return Vec::new();
        }
        let pins: Vec<&Pinned> = locked.iter().map(|l| &l.pin).collect();
        let found = match Osv::new().scan(&pins) {
            Ok(f) => f,
            Err(e) => {
                return vec![violation(
                    &locked[0].rel,
                    0,
                    format!("could not query OSV for known vulnerabilities: {e:#}"),
                    "This check fails closed. Retry once api.osv.dev is reachable.".into(),
                )];
            }
        };
        let mut out = Vec::new();
        for (l, advisories) in locked.iter().zip(found) {
            for a in advisories {
                let p = &l.pin;
                if a.malicious {
                    out.push(violation(
                        &l.rel,
                        l.line,
                        format!(
                            "`{p}` ({}) is a known MALICIOUS package ({}): {}",
                            p.eco, a.id, a.summary
                        ),
                        "Remove it and every package that pulled it in, then treat the machines \
that installed it as compromised: rotate the credentials they held."
                            .into(),
                    ));
                } else if l.fresh && a.severity >= threshold {
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
                        l.line,
                        format!(
                            "`{p}` ({}) has a known {:?} vulnerability {}: {}",
                            p.eco, a.severity, a.id, a.summary
                        ),
                        fix,
                    ));
                }
            }
        }
        out
    }

    /// Before an install runs: malware always blocks; a pinned version blocks
    /// at the configured severity.
    pub(super) fn gate_vulnerable(
        &self,
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
        let osv = Osv::new();
        let ids = match osv.ids(&wanted) {
            Ok(ids) => ids,
            Err(e) => return Some(unreachable(e)),
        };
        let mut reasons = Vec::new();
        for ((eco, name, version), ids) in wanted.iter().zip(ids) {
            for id in ids {
                let a = match osv.advisory(&id, *eco, name) {
                    Ok(a) => a,
                    Err(e) => return Some(unreachable(e)),
                };
                let pinned_and_bad = version.is_some() && a.severity >= threshold;
                if a.malicious || pinned_and_bad {
                    let what = if a.malicious {
                        "malicious".to_string()
                    } else {
                        format!("{:?}", a.severity)
                    };
                    reasons.push(format!(
                        "`{name}` ({eco}): {what} advisory {id}: {}",
                        a.summary
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
mod tests {
    use super::*;

    #[test]
    fn versions_in_install_specs() {
        assert_eq!(
            pinned_version(Ecosystem::Npm, "left-pad@1.3.0"),
            Some("1.3.0")
        );
        assert_eq!(
            pinned_version(Ecosystem::Npm, "@scope/x@2.0.0"),
            Some("2.0.0")
        );
        assert_eq!(pinned_version(Ecosystem::Npm, "@scope/x"), None);
        assert_eq!(pinned_version(Ecosystem::Npm, "zod@latest"), None);
        assert_eq!(
            pinned_version(Ecosystem::PyPI, "requests==2.31.0"),
            Some("2.31.0")
        );
        assert_eq!(
            pinned_version(Ecosystem::Go, "github.com/a/b@v1.2.3"),
            Some("v1.2.3")
        );
        assert_eq!(
            pinned_version(Ecosystem::Packagist, "guzzlehttp/guzzle:7.4.0"),
            Some("7.4.0")
        );
        assert_eq!(
            pinned_version(Ecosystem::Packagist, "guzzlehttp/guzzle:^7"),
            None
        );
    }
}
