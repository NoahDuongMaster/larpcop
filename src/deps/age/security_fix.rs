//! When a too-young version may enter a lockfile anyway: when it is the fix for a
//! real vulnerability of the release the age rule would leave you with.
//!
//! A brand-new release has no advisories yet, and a compromised one is exactly
//! that, so "the older release is vulnerable and this one is not" proves nothing.
//! What does: an advisory at or above the vulnerability threshold that affects the
//! older release and names this very version among its fixed versions.

use super::super::ecosystem::Pinned;
use super::super::osv::{Osv, Query, Severity};
use anyhow::{Result, bail};

/// Ids of the advisories of `older` that `young` fixes; empty when it is not a
/// security fix. `young` must be free of advisories itself. Only an exact match of
/// a fixed version counts: comparing versions across ecosystems would be a guess,
/// so a later release than the listed fix is not trusted by this rule.
pub(super) fn advisories_fixed(
    osv: &Osv,
    threshold: Severity,
    young: &Pinned,
    older: &Pinned,
) -> Result<Vec<String>> {
    let found = osv.scan(&[Query::pinned(older, true), Query::pinned(young, true)])?;
    let [of_older, of_young] = found.as_slice() else {
        bail!("OSV answered {} lists for 2 queries", found.len());
    };
    if !of_young.is_empty() {
        return Ok(Vec::new());
    }
    let fixes = |fixed: &[String]| {
        let bare = young.version.trim_start_matches('v');
        fixed.iter().any(|f| f.trim_start_matches('v') == bare)
    };
    Ok(of_older
        .iter()
        .filter(|a| !a.malicious && a.severity >= threshold && fixes(&a.fixed))
        .map(|a| a.id.clone())
        .collect())
}
