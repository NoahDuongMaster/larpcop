//! OSV's answers to lockfile scans, kept on disk for `QUERY_TTL`: the same pins
//! asked about again soon after (a second `larpcop check` with nothing changed,
//! the Stop hook after the edit hooks) cost no round trip.
//!
//! Only `Osv::scan_cached` reads or writes it. The install gate asks through
//! `Osv::scan`, which always reaches OSV: a package about to be installed is
//! judged by what OSV says now.

use super::{Hit, Osv, Query, system};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::io::ErrorKind;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// How long an answer is trusted. Short on purpose: a malware report published
/// after an answer was stored is missed until that answer expires.
pub(super) const QUERY_TTL: Duration = Duration::from_secs(15 * 60);

pub(super) struct QueryCache {
    dir: PathBuf,
    ttl: Duration,
}

/// What one file holds. The pin is stored whole: the file name is only a hash of
/// it, and an entry that is not for the pin asked about must never answer for it.
#[derive(Serialize, Deserialize)]
struct Entry {
    ecosystem: String,
    name: String,
    version: String,
    /// Seconds since the Unix epoch.
    stored_at: u64,
    hits: Vec<Hit>,
}

impl QueryCache {
    pub(super) fn new(dir: PathBuf, ttl: Duration) -> Self {
        Self { dir, ttl }
    }

    fn file(&self, q: &Query, version: &str) -> PathBuf {
        let mut h = DefaultHasher::new();
        (system(q.eco), q.name, version).hash(&mut h);
        self.dir.join(format!("{:016x}.json", h.finish()))
    }

    /// The stored answer for `q`: `None` when there is none, it has expired, it is
    /// from the future (the clock moved) or it is not for this pin. A file that
    /// cannot be read or parsed is reported and counts as missing, so the pin is
    /// asked about again and the entry rewritten.
    fn load(&self, q: &Query) -> Option<Vec<Hit>> {
        let version = q.version?;
        let file = self.file(q, version);
        let text = match std::fs::read_to_string(&file) {
            Ok(text) => text,
            Err(e) if e.kind() == ErrorKind::NotFound => return None,
            Err(e) => return unreadable(&file, &e),
        };
        let entry: Entry = match serde_json::from_str(&text) {
            Ok(entry) => entry,
            Err(e) => return unreadable(&file, &e),
        };
        let age = unix_now().ok()?.checked_sub(entry.stored_at)?;
        let ours = entry.ecosystem == system(q.eco) && entry.name == q.name;
        (ours && entry.version == version && age < self.ttl.as_secs()).then_some(entry.hits)
    }

    /// Deletes entries more than a day past their expiry, so the directory does
    /// not keep every version ever scanned. A failure only costs disk space:
    /// it is reported, and the scan goes on.
    fn prune(&self) {
        let stale_after = self.ttl * 96;
        let entries = match std::fs::read_dir(&self.dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == ErrorKind::NotFound => return,
            Err(e) => return pruning_failed(&self.dir, &e),
        };
        for entry in entries {
            let path = match entry {
                Ok(entry) => entry.path(),
                Err(e) => return pruning_failed(&self.dir, &e),
            };
            let age = std::fs::metadata(&path)
                .and_then(|m| m.modified())
                .map(|at| SystemTime::now().duration_since(at).unwrap_or_default());
            match age {
                Ok(age) if age > stale_after => {
                    if let Err(e) = std::fs::remove_file(&path) {
                        pruning_failed(&path, &e);
                    }
                }
                Ok(_) => {}
                Err(e) => pruning_failed(&path, &e),
            }
        }
    }

    /// Keeps a complete, validated answer. Written beside its file and renamed into
    /// place: a reader sees the old entry or the new one, never half of one.
    fn store(&self, q: &Query, hits: &[Hit]) -> Result<()> {
        let Some(version) = q.version else {
            return Ok(()); // a whole package, not a pin: only installs ask that
        };
        let entry = Entry {
            ecosystem: system(q.eco).into(),
            name: q.name.into(),
            version: version.into(),
            stored_at: unix_now()?,
            hits: hits.to_vec(),
        };
        let file = self.file(q, version);
        let tmp = file.with_extension(format!("{}.tmp", std::process::id()));
        std::fs::create_dir_all(&self.dir)
            .with_context(|| format!("creating {}", self.dir.display()))?;
        std::fs::write(&tmp, serde_json::to_vec(&entry)?)
            .with_context(|| format!("writing {}", tmp.display()))?;
        std::fs::rename(&tmp, &file).with_context(|| format!("writing {}", file.display()))
    }
}

fn unix_now() -> Result<u64> {
    let since = SystemTime::now().duration_since(UNIX_EPOCH);
    Ok(since.context("the system clock is before 1970")?.as_secs())
}

fn pruning_failed(path: &std::path::Path, e: &dyn std::fmt::Display) {
    eprintln!(
        "larpcop: warning: cannot clean the OSV cache at {}: {e}",
        path.display()
    );
}

/// Says why an entry is not used, and answers "nothing stored".
fn unreadable(file: &std::path::Path, e: &dyn std::fmt::Display) -> Option<Vec<Hit>> {
    eprintln!(
        "larpcop: warning: ignoring the unreadable OSV cache entry {}: {e}",
        file.display()
    );
    None
}

impl Osv {
    /// `ids_modified`, except that pins answered within the TTL are not asked
    /// again. Pins that were asked are stored once the whole fetch has succeeded:
    /// an error, a short answer or an unfinished page chain stores nothing.
    pub(super) fn ids_cached(&self, queries: &[Query]) -> Result<Vec<Vec<Hit>>> {
        let Some(cache) = &self.queries else {
            return self.ids_modified(queries);
        };
        let stored: Vec<Option<Vec<Hit>>> = queries.iter().map(|q| cache.load(q)).collect();
        let missing: Vec<Query> = queries
            .iter()
            .zip(&stored)
            .filter(|(_, hits)| hits.is_none())
            .map(|(q, _)| *q)
            .collect();
        let fetched = self.ids_modified(&missing)?;
        for (q, hits) in missing.iter().zip(&fetched) {
            // The answer is good either way; a cache that cannot be written only
            // costs the next scan another request.
            if let Err(e) = cache.store(q, hits) {
                eprintln!(
                    "larpcop: warning: cannot cache the OSV answer for `{}`: {e:#}",
                    q.name
                );
            }
        }
        if !missing.is_empty() {
            cache.prune();
        }
        let mut fetched = fetched.into_iter();
        stored
            .into_iter()
            .map(|hits| match hits {
                Some(hits) => Ok(hits),
                None => fetched.next().context("OSV: fewer answers than queries"),
            })
            .collect()
    }
}

#[cfg(test)]
mod tests;
