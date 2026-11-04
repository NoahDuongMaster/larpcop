//! Known vulnerabilities and malicious packages from OSV.dev (GitHub Advisory,
//! RustSec, PyPA, Go, and OpenSSF's malicious-packages feed).
//! - `MAL-` advisories (malware) block whatever the scope or the threshold;
//! - other advisories block versions this change brings in, from a severity up.
//!
//! Severity comes from the advisory (GHSA's rating) or its CVSS vector.

mod advisory;
mod query_cache;
#[cfg(test)]
mod tests;

use super::ecosystem::{Ecosystem, Pinned};
use super::net;
use advisory::parse_advisory;
pub use advisory::{Advisory, Severity, is_malicious};
use anyhow::{Context, Result, bail, ensure};
use query_cache::{QUERY_TTL, QueryCache};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

const DEFAULT_API: &str = "https://api.osv.dev/v1";
/// Queries OSV accepts in one `querybatch`.
const BATCH: usize = 1000;
/// Batches of a big lockfile in flight at once.
const BATCHES_AT_ONCE: usize = 4;
/// Result pages followed for one package before giving up.
const MAX_PAGES: usize = 20;

/// One package to ask OSV about.
#[derive(Clone, Copy)]
pub struct Query<'a> {
    pub eco: Ecosystem,
    pub name: &'a str,
    /// `None` asks about the package as a whole (what an unpinned `npm install x`
    /// would get, and typosquats).
    pub version: Option<&'a str>,
    /// Whether advisories other than malware matter: their details are only
    /// fetched for queries that want them.
    pub rated: bool,
}

impl<'a> Query<'a> {
    /// Ask about the exact version a lockfile pins.
    pub fn pinned(pin: &'a Pinned, rated: bool) -> Self {
        Self {
            eco: pin.eco,
            name: &pin.name,
            version: Some(&pin.version),
            rated,
        }
    }

    fn json(&self) -> Value {
        let mut q = json!({ "package": { "name": self.name, "ecosystem": system(self.eco) } });
        if let Some(v) = self.version {
            q["version"] = json!(v);
        }
        q
    }
}

/// (advisory id, `modified` timestamp)
type Hit = (String, String);

pub struct Osv {
    agent: ureq::Agent,
    api: String,
    /// Advisory details by id, valid while their `modified` time is unchanged.
    cache: Option<PathBuf>,
    /// OSV's recent answers to lockfile scans; only `scan_cached` uses them.
    queries: Option<QueryCache>,
}

pub fn system(eco: Ecosystem) -> &'static str {
    match eco {
        Ecosystem::Npm => "npm",
        Ecosystem::PyPI => "PyPI",
        Ecosystem::Cargo => "crates.io",
        Ecosystem::Go => "Go",
        Ecosystem::RubyGems => "RubyGems",
        Ecosystem::NuGet => "NuGet",
        Ecosystem::Maven => "Maven",
        Ecosystem::Packagist => "Packagist",
    }
}

impl Osv {
    pub fn new() -> Self {
        let api = std::env::var("LARPCOP_OSV_API").unwrap_or_else(|_| DEFAULT_API.into());
        let root = crate::config::cache_root().ok();
        Self {
            queries: root
                .as_ref()
                .map(|d| QueryCache::new(d.join("osv-query"), QUERY_TTL)),
            ..Self::at(&api, root.map(|d| d.join("osv")))
        }
    }

    pub(super) fn at(api: &str, cache: Option<PathBuf>) -> Self {
        Self {
            agent: net::agent(Duration::from_secs(30)),
            api: api.into(),
            cache,
            queries: None,
        }
    }

    /// Answers to lockfile scans are reused for `ttl`, kept in `dir`.
    #[cfg(test)]
    pub(super) fn remembering(self, dir: PathBuf, ttl: Duration) -> Self {
        Self {
            queries: Some(QueryCache::new(dir, ttl)),
            ..self
        }
    }

    /// Advisory ids per query, in query order. OSV must answer every query: a short
    /// or padded answer cannot be matched to packages, so it is an error rather
    /// than packages that look clean.
    fn ids_modified(&self, queries: &[Query]) -> Result<Vec<Vec<Hit>>> {
        let batches: Vec<&[Query]> = queries.chunks(BATCH).collect();
        let answers = net::par_map(BATCHES_AT_ONCE, &batches, |batch| self.batch(batch))?;
        Ok(answers.into_iter().flatten().collect())
    }

    fn batch(&self, queries: &[Query]) -> Result<Vec<Vec<Hit>>> {
        let body: Vec<Value> = queries.iter().map(Query::json).collect();
        let res = self.post("querybatch", &json!({ "queries": body }))?;
        queries
            .iter()
            .zip(results(&res, queries.len())?)
            .map(|(q, first)| self.pages(q, first))
            .collect()
    }

    /// A package with many advisories answers in pages: `next_page_token` asks
    /// for the rest, and an advisory on a dropped page could be the malware one.
    fn pages(&self, q: &Query, first: &Value) -> Result<Vec<Hit>> {
        let mut found = hits(first)?;
        let mut token = first["next_page_token"].as_str().map(String::from);
        let mut pages = 1;
        while let Some(t) = token {
            pages += 1;
            ensure!(
                pages <= MAX_PAGES,
                "OSV: more than {MAX_PAGES} pages of advisories for `{}`",
                q.name
            );
            let mut next = q.json();
            next["page_token"] = json!(t);
            let res = self.post("querybatch", &json!({ "queries": [next] }))?;
            let page = results(&res, 1)?.pop().context("OSV: empty page")?;
            found.extend(hits(page)?);
            token = page["next_page_token"].as_str().map(String::from);
        }
        Ok(found)
    }

    /// An advisory's JSON, from the disk cache when querybatch reports the same
    /// `modified` time as when it was cached (edits always bump it). The batch
    /// API rounds that time differently from the full record, so the batch's
    /// own value is what gets stored.
    fn cached(&self, id: &str, modified: &str) -> Result<Value> {
        let file = self
            .cache
            .as_ref()
            .filter(|_| !modified.is_empty())
            .map(|d| d.join(format!("{}.json", id.replace(['/', '\\', ':'], "_"))));
        let hit = file
            .as_ref()
            .and_then(|f| std::fs::read_to_string(f).ok())
            .and_then(|s| serde_json::from_str::<Value>(&s).ok())
            .filter(|c| c["modified"] == modified);
        if let Some(mut c) = hit {
            return Ok(c["advisory"].take());
        }
        let advisory = self.fetch(id)?;
        if let Some(f) = file {
            // Best effort: a missing cache only costs another request.
            let entry = json!({ "modified": modified, "advisory": advisory });
            let _ = std::fs::create_dir_all(f.parent().unwrap_or(&f));
            let _ = std::fs::write(&f, entry.to_string());
        }
        Ok(advisory)
    }

    fn fetch(&self, id: &str) -> Result<Value> {
        let url = format!("{}/vulns/{id}", self.api);
        let (status, body) = net::fetch(|| self.agent.get(&url).call())
            .with_context(|| format!("OSV: fetching {id}"))?;
        ensure!(status == 200, "OSV: {id}: HTTP {status}");
        Ok(serde_json::from_str(&body)?)
    }

    fn post(&self, path: &str, body: &Value) -> Result<Value> {
        let url = format!("{}/{path}", self.api);
        let payload = body.to_string();
        let (status, text) = net::fetch(|| {
            self.agent
                .post(&url)
                .header("content-type", "application/json")
                .send(payload.as_str())
        })
        .context("OSV unreachable")?;
        ensure!(status == 200, "OSV: HTTP {status}");
        Ok(serde_json::from_str(&text)?)
    }

    /// Advisories per query, in query order. Details are fetched once per id, in
    /// parallel, and only for the ids that matter: malware always, other
    /// advisories for `rated` queries. Each advisory is read for the package it
    /// was found on, since its fixed versions differ per package.
    pub fn scan(&self, queries: &[Query]) -> Result<Vec<Vec<Advisory>>> {
        self.advisories(queries, self.ids_modified(queries)?)
    }

    /// `scan` for lockfile checks only: pins OSV answered for in the last
    /// `QUERY_TTL` are not asked about again. Installs use `scan`, which always asks.
    pub fn scan_cached(&self, queries: &[Query]) -> Result<Vec<Vec<Advisory>>> {
        self.advisories(queries, self.ids_cached(queries)?)
    }

    fn advisories(&self, queries: &[Query], ids: Vec<Vec<Hit>>) -> Result<Vec<Vec<Advisory>>> {
        let matters = |q: &Query, id: &str| q.rated || is_malicious(id);
        let mut wanted: BTreeMap<&str, &str> = BTreeMap::new();
        for (q, hits) in queries.iter().zip(&ids) {
            for (id, modified) in hits.iter().filter(|(id, _)| matters(q, id)) {
                wanted.entry(id).or_insert(modified);
            }
        }
        // The common case: nothing known about any of them.
        if wanted.is_empty() {
            return Ok(queries.iter().map(|_| Vec::new()).collect());
        }
        let wanted: Vec<_> = wanted.into_iter().collect();
        let details: BTreeMap<&str, Value> =
            net::par_map(net::CONCURRENCY, &wanted, |(id, modified)| {
                Ok((*id, self.cached(id, modified)?))
            })?
            .into_iter()
            .collect();
        queries
            .iter()
            .zip(&ids)
            .map(|(q, hits)| {
                hits.iter()
                    .filter(|(id, _)| matters(q, id))
                    .map(|(id, _)| {
                        let detail = details
                            .get(id.as_str())
                            .context("OSV: advisory not fetched")?;
                        Ok(parse_advisory(id, detail, q.eco, q.name))
                    })
                    .collect()
            })
            .collect()
    }
}

/// The `results` of a `querybatch` answer, which must hold exactly `expected`.
fn results(res: &Value, expected: usize) -> Result<Vec<&Value>> {
    let list = res["results"].as_array().context("OSV: no `results`")?;
    if list.len() != expected {
        bail!(
            "OSV answered {} result(s) for {expected} queries; cannot tell which packages were checked",
            list.len()
        );
    }
    ensure!(
        list.iter().all(Value::is_object),
        "OSV: malformed `results`"
    );
    Ok(list.iter().collect())
}

/// The advisories of one result; OSV omits `vulns` when nothing matches.
fn hits(result: &Value) -> Result<Vec<Hit>> {
    let Some(vulns) = result.get("vulns") else {
        return Ok(Vec::new());
    };
    vulns
        .as_array()
        .context("OSV: `vulns` is not a list")?
        .iter()
        .map(|v| {
            let id = v["id"]
                .as_str()
                .context("OSV: an advisory without an `id`")?;
            let modified = v["modified"].as_str().unwrap_or_default();
            Ok((id.to_string(), modified.to_string()))
        })
        .collect()
}
