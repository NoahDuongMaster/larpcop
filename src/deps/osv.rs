//! Known vulnerabilities and malicious packages from OSV.dev (GitHub Advisory,
//! RustSec, PyPA, Go, and OpenSSF's malicious-packages feed).
//! - `MAL-` advisories (malware) block whatever the scope or the threshold;
//! - other advisories block versions this change brings in, from a severity up.
//!
//! Severity comes from the advisory (GHSA's rating) or its CVSS vector.

use super::ecosystem::{Ecosystem, Pinned};
use anyhow::{Context, Result, bail};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

const DEFAULT_API: &str = "https://api.osv.dev/v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Moderate,
    High,
    Critical,
}

impl Severity {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "low" => Some(Self::Low),
            "moderate" | "medium" => Some(Self::Moderate),
            "high" => Some(Self::High),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }

    fn of_score(score: f64) -> Self {
        match score {
            s if s >= 9.0 => Self::Critical,
            s if s >= 7.0 => Self::High,
            s if s >= 4.0 => Self::Moderate,
            _ => Self::Low,
        }
    }
}

pub struct Advisory {
    pub id: String,
    pub summary: String,
    pub severity: Severity,
    pub malicious: bool,
    /// Versions that fix it, for this package.
    pub fixed: Vec<String>,
}

pub struct Osv {
    agent: ureq::Agent,
    api: String,
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
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(30)))
            .http_status_as_error(false)
            .user_agent(concat!("agentkit/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        let api = std::env::var("AGENTKIT_OSV_API").unwrap_or_else(|_| DEFAULT_API.into());
        Self { agent, api }
    }

    /// Advisory ids per package; a missing `version` asks about the package as a
    /// whole (what an unpinned `npm install x` would get, and typosquats).
    pub fn ids(&self, queries: &[(Ecosystem, &str, Option<&str>)]) -> Result<Vec<Vec<String>>> {
        Ok(self
            .ids_modified(queries)?
            .into_iter()
            .map(|l| l.into_iter().map(|(id, _)| id).collect())
            .collect())
    }

    /// (id, `modified` timestamp) per package.
    fn ids_modified(
        &self,
        queries: &[(Ecosystem, &str, Option<&str>)],
    ) -> Result<Vec<Vec<(String, String)>>> {
        let mut out = Vec::with_capacity(queries.len());
        for chunk in queries.chunks(1000) {
            let body: Vec<Value> = chunk
                .iter()
                .map(|(eco, name, version)| {
                    let mut q = json!({ "package": { "name": name, "ecosystem": system(*eco) } });
                    if let Some(v) = version {
                        q["version"] = json!(v);
                    }
                    q
                })
                .collect();
            let res: Value = self.post("querybatch", &json!({ "queries": body }))?;
            let results = res["results"].as_array().context("OSV: no `results`")?;
            out.extend(results.iter().map(|r| {
                r["vulns"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|v| {
                        let modified = v["modified"].as_str().unwrap_or_default();
                        Some((v["id"].as_str()?.to_string(), modified.to_string()))
                    })
                    .collect()
            }));
        }
        Ok(out)
    }

    pub fn advisory(&self, id: &str, eco: Ecosystem, name: &str) -> Result<Advisory> {
        Ok(parse_advisory(id, &self.fetch(id)?, eco, name))
    }

    /// An advisory's JSON, from the disk cache when querybatch reports the same
    /// `modified` time as when it was cached (edits always bump it). The batch
    /// API rounds that time differently from the full record, so the batch's
    /// own value is what gets stored.
    fn cached(&self, id: &str, modified: &str) -> Result<Value> {
        let file = (!modified.is_empty())
            .then(|| crate::config::cache_root().ok())
            .flatten()
            .map(|d| {
                d.join("osv")
                    .join(format!("{}.json", id.replace(['/', '\\', ':'], "_")))
            });
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
        let mut res = self
            .agent
            .get(&format!("{}/vulns/{id}", self.api))
            .call()
            .with_context(|| format!("OSV: fetching {id}"))?;
        if res.status() != 200 {
            bail!("OSV: {id}: HTTP {}", res.status());
        }
        Ok(serde_json::from_str(&res.body_mut().read_to_string()?)?)
    }

    fn post(&self, path: &str, body: &Value) -> Result<Value> {
        let mut res = self
            .agent
            .post(&format!("{}/{path}", self.api))
            .header("content-type", "application/json")
            .send(body.to_string())
            .context("OSV unreachable")?;
        if res.status() != 200 {
            bail!("OSV: HTTP {}", res.status());
        }
        Ok(serde_json::from_str(&res.body_mut().read_to_string()?)?)
    }

    /// Advisories that apply to `pins`, details fetched once per id, in parallel.
    pub fn scan(&self, pins: &[&Pinned]) -> Result<Vec<Vec<Arc<Advisory>>>> {
        let queries: Vec<_> = pins
            .iter()
            .map(|p| (p.eco, p.name.as_str(), Some(p.version.as_str())))
            .collect();
        let ids = self.ids_modified(&queries)?;
        let mut wanted: BTreeMap<&str, (&str, &Pinned)> = BTreeMap::new();
        for (pin, ids) in pins.iter().zip(&ids) {
            for (id, modified) in ids {
                wanted.entry(id).or_insert((modified, pin));
            }
        }
        let pool = rayon::ThreadPoolBuilder::new().num_threads(16).build()?;
        let details: BTreeMap<&str, Arc<Advisory>> = pool.install(|| {
            wanted
                .par_iter()
                .map(|(id, (modified, pin))| {
                    let v = self.cached(id, modified)?;
                    Ok((*id, Arc::new(parse_advisory(id, &v, pin.eco, &pin.name))))
                })
                .collect::<Result<_>>()
        })?;
        Ok(ids
            .iter()
            .map(|list| {
                list.iter()
                    .map(|(id, _)| details[id.as_str()].clone())
                    .collect()
            })
            .collect())
    }
}

fn parse_advisory(id: &str, v: &Value, eco: Ecosystem, name: &str) -> Advisory {
    let rated = v["database_specific"]["severity"]
        .as_str()
        .and_then(Severity::parse);
    let scored = v["severity"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| s["score"].as_str())
        .filter_map(|vector| cvss::Cvss::from_str(vector).ok())
        .map(|c| Severity::of_score(c.score()))
        .max();
    let fixed = v["affected"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|a| a["package"]["name"] == name && a["package"]["ecosystem"] == system(eco))
        .flat_map(|a| a["ranges"].as_array().into_iter().flatten())
        .flat_map(|r| r["events"].as_array().into_iter().flatten())
        .filter_map(|e| e["fixed"].as_str().map(String::from))
        .collect();
    let summary = v["summary"]
        .as_str()
        .or_else(|| v["details"].as_str())
        .unwrap_or("")
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    Advisory {
        id: id.into(),
        summary,
        // Unrated advisories count as moderate rather than being ignored.
        severity: rated.or(scored).unwrap_or(Severity::Moderate),
        malicious: id.starts_with("MAL-"),
        fixed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_from_rating_or_cvss() {
        let ghsa = json!({ "summary": "Prototype Pollution in lodash",
            "database_specific": { "severity": "HIGH" },
            "affected": [{ "package": { "name": "lodash", "ecosystem": "npm" },
                           "ranges": [{ "events": [{ "introduced": "0" }, { "fixed": "4.17.19" }] }] }] });
        let a = parse_advisory("GHSA-x", &ghsa, Ecosystem::Npm, "lodash");
        assert_eq!(
            (a.severity, a.fixed.as_slice()),
            (Severity::High, &["4.17.19".to_string()][..])
        );
        let rustsec = json!({ "summary": "x", "severity": [{ "type": "CVSS_V3",
            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }] });
        assert_eq!(
            parse_advisory("RUSTSEC-1", &rustsec, Ecosystem::Cargo, "x").severity,
            Severity::Critical
        );
        let mal = parse_advisory(
            "MAL-2026-1",
            &json!({ "summary": "Malicious code in x" }),
            Ecosystem::Npm,
            "x",
        );
        assert!(mal.malicious);
    }
}
