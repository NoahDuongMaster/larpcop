//! Publish dates from deps.dev — one API for npm, PyPI, crates.io, Go,
//! RubyGems, NuGet and Maven — and Packagist's own API for Composer; cached on
//! disk, since the date a version was published never changes.

mod memo;
mod packagist;
#[cfg(test)]
mod tests;

use super::ecosystem::{Ecosystem, Pinned};
use super::net;
use anyhow::{Result, bail};
use jiff::Timestamp;
use memo::Memo;
use packagist::Tags;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use std::{env, fs};

const DEFAULT_API: &str = "https://api.deps.dev/v3";

pub struct Registry {
    agent: ureq::Agent,
    api: String,
    packagist_api: String,
    cache: Option<PathBuf>,
    /// Documents fetched during this run, so a package asked about for several
    /// versions (or for its default release, then an older one) costs one request.
    releases: Memo<(Ecosystem, String), Option<Arc<Vec<Release>>>>,
    composer: Memo<String, Option<Arc<Tags>>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Version {
    published_at: Option<Timestamp>,
}

#[derive(Deserialize)]
struct Package {
    versions: Vec<PackageVersion>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PackageVersion {
    version_key: VersionKey,
    published_at: Option<Timestamp>,
    #[serde(default)]
    is_default: bool,
}

/// A published version: (version, publish time, is the registry's default/latest).
pub type Release = (String, Timestamp, bool);

#[derive(Deserialize)]
struct VersionKey {
    version: String,
}

impl Registry {
    pub fn new() -> Self {
        let api = env::var("LARPCOP_DEPS_API").unwrap_or_else(|_| DEFAULT_API.to_string());
        let packagist = env::var("LARPCOP_PACKAGIST_API").unwrap_or_else(|_| packagist::API.into());
        let cache = crate::config::cache_root()
            .ok()
            .map(|d| d.join("published"));
        Self::at(&api, &packagist, cache)
    }

    pub(super) fn at(api: &str, packagist_api: &str, cache: Option<PathBuf>) -> Self {
        Self {
            agent: net::agent(Duration::from_secs(20)),
            api: api.trim_end_matches('/').to_string(),
            packagist_api: packagist_api.trim_end_matches('/').to_string(),
            cache,
            releases: Memo::new(),
            composer: Memo::new(),
        }
    }

    /// `Ok(None)`: deps.dev does not know this version (yet).
    pub fn published(&self, p: &Pinned) -> Result<Option<Timestamp>> {
        let cached = self.cache.as_ref().map(|dir| {
            dir.join(p.eco.label())
                .join(enc(&format!("{}@{}", p.name, p.version)))
        });
        if let Some(t) = cached
            .as_ref()
            .and_then(|f| fs::read_to_string(f).ok())
            .and_then(|s| s.trim().parse().ok())
        {
            return Ok(Some(t));
        }
        let Some(t) = self.fetch_published(p)? else {
            return Ok(None);
        };
        if let Some(file) = cached {
            // Best effort: a missing cache only costs another request.
            if let Some(dir) = file.parent() {
                let _ = fs::create_dir_all(dir);
            }
            let _ = fs::write(file, t.to_string());
        }
        Ok(Some(t))
    }

    fn fetch_published(&self, p: &Pinned) -> Result<Option<Timestamp>> {
        if p.eco == Ecosystem::Packagist {
            let all = self.composer(&p.name)?;
            let found = all.and_then(|all| {
                all.iter()
                    .find(|(v, _)| packagist::same(v, &p.version))
                    .map(|(_, t)| *t)
            });
            return Ok(found);
        }
        let url = format!(
            "{}/systems/{}/packages/{}/versions/{}",
            self.api,
            p.eco.label(),
            enc(&p.name),
            enc(&p.version)
        );
        match self.get(&url)? {
            Some(body) => Ok(serde_json::from_str::<Version>(&body)?.published_at),
            None => Ok(None),
        }
    }

    /// Every tagged version of a Composer package, one request per package.
    fn composer(&self, name: &str) -> Result<Option<Arc<Tags>>> {
        self.composer.get(name.to_string(), || {
            let all = packagist::versions(&self.agent, &self.packagist_api, name)?;
            Ok(all.map(Arc::new))
        })
    }

    /// Every published version of a package; `None` if the registry does not know it.
    pub fn releases(&self, eco: Ecosystem, name: &str) -> Result<Option<Arc<Vec<Release>>>> {
        self.releases.get((eco, name.to_string()), || {
            if eco == Ecosystem::Packagist {
                let Some(all) = self.composer(name)? else {
                    return Ok(None);
                };
                // Packagist has no "default" flag: the newest stable release is what installs.
                let newest = all
                    .iter()
                    .filter(|(v, _)| is_stable(v))
                    .max_by_key(|(_, t)| *t)
                    .map(|(v, _)| v.clone());
                return Ok(Some(Arc::new(
                    all.iter()
                        .map(|(v, t)| (v.clone(), *t, Some(v) == newest.as_ref()))
                        .collect(),
                )));
            }
            let url = format!(
                "{}/systems/{}/packages/{}",
                self.api,
                eco.label(),
                enc(name)
            );
            let Some(body) = self.get(&url)? else {
                return Ok(None);
            };
            let package: Package = serde_json::from_str(&body)?;
            Ok(Some(Arc::new(
                package
                    .versions
                    .into_iter()
                    .filter_map(|v| Some((v.version_key.version, v.published_at?, v.is_default)))
                    .collect(),
            )))
        })
    }

    /// Newest stable release in the same major line as `p`, published by `cutoff`:
    /// a concrete version an agent can pin instead.
    pub fn newest_before(
        &self,
        p: &Pinned,
        cutoff: Timestamp,
    ) -> Result<Option<(String, Timestamp)>> {
        let line = major_line(&p.version);
        let all = self.releases(p.eco, &p.name)?;
        Ok(all.and_then(|all| newest_stable(&all, cutoff, |v| major_line(v) == line)))
    }

    /// Newest stable release of any line published by `cutoff`.
    pub fn newest_any_before(
        &self,
        eco: Ecosystem,
        name: &str,
        cutoff: Timestamp,
    ) -> Result<Option<(String, Timestamp)>> {
        let all = self.releases(eco, name)?;
        Ok(all.and_then(|all| newest_stable(&all, cutoff, |_| true)))
    }

    fn get(&self, url: &str) -> Result<Option<String>> {
        match net::fetch(|| self.agent.get(url).call())? {
            (200, body) => Ok(Some(body)),
            (404, _) => Ok(None),
            (status, _) => bail!("deps.dev answered HTTP {status}"),
        }
    }
}

fn newest_stable(
    all: &[Release],
    cutoff: Timestamp,
    keep: impl Fn(&str) -> bool,
) -> Option<(String, Timestamp)> {
    all.iter()
        .filter(|(v, t, _)| *t <= cutoff && is_stable(v) && keep(v))
        .map(|(v, t, _)| (v.clone(), *t))
        .max_by_key(|(_, t)| *t)
}

fn enc(s: &str) -> String {
    utf8_percent_encode(s, NON_ALPHANUMERIC).to_string()
}

fn is_stable(version: &str) -> bool {
    let v = version.strip_prefix('v').unwrap_or(version);
    !v.is_empty() && v.chars().all(|c| c.is_ascii_digit() || c == '.')
}

/// `4.17.21` → `4`; `0.13.2` → `0.13` (in 0.x the minor is the breaking part).
fn major_line(version: &str) -> String {
    let v = version.strip_prefix('v').unwrap_or(version);
    let mut parts = v.split(|c: char| !c.is_ascii_digit());
    let major = parts.next().unwrap_or("");
    if major == "0" {
        format!("0.{}", parts.next().unwrap_or(""))
    } else {
        major.to_string()
    }
}
