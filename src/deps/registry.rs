//! Publish dates from deps.dev — one API for npm, PyPI, crates.io, Go,
//! RubyGems, NuGet and Maven — and Packagist's own API for Composer; cached on
//! disk, since the date a version was published never changes.

mod packagist;

use super::ecosystem::{Ecosystem, Pinned};
use anyhow::{Result, bail};
use jiff::Timestamp;
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use serde::Deserialize;
use std::path::PathBuf;
use std::time::Duration;
use std::{env, fs};

const DEFAULT_API: &str = "https://api.deps.dev/v3";

pub struct Registry {
    agent: ureq::Agent,
    api: String,
    cache: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Version {
    published_at: Option<Timestamp>,
    #[serde(default)]
    advisory_keys: Vec<AdvisoryKey>,
}

#[derive(Deserialize)]
struct AdvisoryKey {
    id: String,
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
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(20)))
            .http_status_as_error(false)
            .user_agent(concat!("larpcop/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        let api = env::var("LARPCOP_DEPS_API").unwrap_or_else(|_| DEFAULT_API.to_string());
        Self {
            agent,
            api: api.trim_end_matches('/').to_string(),
            cache: crate::config::cache_root()
                .ok()
                .map(|d| d.join("published")),
        }
    }

    /// `Ok(None)`: deps.dev does not know this version (yet).
    pub fn published(&self, p: &Pinned) -> Result<Option<Timestamp>> {
        let cached = self.cache.as_ref().map(|dir| {
            dir.join(p.eco.deps_dev())
                .join(enc(&format!("{}@{}", p.name, p.version)))
        });
        if let Some(t) = cached
            .as_ref()
            .and_then(|f| fs::read_to_string(f).ok())
            .and_then(|s| s.trim().parse().ok())
        {
            return Ok(Some(t));
        }
        let Some(version) = self.version(p)? else {
            return Ok(None);
        };
        if let (Some(t), Some(file)) = (version.published_at, cached) {
            // Best effort: a missing cache only costs another request.
            if let Some(dir) = file.parent() {
                let _ = fs::create_dir_all(dir);
            }
            let _ = fs::write(file, t.to_string());
        }
        Ok(version.published_at)
    }

    /// Known advisories (OSV ids) affecting `p`. Never cached: new ones appear over time.
    pub fn advisories(&self, p: &Pinned) -> Result<Vec<String>> {
        Ok(self
            .version(p)?
            .map(|v| v.advisory_keys.into_iter().map(|k| k.id).collect())
            .unwrap_or_default())
    }

    fn version(&self, p: &Pinned) -> Result<Option<Version>> {
        if p.eco == Ecosystem::Packagist {
            let found = packagist::versions(&self.agent, &p.name)?.and_then(|all| {
                all.into_iter()
                    .find(|(v, _)| packagist::same(v, &p.version))
            });
            return Ok(found.map(|(_, t)| Version {
                published_at: Some(t),
                advisory_keys: Vec::new(),
            }));
        }
        let url = format!(
            "{}/systems/{}/packages/{}/versions/{}",
            self.api,
            p.eco.deps_dev(),
            enc(&p.name),
            enc(&p.version)
        );
        match self.get(&url)? {
            Some(body) => Ok(Some(serde_json::from_str(&body)?)),
            None => Ok(None),
        }
    }

    /// Every published version of a package; `None` if the registry does not know it.
    pub fn releases(&self, eco: Ecosystem, name: &str) -> Result<Option<Vec<Release>>> {
        if eco == Ecosystem::Packagist {
            let Some(all) = packagist::versions(&self.agent, name)? else {
                return Ok(None);
            };
            // Packagist has no "default" flag: the newest stable release is what installs.
            let newest = all
                .iter()
                .filter(|(v, _)| is_stable(v))
                .max_by_key(|(_, t)| *t)
                .map(|(v, _)| v.clone());
            return Ok(Some(
                all.into_iter()
                    .map(|(v, t)| {
                        let d = Some(&v) == newest.as_ref();
                        (v, t, d)
                    })
                    .collect(),
            ));
        }
        let url = format!(
            "{}/systems/{}/packages/{}",
            self.api,
            eco.deps_dev(),
            enc(name)
        );
        let Some(body) = self.get(&url)? else {
            return Ok(None);
        };
        let package: Package = serde_json::from_str(&body)?;
        Ok(Some(
            package
                .versions
                .into_iter()
                .filter_map(|v| Some((v.version_key.version, v.published_at?, v.is_default)))
                .collect(),
        ))
    }

    /// Newest stable release in the same major line as `p`, published by `cutoff`:
    /// a concrete version an agent can pin instead.
    pub fn newest_before(&self, p: &Pinned, cutoff: Timestamp) -> Option<(String, Timestamp)> {
        let line = major_line(&p.version);
        newest_stable(self.releases(p.eco, &p.name).ok()??, cutoff, |v| {
            major_line(v) == line
        })
    }

    /// Newest stable release of any line published by `cutoff`.
    pub fn newest_any_before(
        &self,
        eco: Ecosystem,
        name: &str,
        cutoff: Timestamp,
    ) -> Option<(String, Timestamp)> {
        newest_stable(self.releases(eco, name).ok()??, cutoff, |_| true)
    }

    fn get(&self, url: &str) -> Result<Option<String>> {
        let mut resp = self.agent.get(url).call()?;
        match resp.status().as_u16() {
            200 => Ok(Some(resp.body_mut().read_to_string()?)),
            404 => Ok(None),
            status => bail!("deps.dev answered HTTP {status}"),
        }
    }
}

fn newest_stable(
    all: Vec<Release>,
    cutoff: Timestamp,
    keep: impl Fn(&str) -> bool,
) -> Option<(String, Timestamp)> {
    all.into_iter()
        .filter(|(v, t, _)| *t <= cutoff && is_stable(v) && keep(v))
        .map(|(v, t, _)| (v, t))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_lines() {
        assert_eq!(major_line("4.17.21"), "4");
        assert_eq!(major_line("v0.13.2"), "0.13");
        assert_eq!(major_line("6.1.0-dev.20261031"), "6");
        assert!(is_stable("v1.8.1") && is_stable("2.32.3"));
        assert!(!is_stable("1.0.0-rc.1") && !is_stable("1.0a1"));
    }
}
