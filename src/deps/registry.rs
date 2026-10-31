//! Publish dates from deps.dev — one API for npm, PyPI, crates.io and Go —
//! cached on disk, since the date a version was published never changes.

use super::ecosystem::Pinned;
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
}

#[derive(Deserialize)]
struct VersionKey {
    version: String,
}

impl Registry {
    pub fn new() -> Self {
        let agent = ureq::Agent::config_builder()
            .timeout_global(Some(Duration::from_secs(20)))
            .http_status_as_error(false)
            .user_agent(concat!("agentkit/", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        let api = env::var("AGENTKIT_DEPS_API").unwrap_or_else(|_| DEFAULT_API.to_string());
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

    /// Newest stable release in the same major line as `p`, published by `cutoff`:
    /// a concrete version an agent can pin instead.
    pub fn newest_before(&self, p: &Pinned, cutoff: Timestamp) -> Option<(String, Timestamp)> {
        let url = format!(
            "{}/systems/{}/packages/{}",
            self.api,
            p.eco.deps_dev(),
            enc(&p.name)
        );
        let package: Package = serde_json::from_str(&self.get(&url).ok()??).ok()?;
        let line = major_line(&p.version);
        package
            .versions
            .into_iter()
            .filter_map(|v| Some((v.version_key.version, v.published_at?)))
            .filter(|(v, t)| *t <= cutoff && is_stable(v) && major_line(v) == line)
            .max_by_key(|(_, t)| *t)
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
