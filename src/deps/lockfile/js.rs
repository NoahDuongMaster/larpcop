//! JavaScript lockfiles: npm, pnpm, yarn (v1 and Berry) and bun.

use super::super::ecosystem::{Ecosystem, Pinned};
use anyhow::{Result, anyhow, bail};
use serde::Deserialize;
use std::collections::BTreeMap;

const NPM_REGISTRIES: [&str; 2] = [
    "https://registry.npmjs.org/",
    "https://registry.yarnpkg.com/",
];

fn public_npm(resolved: Option<&str>) -> bool {
    resolved.is_none_or(|r| NPM_REGISTRIES.iter().any(|reg| r.starts_with(reg)))
}

#[derive(Deserialize)]
struct NpmLock {
    #[serde(rename = "lockfileVersion", default)]
    version: u32,
    #[serde(default)]
    packages: BTreeMap<String, NpmEntry>,
}

#[derive(Deserialize)]
struct NpmEntry {
    name: Option<String>,
    version: Option<String>,
    resolved: Option<String>,
    #[serde(default)]
    link: bool,
}

pub(super) fn npm(content: &str) -> Result<Vec<Pinned>> {
    const PREFIX: &str = "node_modules/";
    let lock: NpmLock = serde_json::from_str(content)?;
    if lock.version < 2 {
        bail!(
            "lockfileVersion {} is not supported; regenerate it with npm 7 or newer",
            lock.version
        );
    }
    Ok(lock
        .packages
        .into_iter()
        .filter_map(|(path, e)| {
            let at = path.rfind(PREFIX)?;
            if e.link || !public_npm(e.resolved.as_deref()) {
                return None;
            }
            // Aliases (`"x": "npm:real@1"`) carry the real package in `name`.
            let name = e
                .name
                .unwrap_or_else(|| path[at + PREFIX.len()..].to_string());
            Some(Pinned::new(Ecosystem::Npm, &name, &e.version?))
        })
        .collect())
}

#[derive(Deserialize)]
struct PnpmLock {
    #[serde(default)]
    packages: BTreeMap<String, PnpmEntry>,
}

#[derive(Deserialize, Default)]
struct PnpmEntry {
    #[serde(default)]
    resolution: PnpmResolution,
}

#[derive(Deserialize, Default)]
struct PnpmResolution {
    tarball: Option<String>,
    /// Set for git and directory resolutions.
    #[serde(rename = "type")]
    kind: Option<String>,
}

pub(super) fn pnpm(content: &str) -> Result<Vec<Pinned>> {
    let lock: PnpmLock = serde_saphyr::from_str(content)?;
    Ok(lock
        .packages
        .iter()
        .filter(|(_, e)| e.resolution.kind.is_none() && public_npm(e.resolution.tarball.as_deref()))
        .filter_map(|(key, _)| pnpm_key(key))
        .map(|(name, version)| Pinned::new(Ecosystem::Npm, name, version))
        .collect())
}

/// `name@1.2.3` (v9), `/name@1.2.3(peer@1)` (v6–v8), `/name/1.2.3_peer@1` (v5).
pub(super) fn pnpm_key(key: &str) -> Option<(&str, &str)> {
    let key = key.strip_prefix('/').unwrap_or(key);
    let key = key.split('(').next()?;
    let modern = key.get(1..)?.find('@').map(|i| (&key[..=i], &key[i + 2..]));
    let legacy = key
        .rfind('/')
        .and_then(|s| Some((&key[..s], key[s + 1..].split('_').next()?)));
    [modern, legacy]
        .into_iter()
        .flatten()
        .find(|(n, v)| valid_npm_name(n) && v.starts_with(|c: char| c.is_ascii_digit()))
}

fn valid_npm_name(name: &str) -> bool {
    match name.strip_prefix('@') {
        Some(scoped) => scoped.matches('/').count() == 1,
        None => !name.is_empty() && !name.contains('/'),
    }
}

/// v1 `resolved` is a tarball URL; berry `resolution` is `name@npm:1.2.3`
/// (other protocols: workspace, patch, git, file…).
pub(super) fn yarn(content: &str) -> Result<Vec<Pinned>> {
    let lock = yarn_lock_parser::parse_str(content).map_err(|e| anyhow!("{e}"))?;
    Ok(lock
        .entries
        .iter()
        .filter(|e| {
            let r = e.resolved;
            r.is_empty() || public_npm(Some(r)) || (r.contains("@npm:") && !r.contains("@patch:"))
        })
        .map(|e| Pinned::new(Ecosystem::Npm, e.name, e.version))
        .collect())
}

/// bun.lock (text lockfile, JSONC): `"key": ["name@version", "<registry>", {deps}, "sha512-…"]`.
/// The registry is `""` for the default one; workspace, git, file and link
/// entries have another protocol after `@` or no registry string.
pub(super) fn bun(content: &str) -> Result<Vec<Pinned>> {
    #[derive(Deserialize)]
    struct BunLock {
        #[serde(default)]
        packages: BTreeMap<String, Vec<serde_json::Value>>,
    }
    let lock: BunLock = jsonc_parser::parse_to_serde_value(content, &Default::default())
        .map_err(|e| anyhow!("{e}"))?;
    Ok(lock
        .packages
        .values()
        .filter_map(|entry| {
            let spec = entry.first()?.as_str()?;
            let registry = entry.get(1)?.as_str()?;
            if !(registry.is_empty() || public_npm(Some(registry))) {
                return None;
            }
            let at = spec.get(1..)?.find('@')? + 1;
            let (name, version) = (&spec[..at], &spec[at + 1..]);
            version
                .starts_with(|c: char| c.is_ascii_digit())
                .then(|| Pinned::new(Ecosystem::Npm, name, version))
        })
        .collect())
}
