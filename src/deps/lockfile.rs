//! Exact versions a lockfile pins. Only packages from the public registry count:
//! private registries, git, path and workspace entries have no public publish date.

#[cfg(test)]
mod tests;

use super::ecosystem::{Ecosystem, Pinned};
use anyhow::{Context, Result, anyhow, bail};
use serde::Deserialize;
use std::collections::BTreeMap;

/// `None` when `file_name` is not a lockfile agentkit reads.
pub fn parse(file_name: &str, content: &str) -> Option<Result<Vec<Pinned>>> {
    let parsed = match file_name {
        "package-lock.json" | "npm-shrinkwrap.json" => npm(content),
        "pnpm-lock.yaml" => pnpm(content),
        "yarn.lock" => yarn(content),
        "Cargo.lock" => cargo(content),
        "uv.lock" => uv(content),
        "poetry.lock" => poetry(content),
        "go.mod" => Ok(go_requires(content)
            .into_iter()
            .map(|r| Pinned::new(Ecosystem::Go, &r.module, &r.version))
            .collect()),
        _ => return None,
    };
    Some(parsed.with_context(|| format!("reading {file_name}")))
}

/// Line where `p` is pinned, for annotations; 0 when not found.
pub fn line_of(file_name: &str, content: &str, p: &Pinned) -> usize {
    let needles = match file_name {
        "package-lock.json" | "npm-shrinkwrap.json" => vec![format!("\"node_modules/{}\"", p.name)],
        "pnpm-lock.yaml" | "yarn.lock" => vec![p.to_string(), format!("{}@", p.name)],
        "go.mod" => vec![format!("{} {}", p.name, p.version)],
        _ => vec![format!("name = \"{}\"", p.name)],
    };
    needles
        .iter()
        .find_map(|n| content.lines().position(|l| l.contains(n.as_str())))
        .map_or(0, |i| i + 1)
}

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

fn npm(content: &str) -> Result<Vec<Pinned>> {
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

fn pnpm(content: &str) -> Result<Vec<Pinned>> {
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
fn pnpm_key(key: &str) -> Option<(&str, &str)> {
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
fn yarn(content: &str) -> Result<Vec<Pinned>> {
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

#[derive(Deserialize)]
struct TomlLock<P> {
    #[serde(default = "Vec::new")]
    package: Vec<P>,
}

#[derive(Deserialize)]
struct CargoPackage {
    name: String,
    version: String,
    source: Option<String>,
}

fn cargo(content: &str) -> Result<Vec<Pinned>> {
    const CRATES_IO: [&str; 2] = [
        "registry+https://github.com/rust-lang/crates.io-index",
        "sparse+https://index.crates.io/",
    ];
    let lock: TomlLock<CargoPackage> = toml::from_str(content)?;
    Ok(lock
        .package
        .into_iter()
        .filter(|p| p.source.as_deref().is_some_and(|s| CRATES_IO.contains(&s)))
        .map(|p| Pinned::new(Ecosystem::Cargo, &p.name, &p.version))
        .collect())
}

#[derive(Deserialize)]
struct UvPackage {
    name: String,
    version: Option<String>,
    #[serde(default)]
    source: BTreeMap<String, toml::Value>,
}

fn uv(content: &str) -> Result<Vec<Pinned>> {
    let lock: TomlLock<UvPackage> = toml::from_str(content)?;
    Ok(lock
        .package
        .into_iter()
        .filter(|p| {
            p.source
                .get("registry")
                .and_then(toml::Value::as_str)
                .is_some_and(|r| r.starts_with("https://pypi.org/"))
        })
        .filter_map(|p| Some(Pinned::new(Ecosystem::PyPI, &p.name, &p.version?)))
        .collect())
}

#[derive(Deserialize)]
struct PoetryPackage {
    name: String,
    version: String,
    source: Option<PoetrySource>,
}

#[derive(Deserialize)]
struct PoetrySource {
    url: Option<String>,
}

fn poetry(content: &str) -> Result<Vec<Pinned>> {
    let lock: TomlLock<PoetryPackage> = toml::from_str(content)?;
    Ok(lock
        .package
        .into_iter()
        .filter(|p| match &p.source {
            None => true,
            Some(s) => s.url.as_deref().is_some_and(|u| u.contains("://pypi.org/")),
        })
        .map(|p| Pinned::new(Ecosystem::PyPI, &p.name, &p.version))
        .collect())
}

pub struct GoRequire {
    pub module: String,
    pub version: String,
    pub indirect: bool,
}

/// `require` entries of a go.mod: since Go 1.17 they list every module the build uses.
pub fn go_requires(content: &str) -> Vec<GoRequire> {
    let mut out = Vec::new();
    let mut in_block = false;
    for line in content.lines().map(str::trim) {
        let entry = if in_block {
            if line.starts_with(')') {
                in_block = false;
                continue;
            }
            line
        } else if let Some(rest) = line.strip_prefix("require")
            && rest.starts_with([' ', '\t', '('])
        {
            let rest = rest.trim();
            if rest.starts_with('(') {
                in_block = true;
                continue;
            }
            rest
        } else {
            continue;
        };
        let indirect = entry.contains("// indirect");
        let mut parts = entry.split("//").next().unwrap_or("").split_whitespace();
        if let (Some(module), Some(version)) = (parts.next(), parts.next()) {
            out.push(GoRequire {
                module: module.trim_matches('"').to_string(),
                version: version.to_string(),
                indirect,
            });
        }
    }
    out
}
