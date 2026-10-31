//! Exact versions a lockfile pins. Only packages from the public registry count:
//! private registries, git, path and workspace entries have no public publish date.

mod js;
#[cfg(test)]
mod tests;

use super::ecosystem::{Ecosystem, Pinned};
use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;

/// `None` when `file_name` is not a lockfile agentkit reads.
pub fn parse(file_name: &str, content: &str) -> Option<Result<Vec<Pinned>>> {
    let parsed = match file_name {
        "package-lock.json" | "npm-shrinkwrap.json" => js::npm(content),
        "pnpm-lock.yaml" => js::pnpm(content),
        "yarn.lock" => js::yarn(content),
        "bun.lock" => js::bun(content),
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
        "bun.lock" => vec![format!("\"{p}\"")],
        _ => vec![format!("name = \"{}\"", p.name)],
    };
    needles
        .iter()
        .find_map(|n| content.lines().position(|l| l.contains(n.as_str())))
        .map_or(0, |i| i + 1)
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
