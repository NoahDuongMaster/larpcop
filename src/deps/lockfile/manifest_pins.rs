//! Exact versions pinned in manifests, for projects without a lockfile:
//! `requirements*.txt` (`name==1.2.3`) and `package.json` (`"x": "1.2.3"`).
//! With a lockfile next to (or above) the manifest, the lockfile is the
//! record and these are not read.

use super::super::ecosystem::{Ecosystem, Pinned};
use anyhow::Result;

/// The lockfiles that make a manifest's own pins redundant.
pub fn superseded_by(file_name: &str) -> &'static [&'static str] {
    if file_name == "package.json" {
        &[
            "package-lock.json",
            "npm-shrinkwrap.json",
            "pnpm-lock.yaml",
            "yarn.lock",
            "bun.lock",
        ]
    } else {
        &["uv.lock", "poetry.lock", "Pipfile.lock", "pdm.lock"]
    }
}

pub fn requirements(content: &str) -> Vec<Pinned> {
    content
        .lines()
        .filter_map(|l| {
            let l = l.split(" #").next()?.split(';').next()?.trim();
            if l.starts_with(['#', '-']) || l.contains("://") {
                return None;
            }
            let (name, version) = l.split_once("==")?;
            let name = name.split('[').next()?.trim();
            let version = version.split([',', ' ', '\\']).next()?.trim();
            (!name.is_empty()
                && version.starts_with(|c: char| c.is_ascii_digit())
                && !version.contains('*'))
            .then(|| Pinned::new(Ecosystem::PyPI, &Ecosystem::PyPI.normalize(name), version))
        })
        .collect()
}

pub fn package_json(content: &str) -> Result<Vec<Pinned>> {
    let doc: serde_json::Value = serde_json::from_str(content)?;
    fn exact(v: &str) -> Option<&str> {
        let v = v.trim_start_matches('=');
        let core = v.split(['-', '+']).next().unwrap_or("");
        let parts: Vec<&str> = core.split('.').collect();
        (parts.len() == 3
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit())))
        .then_some(v)
    }
    let mut out = Vec::new();
    for key in ["dependencies", "devDependencies", "optionalDependencies"] {
        let Some(deps) = doc[key].as_object() else {
            continue;
        };
        for (name, spec) in deps {
            if let Some(v) = spec.as_str().and_then(exact) {
                out.push(Pinned::new(Ecosystem::Npm, name, v));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #[test]
    fn exact_pins_only() {
        let req = "# deps\nrequests==2.19.1\nFlask[async]==2.0.0 ; python_version > '3.7'\nnumpy>=1.20\n-r base.txt\npkg @ https://x/y.whl\nDjango==3.2.* \n";
        let pins: Vec<String> = super::requirements(req)
            .iter()
            .map(|p| p.to_string())
            .collect();
        assert_eq!(pins, ["requests@2.19.1", "flask@2.0.0"]);
        let pkg = r#"{"dependencies": {"mathjs": "3.10.1", "express": "^4.17.1", "x": "=1.0.0", "y": "1.0.0-rc.1"},
                       "devDependencies": {"jest": "~29.0.0"}}"#;
        let pins: Vec<String> = super::package_json(pkg)
            .unwrap()
            .iter()
            .map(|p| p.to_string())
            .collect();
        assert_eq!(pins, ["mathjs@3.10.1", "x@1.0.0", "y@1.0.0-rc.1"]);
    }
}
