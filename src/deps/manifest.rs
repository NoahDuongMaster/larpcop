//! Direct dependencies a manifest declares: what someone chose to depend on.

use super::ecosystem::{Ecosystem, npm_spec_name};
use super::lockfile::go_requires;
use anyhow::{Context, Result};
use std::collections::BTreeSet;
use toml::{Table, Value};

pub type Direct = BTreeSet<(Ecosystem, String)>;

mod other;

/// Manifests with a fixed name (plus `requirements*.txt` and .NET project files).
const NAMES: [&str; 11] = [
    "package.json",
    "Cargo.toml",
    "pyproject.toml",
    "go.mod",
    "requirements.txt",
    "Gemfile",
    "composer.json",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "libs.versions.toml",
];

pub fn is_manifest(file_name: &str) -> bool {
    NAMES.contains(&file_name)
        || is_requirements(file_name)
        || super::lockfile::is_project_file(file_name)
}

fn is_requirements(name: &str) -> bool {
    name.starts_with("requirements") && name.ends_with(".txt")
}

/// `None` when `file_name` is not a manifest larpcop reads.
pub fn parse(file_name: &str, content: &str) -> Option<Result<Direct>> {
    let parsed = match file_name {
        "package.json" => package_json(content),
        "Cargo.toml" => cargo_toml(content),
        "pyproject.toml" => pyproject(content),
        "go.mod" => Ok(go_requires(content)
            .into_iter()
            .filter(|r| !r.indirect)
            .map(|r| (Ecosystem::Go, r.module))
            .collect()),
        n if is_requirements(n) => Ok(requirements(content)),
        "Gemfile" => Ok(other::gemfile(content)),
        "composer.json" => other::composer_json(content),
        "pom.xml" => other::pom(content),
        "build.gradle" | "build.gradle.kts" => Ok(other::gradle(content)),
        "libs.versions.toml" => other::version_catalog(content),
        n if super::lockfile::is_project_file(n) => other::csproj(content),
        _ => return None,
    };
    Some(parsed.with_context(|| format!("reading {file_name}")))
}

/// First line naming the dependency, for annotations; 0 when not found.
pub fn line_of(content: &str, name: &str) -> usize {
    let lower = name.to_ascii_lowercase();
    let artifact = lower.rsplit(':').next().unwrap_or(&lower);
    let needles = [
        format!("\"{lower}\""),
        format!("'{lower}'"),
        format!("\"{lower}:"),
        format!("'{lower}:"),
        format!("<artifactid>{artifact}</artifactid>"),
    ];
    content
        .lines()
        .position(|l| {
            let t = l.trim_start().to_ascii_lowercase();
            t.starts_with(&lower) || needles.iter().any(|n| t.contains(n.as_str()))
        })
        .map_or(0, |i| i + 1)
}

fn package_json(content: &str) -> Result<Direct> {
    const SECTIONS: [&str; 4] = [
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ];
    const LOCAL: [&str; 4] = ["workspace:", "file:", "link:", "portal:"];
    let doc: serde_json::Value = serde_json::from_str(content)?;
    let mut out = Direct::new();
    for section in SECTIONS {
        let Some(deps) = doc.get(section).and_then(|d| d.as_object()) else {
            continue;
        };
        for (key, spec) in deps {
            let spec = spec.as_str().unwrap_or("");
            if LOCAL.iter().any(|p| spec.starts_with(p)) {
                continue;
            }
            // `"alias": "npm:real@^1"` installs `real`.
            let name = spec
                .strip_prefix("npm:")
                .map_or(key.as_str(), npm_spec_name);
            out.insert((Ecosystem::Npm, name.to_string()));
        }
    }
    Ok(out)
}

fn cargo_toml(content: &str) -> Result<Direct> {
    const SECTIONS: [&str; 3] = ["dependencies", "dev-dependencies", "build-dependencies"];
    let doc: Table = toml::from_str(content)?;
    let sections = |t: &Table| -> Vec<Table> {
        SECTIONS
            .iter()
            .filter_map(|s| t.get(*s).and_then(Value::as_table).cloned())
            .collect()
    };
    let mut tables = sections(&doc);
    if let Some(ws) = doc.get("workspace").and_then(Value::as_table) {
        tables.extend(ws.get("dependencies").and_then(Value::as_table).cloned());
    }
    if let Some(targets) = doc.get("target").and_then(Value::as_table) {
        for target in targets.values().filter_map(Value::as_table) {
            tables.extend(sections(target));
        }
    }
    let mut out = Direct::new();
    for (key, spec) in tables.iter().flat_map(|t| t.iter()) {
        let detail = spec.as_table();
        // Path dependencies are local code; `workspace = true` is declared at the root.
        let local = detail.is_some_and(|d| {
            d.contains_key("path") || d.get("workspace").and_then(Value::as_bool) == Some(true)
        });
        if local {
            continue;
        }
        let name = detail
            .and_then(|d| d.get("package"))
            .and_then(Value::as_str)
            .unwrap_or(key);
        out.insert((Ecosystem::Cargo, name.to_string()));
    }
    Ok(out)
}

fn pyproject(content: &str) -> Result<Direct> {
    fn strings<'a>(v: Option<&'a Value>, out: &mut Vec<&'a str>) {
        let items = v.and_then(Value::as_array).into_iter().flatten();
        out.extend(items.filter_map(Value::as_str));
    }
    let doc: Table = toml::from_str(content)?;
    let mut specs: Vec<&str> = Vec::new();
    if let Some(project) = doc.get("project") {
        strings(project.get("dependencies"), &mut specs);
        if let Some(extras) = project
            .get("optional-dependencies")
            .and_then(Value::as_table)
        {
            extras.values().for_each(|v| strings(Some(v), &mut specs));
        }
    }
    if let Some(groups) = doc.get("dependency-groups").and_then(Value::as_table) {
        groups.values().for_each(|v| strings(Some(v), &mut specs));
    }
    let mut names: Vec<&str> = specs.into_iter().filter_map(pep508_name).collect();
    if let Some(poetry) = doc.get("tool").and_then(|t| t.get("poetry")) {
        let mut tables = vec![poetry.get("dependencies"), poetry.get("dev-dependencies")];
        if let Some(groups) = poetry.get("group").and_then(Value::as_table) {
            tables.extend(groups.values().map(|g| g.get("dependencies")));
        }
        for t in tables.into_iter().flatten().filter_map(Value::as_table) {
            names.extend(t.keys().map(String::as_str).filter(|k| *k != "python"));
        }
    }
    Ok(names
        .into_iter()
        .map(|n| (Ecosystem::PyPI, Ecosystem::PyPI.normalize(n)))
        .collect())
}

fn requirements(content: &str) -> Direct {
    content
        .lines()
        .map(|l| l.split(" #").next().unwrap_or("").trim())
        .filter(|l| !l.is_empty() && !l.starts_with(['#', '-', '.', '/']) && !l.contains("://"))
        .filter_map(pep508_name)
        .map(|n| (Ecosystem::PyPI, Ecosystem::PyPI.normalize(n)))
        .collect()
}

/// Distribution name at the start of a PEP 508 requirement (`requests[socks]>=2`).
pub fn pep508_name(spec: &str) -> Option<&str> {
    let s = spec.trim();
    let end = s
        .find(|c: char| !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')))
        .unwrap_or(s.len());
    (end > 0).then(|| &s[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(file: &str, content: &str) -> Vec<String> {
        let direct = parse(file, content).unwrap().unwrap();
        direct
            .into_iter()
            .map(|(e, n)| format!("{e}:{n}"))
            .collect()
    }

    #[test]
    fn manifests() {
        let pkg = r#"{"dependencies": {"left-pad": "^1", "ui": "workspace:*", "pad": "npm:@acme/pad@^2"},
                      "devDependencies": {"@types/node": "^22"}}"#;
        assert_eq!(
            names("package.json", pkg),
            ["npm:@acme/pad", "npm:@types/node", "npm:left-pad"]
        );
        let cargo = "[dependencies]\nserde = { version = \"1\", features = [\"derive\"] }\n\
                     local = { path = \"../local\" }\nshared = { workspace = true }\n\
                     [target.'cfg(unix)'.dependencies]\nlibc = \"0.2\"\n\
                     [dev-dependencies]\nrenamed = { package = \"tempfile\", version = \"3\" }\n";
        assert_eq!(
            names("Cargo.toml", cargo),
            ["cargo:libc", "cargo:serde", "cargo:tempfile"]
        );
        let py = "[project]\ndependencies = [\"Requests[socks]>=2.31\", \"zope.interface\"]\n\
                  [project.optional-dependencies]\ndev = [\"pytest\"]\n\
                  [dependency-groups]\nlint = [\"ruff==0.6\", { include-group = \"dev\" }]\n\
                  [tool.poetry.dependencies]\npython = \"^3.11\"\nDjango = \"^5\"\n";
        assert_eq!(
            names("pyproject.toml", py),
            [
                "pypi:django",
                "pypi:pytest",
                "pypi:requests",
                "pypi:ruff",
                "pypi:zope-interface"
            ]
        );
        let req = "# pinned\nflask==3.0.0  # web\n-r base.txt\n-e .\nhttps://x.example/pkg.whl\n";
        assert_eq!(names("requirements-dev.txt", req), ["pypi:flask"]);
        assert!(parse("README.md", "").is_none());
    }
}
