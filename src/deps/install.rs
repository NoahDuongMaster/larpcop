//! Package installs inside a shell command, so an agent hook can stop an
//! unapproved package before any of its install scripts run.

use super::ecosystem::{Ecosystem, npm_spec_name};
use super::manifest::pep508_name;
use regex::Regex;
use std::sync::LazyLock;

pub struct Request {
    pub eco: Ecosystem,
    pub spec: String,
    /// Registry package name; `None` for git URLs, tarballs and paths.
    pub name: Option<String>,
}

/// Flags that take a separate value, per tool: their value is not a package.
const NPM_FLAGS: &[&str] = &[
    "--registry",
    "--prefix",
    "-w",
    "--workspace",
    "--tag",
    "--cache",
    "--userconfig",
    "--omit",
    "--include",
];
const PNPM_FLAGS: &[&str] = &["--filter", "-F", "--dir", "-C", "--registry", "--store-dir"];
const YARN_FLAGS: &[&str] = &["--cwd", "--registry"];
const BUN_FLAGS: &[&str] = &[
    "--cwd",
    "--registry",
    "-c",
    "--config",
    "--cache-dir",
    "--backend",
];
const PIP_FLAGS: &[&str] = &[
    "-r",
    "--requirement",
    "-c",
    "--constraint",
    "-e",
    "--editable",
    "-i",
    "--index-url",
    "--extra-index-url",
    "-f",
    "--find-links",
    "-t",
    "--target",
    "--prefix",
    "--root",
    "--python",
    "-p",
    "--group",
    "--optional",
    "--extra",
    "--platform",
    "--python-version",
    "-P",
    "--upgrade-package",
];
const CARGO_FLAGS: &[&str] = &[
    "--git",
    "--path",
    "-p",
    "--package",
    "-F",
    "--features",
    "--rename",
    "--registry",
    "--branch",
    "--tag",
    "--rev",
    "--manifest-path",
    "--target",
];

pub fn requests(command: &str) -> Vec<Request> {
    crate::shell_ast::parse(command)
        .commands
        .iter()
        .flat_map(|c| parse(&c.words))
        .collect()
}

/// Commands that switch off or shorten a package manager's minimum release age.
pub fn weakens_age_gate(command: &str) -> bool {
    static OVERRIDE: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"(?i)(--|\.)min(imum)?-release-age|\b(npm|pnpm)_config_min(imum)?_release_age\s*=|YARN_NPM_MINIMAL_AGE_GATE\s*=|\b(npm|pnpm|yarn|bun)\b[^;&|\n]*\bconfig\s+(set|delete|rm|unset)\b[^;&|\n]*(min(imum)?-?release-?age|npmMinimalAgeGate)|\buv\b[^;&|\n]*--exclude-newer|UV_EXCLUDE_NEWER\s*=",
        )
        .expect("static regex")
    });
    OVERRIDE.is_match(command)
}

fn parse(tokens: &[String]) -> Vec<Request> {
    let mut t: Vec<&str> = tokens.iter().map(String::as_str).collect();
    if t.len() > 2 && t[0].starts_with("python") && t[1] == "-m" {
        t.drain(..2); // python -m pip install …
    }
    use Ecosystem::*;
    let (eco, args, value_flags) = match t.as_slice() {
        ["npm", "install" | "i" | "add" | "in", rest @ ..] => (Npm, rest, NPM_FLAGS),
        ["pnpm", "add" | "install" | "i", rest @ ..] => (Npm, rest, PNPM_FLAGS),
        ["yarn", "add", rest @ ..] => (Npm, rest, YARN_FLAGS),
        ["bun", "add" | "install" | "i", rest @ ..] => (Npm, rest, BUN_FLAGS),
        ["pip" | "pip3", "install", rest @ ..]
        | ["uv", "pip", "install", rest @ ..]
        | ["uv" | "poetry", "add", rest @ ..] => (PyPI, rest, PIP_FLAGS),
        ["cargo", "add", rest @ ..] => (Cargo, rest, CARGO_FLAGS),
        ["go", "get", rest @ ..] => (Go, rest, &[][..]),
        _ => return Vec::new(),
    };
    let mut out = Vec::new();
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        if arg.starts_with('-') {
            if !arg.contains('=') && value_flags.contains(arg) {
                args.next();
            }
            continue;
        }
        if eco == Go && (arg.starts_with('.') || arg.ends_with("@none")) {
            continue; // local packages, or removing a module
        }
        out.push(Request {
            eco,
            spec: (*arg).to_string(),
            name: registry_name(eco, arg),
        });
    }
    out
}

fn registry_name(eco: Ecosystem, spec: &str) -> Option<String> {
    let local = spec.starts_with(['.', '/', '~']) || spec.contains("://");
    match eco {
        Ecosystem::Npm => {
            if let Some((_, real)) = spec.split_once("@npm:") {
                return Some(npm_spec_name(real).to_string());
            }
            // `user/repo`, `github:…`, `file:…`, URLs and paths are not registry packages.
            let other =
                local || spec.contains(':') || (!spec.starts_with('@') && spec.contains('/'));
            (!other).then(|| npm_spec_name(spec).to_string())
        }
        Ecosystem::PyPI => {
            let archive = [".whl", ".tar.gz", ".zip"]
                .iter()
                .any(|s| spec.ends_with(s));
            (!local && !archive)
                .then(|| pep508_name(spec))
                .flatten()
                .map(|n| Ecosystem::PyPI.normalize(n))
        }
        Ecosystem::Cargo | Ecosystem::Go => {
            Some(spec.split('@').next().unwrap_or(spec).to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn names(cmd: &str) -> Vec<String> {
        requests(cmd)
            .into_iter()
            .map(|r| {
                format!(
                    "{}:{}",
                    r.eco,
                    r.name.unwrap_or_else(|| format!("<{}>", r.spec))
                )
            })
            .collect()
    }

    #[test]
    fn finds_package_installs() {
        assert_eq!(
            names("npm i -D left-pad@1.3.0 @types/node"),
            ["npm:left-pad", "npm:@types/node"]
        );
        assert_eq!(
            names("cd web && pnpm --version; pnpm add --filter app zod"),
            ["npm:zod"]
        );
        assert_eq!(names("CI=1 yarn add pad@npm:left-pad@^1"), ["npm:left-pad"]);
        assert_eq!(
            names("npm install github:acme/x ./local"),
            ["npm:<github:acme/x>", "npm:<./local>"]
        );
        assert_eq!(
            names("python3 -m pip install 'Requests[socks]>=2' -r req.txt"),
            ["pypi:requests"]
        );
        assert_eq!(
            names("uv add --group dev Pytest && poetry add django"),
            ["pypi:pytest", "pypi:django"]
        );
        assert_eq!(names("cargo add serde@1 -F derive"), ["cargo:serde"]);
        assert_eq!(
            names("go get github.com/spf13/cobra@v1.8.1 ./..."),
            ["go:github.com/spf13/cobra"]
        );
        // Regression (live Claude Code run): `2>&1` was read as a package.
        assert_eq!(
            names("npm view slugify version 2>&1 | head && npm install slugify 2>&1 | tail -5"),
            ["npm:slugify"]
        );
        assert_eq!(names("npm i zod > install.log 2>/dev/null"), ["npm:zod"]);
        assert_eq!(
            names("npm i zod & pnpm add yup &> log"),
            ["npm:zod", "npm:yup"]
        );
        for cmd in [
            "npm install",
            "npm ci",
            "pnpm install --frozen-lockfile",
            "yarn",
            "npm test",
            "cargo build",
        ] {
            assert!(requests(cmd).is_empty(), "{cmd}");
        }
    }

    #[test]
    fn spots_age_gate_overrides() {
        for cmd in [
            "npm install --min-release-age=0 x",
            "pnpm add x --config.minimum-release-age=0",
            "npm_config_min_release_age=0 npm i x",
            "npm config set min-release-age 0",
            "yarn config set npmMinimalAgeGate 0",
            "uv add requests --exclude-newer 2099-01-01",
            "UV_EXCLUDE_NEWER=2099-01-01 uv lock",
        ] {
            assert!(weakens_age_gate(cmd), "{cmd}");
        }
        assert!(!weakens_age_gate("npm config get min-release-age"));
        assert!(!weakens_age_gate("npm install left-pad"));
    }
}
