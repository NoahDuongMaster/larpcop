//! Package installs inside a shell command, so an agent hook can stop an
//! unapproved, malicious or too-new package before any of its code runs.

use super::ecosystem::{Ecosystem, npm_spec_name};
use super::manifest::pep508_name;
use super::vulns::pinned_version;
use crate::shell_ast::Script;

mod flags;
mod overrides;
use flags::*;
pub use overrides::{uv_ok, weakens_age_gate};

pub struct Request {
    pub eco: Ecosystem,
    pub spec: String,
    /// Registry package name; `None` for git URLs, tarballs and paths.
    pub name: Option<String>,
    /// Exact version asked for (`x@1.2.3`, `-v 1.2.3`); `None`: whatever is newest.
    pub version: Option<String>,
    /// How it gets installed: `"cargo install"`, `"npx"`, …
    pub via: &'static str,
}

/// One package-manager command that installs or runs packages.
pub struct Invocation {
    /// `"npm install"`, `"npx"`, `"poetry add"`, …
    pub via: &'static str,
    pub eco: Ecosystem,
    /// Words after the subcommand, unquoted.
    pub args: Vec<String>,
    /// `VAR=value` prefixes of this command.
    pub env: Vec<(String, String)>,
    /// Runs a tool: only its package is ours, the rest are the tool's arguments.
    runs_tool: bool,
    value_flags: &'static [&'static str],
}

#[cfg(test)]
pub fn requests(command: &str) -> Vec<Request> {
    invocations(&crate::shell_ast::parse(command))
        .iter()
        .flat_map(Invocation::requests)
        .collect()
}

pub fn invocations(script: &Script) -> Vec<Invocation> {
    script
        .commands
        .iter()
        .filter_map(|c| {
            let mut t: Vec<&str> = c.words.iter().map(String::as_str).collect();
            if t.len() > 2 && t[0].starts_with("python") && t[1] == "-m" {
                t.drain(..2); // python -m pip install …
            }
            let (via, eco, skip, value_flags, runs_tool) = classify(&t)?;
            Some(Invocation {
                via,
                eco,
                args: t[skip..].iter().map(|s| s.to_string()).collect(),
                env: c.env.clone(),
                runs_tool,
                value_flags,
            })
        })
        .collect()
}

type Kind = (
    &'static str,
    Ecosystem,
    usize,
    &'static [&'static str],
    bool,
);

fn classify(t: &[&str]) -> Option<Kind> {
    use Ecosystem::*;
    Some(match t {
        ["npm", "install" | "i" | "add" | "in", ..] => ("npm install", Npm, 2, NPM_FLAGS, false),
        ["npm", "exec" | "x", ..] => ("npx", Npm, 2, NPX_FLAGS, true),
        ["npx", ..] => ("npx", Npm, 1, NPX_FLAGS, true),
        ["pnpm", "add" | "install" | "i", ..] => ("pnpm add", Npm, 2, PNPM_FLAGS, false),
        ["pnpm", "dlx", ..] => ("pnpm dlx", Npm, 2, NPX_FLAGS, true),
        ["pnpx", ..] => ("pnpm dlx", Npm, 1, NPX_FLAGS, true),
        ["yarn", "add", ..] => ("yarn add", Npm, 2, YARN_FLAGS, false),
        ["yarn", "dlx", ..] => ("yarn dlx", Npm, 2, NPX_FLAGS, true),
        ["bun", "add" | "install" | "i", ..] => ("bun add", Npm, 2, BUN_FLAGS, false),
        ["bun", "x", ..] => ("bunx", Npm, 2, NPX_FLAGS, true),
        ["bunx", ..] => ("bunx", Npm, 1, NPX_FLAGS, true),
        ["pip" | "pip3", "install", ..] => ("pip install", PyPI, 2, PIP_FLAGS, false),
        ["uv", "pip", "install", ..] => ("uv pip install", PyPI, 3, PIP_FLAGS, false),
        ["uv", "add", ..] => ("uv add", PyPI, 2, PIP_FLAGS, false),
        ["poetry", "add", ..] => ("poetry add", PyPI, 2, PIP_FLAGS, false),
        ["uvx", ..] => ("uvx", PyPI, 1, UVX_FLAGS, true),
        ["uv", "tool", "run" | "install", ..] => ("uvx", PyPI, 3, UVX_FLAGS, true),
        ["pipx", "install" | "run", ..] => ("pipx", PyPI, 2, PIPX_FLAGS, true),
        ["cargo", "add", ..] => ("cargo add", Cargo, 2, CARGO_FLAGS, false),
        ["cargo", "install", ..] => ("cargo install", Cargo, 2, CARGO_INSTALL_FLAGS, false),
        ["go", "get", ..] => ("go get", Go, 2, &[][..], false),
        ["go", "install", ..] => ("go install", Go, 2, GO_FLAGS, false),
        ["gem", "install", ..] => ("gem install", RubyGems, 2, GEM_FLAGS, false),
        ["bundle", "add", ..] => ("bundle add", RubyGems, 2, GEM_FLAGS, false),
        ["composer", "require", ..] => ("composer require", Packagist, 2, &[][..], false),
        // dotnet add [PROJECT] package NAME [--version V]
        ["dotnet", "add", rest @ ..] => {
            let at = rest.iter().position(|w| *w == "package")?;
            ("dotnet add package", NuGet, at + 3, DOTNET_FLAGS, false)
        }
        _ => return None,
    })
}

impl Invocation {
    /// `--flag` given, alone or as `--flag=value`.
    pub fn has(&self, flag: &str) -> bool {
        self.args
            .iter()
            .any(|a| a == flag || a.strip_prefix(flag).is_some_and(|r| r.starts_with('=')))
    }

    /// Value of the first of `flags` given (`--f v` or `--f=v`).
    pub fn value(&self, flags: &[&str]) -> Option<&str> {
        let mut args = self.args.iter();
        while let Some(a) = args.next() {
            for f in flags {
                if a == f {
                    return args.next().map(String::as_str);
                }
                if let Some(v) = a.strip_prefix(f).and_then(|r| r.strip_prefix('=')) {
                    return Some(v);
                }
            }
        }
        None
    }

    pub fn requests(&self) -> Vec<Request> {
        let flagged = match self.via {
            "gem install" | "bundle add" | "dotnet add package" => self.value(&["-v", "--version"]),
            "cargo install" => self.value(&["--version", "--vers"]),
            _ => None,
        }
        .map(String::from);
        self.packages()
            .into_iter()
            .map(|spec| {
                let (name, version) = self.split(&spec);
                Request {
                    eco: self.eco,
                    name,
                    version: flagged.clone().or(version),
                    spec,
                    via: self.via,
                }
            })
            .collect()
    }

    fn packages(&self) -> Vec<String> {
        // `npx -p pkg cmd`, `uvx --from pkg cmd`, `pipx run --spec pkg cmd`.
        let package_flags: &[&str] = match self.via {
            "npx" | "bunx" | "pnpm dlx" | "yarn dlx" => &["-p", "--package"],
            "uvx" => &["--from"],
            "pipx" => &["--spec"],
            _ => &[],
        };
        if let Some(p) = self.value(package_flags) {
            return vec![p.to_string()];
        }
        let mut out = Vec::new();
        let mut args = self.args.iter();
        while let Some(arg) = args.next() {
            if arg.starts_with('-') {
                if !arg.contains('=') && self.value_flags.contains(&arg.as_str()) {
                    args.next();
                }
                continue;
            }
            if self.eco == Ecosystem::Go && (arg.starts_with('.') || arg.ends_with("@none")) {
                continue; // local packages, or removing a module
            }
            out.push(arg.clone());
            if self.runs_tool {
                break; // the rest are the tool's own arguments
            }
        }
        out
    }

    fn split(&self, spec: &str) -> (Option<String>, Option<String>) {
        // `uvx ruff@0.6.0`, `pipx install black==24.1`
        if self.eco == Ecosystem::PyPI
            && let Some((name, v)) = spec.split_once('@')
            && !name.is_empty()
            && !spec.contains("://")
        {
            return (registry_name(self.eco, name), Some(v.to_string()));
        }
        let version = pinned_version(self.eco, spec).map(String::from);
        (registry_name(self.eco, spec), version)
    }
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
        // `composer require vendor/pkg:^2`
        Ecosystem::Packagist => (!local && spec.contains('/'))
            .then(|| eco.normalize(spec.split(':').next().unwrap_or(spec))),
        Ecosystem::RubyGems | Ecosystem::NuGet | Ecosystem::Maven => {
            (!local).then(|| eco.normalize(spec))
        }
    }
}

#[cfg(test)]
mod tests;
