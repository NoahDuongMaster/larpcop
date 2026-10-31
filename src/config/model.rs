//! On-disk schema of `.agentkit.yaml` (repo) and `agentkit.yaml` (standards).

use crate::rules::Level;
use serde::Deserialize;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawConfig {
    /// Standards applied before this file, in order.
    #[serde(default)]
    pub extends: Vec<ExtendSpec>,
    /// Globs (relative to the repo root) that are never checked.
    #[serde(default)]
    pub exclude: Vec<String>,
    pub max_lines: Option<MaxLinesConfig>,
    /// Directories of ast-grep rule files, relative to this config file.
    #[serde(default)]
    pub rule_dirs: Vec<String>,
    /// External tools whose non-zero exit counts as a violation.
    #[serde(default)]
    pub linters: Vec<LinterConfig>,
    /// Rule ids switched off by this layer. Locked rules cannot be disabled.
    #[serde(default)]
    pub disable: Vec<String>,
    /// Rule ids later layers may neither disable nor override.
    #[serde(default)]
    pub locked: Vec<String>,
    /// Markdown file inlined into AGENTS.md, relative to this config file.
    pub guidelines: Option<String>,
    pub dependencies: Option<DependenciesConfig>,
}

/// Supply-chain rules. Patterns are `[ecosystem:]glob`, e.g. `npm:@acme/*`, `serde`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DependenciesConfig {
    /// Days a version must have been public before it may enter a lockfile.
    pub min_release_age: Option<u32>,
    /// A new direct dependency needs a human's approval (an `approved` entry).
    pub require_approval: Option<bool>,
    /// Direct dependencies a human approved.
    #[serde(default)]
    pub approved: Vec<String>,
    /// Packages with no public publish date (private registries): age is not checked.
    #[serde(default)]
    pub exempt: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaxLinesConfig {
    pub max: usize,
    /// Files the limit applies to. Empty = every source file ast-grep can parse.
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
    #[serde(default)]
    pub level: Level,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinterConfig {
    pub id: String,
    /// Shell command run from the repo root. `{files}` expands to the matched files.
    pub run: String,
    /// Files that trigger the linter. Empty = every checked file.
    #[serde(default)]
    pub include: Vec<String>,
    #[serde(default)]
    pub level: Level,
}

/// Where a layer of standards comes from.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum ExtendSpec {
    Git {
        git: String,
        #[serde(default, rename = "ref")]
        reference: Option<String>,
        #[serde(default)]
        subdir: Option<String>,
    },
    Path {
        path: String,
    },
    /// `../standards` or `git@host:org/repo.git#v1.2.0`
    Short(String),
}

impl ExtendSpec {
    pub fn parse(spec: &str) -> Self {
        let spec = spec.trim();
        if !(spec.contains("://") || spec.starts_with("git@")) {
            return Self::Path {
                path: spec.to_string(),
            };
        }
        let (url, reference) = match spec.rsplit_once('#') {
            Some((url, r)) => (url, Some(r.to_string())),
            None => (spec, None),
        };
        Self::Git {
            git: url.to_string(),
            reference,
            subdir: None,
        }
    }

    /// Canonical form: `Short` is expanded into `Git` or `Path`.
    pub fn normalized(&self) -> Self {
        match self {
            Self::Short(s) => Self::parse(s),
            other => other.clone(),
        }
    }
}
