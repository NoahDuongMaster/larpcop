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
    /// Agents `sync` generates files for (default: all). Ids as in `agentkit hook`.
    pub agents: Option<Vec<String>>,
    /// Function-level limits (`complexity`, `function-length` rules).
    pub metrics: Option<MetricsConfig>,
    /// Secret scanning (`secrets` rule, gitleaks' detectors).
    pub secrets: Option<SecretsConfig>,
    /// Intraprocedural taint rules: sources must not reach sinks unsanitized.
    #[serde(default)]
    pub taint: Vec<TaintConfig>,
    /// Rules in plain language, judged by a model (`agentkit review`).
    pub llm: Option<LlmConfig>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LlmConfig {
    /// CLI that reads a prompt on stdin and answers on stdout
    /// (default: `claude -p`, else `codex exec -`).
    pub command: Option<LlmCommand>,
    #[serde(default)]
    pub rules: Vec<LlmRule>,
}

/// `[claude, -p]` runs the program directly; `"claude -p | tail -1"` runs
/// through a POSIX shell (Git's `sh` on Windows), like linter `run:` commands.
#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum LlmCommand {
    Argv(Vec<String>),
    Shell(String),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LlmRule {
    pub id: String,
    /// What to look for, as you would tell a reviewer.
    pub prompt: String,
    /// Globs of files the rule applies to (default: every file).
    #[serde(default)]
    pub files: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaintConfig {
    pub id: String,
    /// ast-grep language names, e.g. [TypeScript, Tsx, JavaScript].
    pub languages: Vec<String>,
    pub severity: Option<Level>,
    pub message: String,
    pub note: Option<String>,
    /// ast-grep patterns of untrusted data, e.g. `req.query`.
    pub sources: Vec<String>,
    /// ast-grep patterns of dangerous calls, e.g. `$DB.query($SQL, $$$REST)`.
    pub sinks: Vec<String>,
    /// Metavariable of the sink argument that must stay clean (default: the whole call).
    pub sink_arg: Option<String>,
    /// ast-grep patterns that make data safe, e.g. `Number($X)`.
    #[serde(default)]
    pub sanitizers: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretsConfig {
    /// Globs never scanned (e.g. test fixtures with fake keys).
    #[serde(default)]
    pub exclude: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    /// Highest cyclomatic complexity a function may have.
    pub max_complexity: Option<usize>,
    /// Longest a function may be, in lines.
    pub max_function_lines: Option<usize>,
    #[serde(default)]
    pub exclude: Vec<String>,
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
    /// Block known vulnerabilities from this severity up (low, moderate, high,
    /// critical); known-malicious packages are always blocked once this is set.
    pub vulnerabilities: Option<String>,
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
        // `URL#v1.2.0//standards/recommended`: a subdirectory of the checkout.
        let (reference, subdir) = match reference.as_deref().and_then(|r| r.split_once("//")) {
            Some((r, sub)) => (Some(r.to_string()), Some(sub.to_string())),
            None => (reference, None),
        };
        Self::Git {
            git: url.to_string(),
            reference,
            subdir,
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
