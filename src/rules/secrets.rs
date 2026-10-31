//! Secret detection with gitleaks' default ruleset (MIT, `assets/gitleaks.toml`,
//! v8.30 rules, 222 detectors): keyword prefilter, regex, secret group, entropy
//! and allowlists with gitleaks' semantics. Findings are reported redacted.

use super::{Level, RuleInfo, Violation};
use anyhow::Result;
use regex::{Regex, RegexBuilder};
use serde::Deserialize;
use std::sync::OnceLock;

pub const ID: &str = "secrets";
const CONFIG: &str = include_str!("../../assets/gitleaks.toml");

#[derive(Deserialize)]
struct RawConfig {
    allowlist: RawAllow,
    rules: Vec<RawRule>,
}

#[derive(Deserialize)]
struct RawRule {
    id: String,
    description: String,
    regex: Option<String>,
    path: Option<String>,
    #[serde(default, rename = "secretGroup")]
    secret_group: usize,
    entropy: Option<f32>,
    #[serde(default)]
    keywords: Vec<String>,
    #[serde(default)]
    allowlists: Vec<RawAllow>,
}

#[derive(Deserialize, Default)]
struct RawAllow {
    #[serde(default)]
    regexes: Vec<String>,
    #[serde(default, rename = "regexTarget")]
    target: Option<String>,
    #[serde(default)]
    paths: Vec<String>,
    #[serde(default)]
    stopwords: Vec<String>,
    condition: Option<String>,
}

struct Allow {
    regexes: Vec<Regex>,
    /// What `regexes` test: the secret (default), the whole match, or the line.
    target: String,
    paths: Vec<Regex>,
    stopwords: Vec<String>,
    all: bool,
}

struct Rule {
    id: String,
    description: String,
    /// Compiled on first use: most files never pass a rule's keyword prefilter,
    /// and compiling all 222 patterns up front costs more than a whole check.
    pattern: Option<String>,
    regex: OnceLock<Option<Regex>>,
    path: Option<Regex>,
    secret_group: usize,
    entropy: Option<f32>,
    keywords: Vec<String>,
    allows: Vec<Allow>,
}

pub struct Secrets {
    rules: Vec<Rule>,
    global: Allow,
}

fn compile(pattern: &str) -> Option<Regex> {
    RegexBuilder::new(pattern).size_limit(64 << 20).build().ok()
}

fn allow(raw: RawAllow) -> Allow {
    Allow {
        regexes: raw.regexes.iter().filter_map(|r| compile(r)).collect(),
        target: raw.target.unwrap_or_else(|| "secret".into()),
        paths: raw.paths.iter().filter_map(|r| compile(r)).collect(),
        stopwords: raw.stopwords.iter().map(|s| s.to_lowercase()).collect(),
        all: raw.condition.as_deref() == Some("AND"),
    }
}

impl Allow {
    fn allows(&self, path: &str, secret: &str, whole: &str, line: &str) -> bool {
        let target = match self.target.as_str() {
            "match" => whole,
            "line" => line,
            _ => secret,
        };
        let lower = secret.to_lowercase();
        let checks = [
            (!self.regexes.is_empty()).then(|| self.regexes.iter().any(|r| r.is_match(target))),
            (!self.paths.is_empty()).then(|| self.paths.iter().any(|r| r.is_match(path))),
            (!self.stopwords.is_empty()).then(|| self.stopwords.iter().any(|s| lower.contains(s))),
        ];
        let mut present = checks.iter().flatten();
        if self.all {
            checks.iter().flatten().count() > 0 && present.all(|c| *c)
        } else {
            present.any(|c| *c)
        }
    }
}

impl Secrets {
    pub fn new() -> Result<Self> {
        let raw: RawConfig = toml::from_str(CONFIG)?;
        let rules = raw
            .rules
            .into_iter()
            .map(|r| Rule {
                path: r.path.as_deref().and_then(compile),
                keywords: r.keywords.iter().map(|k| k.to_lowercase()).collect(),
                allows: r.allowlists.into_iter().map(allow).collect(),
                id: r.id,
                description: r.description,
                pattern: r.regex,
                regex: OnceLock::new(),
                secret_group: r.secret_group,
                entropy: r.entropy,
            })
            .collect();
        Ok(Self {
            rules,
            global: allow(raw.allowlist),
        })
    }

    /// Detectors whose pattern compiles with Rust's regex engine.
    #[cfg(test)]
    pub fn detectors(&self) -> usize {
        self.rules
            .iter()
            .filter(|r| r.pattern.is_none() || r.regex().is_some())
            .count()
    }

    pub fn info() -> RuleInfo {
        RuleInfo {
            id: ID.into(),
            level: Level::Error,
            scope: "all files".into(),
            message: "No credentials, tokens or private keys in the repository.".into(),
            note: Some(NOTE.into()),
        }
    }

    pub fn check(&self, rel: &str, content: &str) -> Vec<Violation> {
        if self.global.paths.iter().any(|p| p.is_match(rel)) {
            return Vec::new();
        }
        let lower = content.to_lowercase();
        // (rule, line, secret, finding)
        let mut hits: Vec<(&str, usize, &str, Violation)> = Vec::new();
        for rule in &self.rules {
            if !rule.keywords.is_empty() && !rule.keywords.iter().any(|k| lower.contains(k)) {
                continue;
            }
            if let Some(p) = &rule.path
                && !p.is_match(rel)
            {
                continue;
            }
            let Some(regex) = rule.regex() else {
                if rule.pattern.is_none() {
                    hits.push((&rule.id, 0, "", finding(rule, rel, 0, String::new())));
                }
                continue;
            };
            for caps in regex.captures_iter(content) {
                let whole = caps.get(0).expect("group 0");
                let secret = match rule.secret_group {
                    0 => (1..caps.len()).find_map(|i| caps.get(i)).unwrap_or(whole),
                    g => caps.get(g).unwrap_or(whole),
                }
                .as_str();
                if rule.entropy.is_some_and(|min| entropy(secret) <= min)
                    || (rule.id.starts_with("generic")
                        && !secret.chars().any(|c| c.is_ascii_digit()))
                {
                    continue;
                }
                let line_no = content[..whole.start()].matches('\n').count();
                let line = content.lines().nth(line_no).unwrap_or("");
                let allowed = std::iter::once(&self.global)
                    .chain(&rule.allows)
                    .any(|a| a.allows(rel, secret, whole.as_str(), line));
                if !allowed {
                    let v = finding(rule, rel, line_no + 1, redact(line, secret));
                    hits.push((&rule.id, line_no + 1, secret, v));
                }
            }
        }
        // As gitleaks does: a generic finding inside a specific one on the same
        // line is the same secret, reported once.
        let generic = |id: &str| id.to_lowercase().contains("generic");
        let dup = |(id, line, secret, _): &(&str, usize, &str, Violation)| {
            generic(id)
                && hits.iter().any(|(id2, line2, secret2, _)| {
                    line2 == line && id2 != id && !generic(id2) && secret2.contains(secret)
                })
        };
        let keep: Vec<bool> = hits.iter().map(|h| !dup(h)).collect();
        hits.into_iter()
            .zip(keep)
            .filter(|(_, k)| *k)
            .map(|((.., v), _)| v)
            .collect()
    }
}

/// Shannon entropy exactly as gitleaks computes it (character counts over the
/// byte length), since its rules' thresholds are tuned to that formula; a
/// per-byte entropy differs on non-ASCII text and flagged CJK translations.
fn entropy(s: &str) -> f32 {
    let mut counts: std::collections::HashMap<char, usize> = std::collections::HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_default() += 1;
    }
    let len = s.len() as f64;
    let h: f64 = counts
        .values()
        .map(|&n| n as f64 / len)
        .map(|f| -f * f.log2())
        .sum();
    h as f32
}

impl Rule {
    fn regex(&self) -> Option<&Regex> {
        self.regex
            .get_or_init(|| self.pattern.as_deref().and_then(compile))
            .as_ref()
    }
}

const NOTE: &str = "Remove it from the code and load it from the environment or a secret manager. \
Treat it as leaked: revoke and rotate it at the provider, because git history keeps it.";

fn finding(rule: &Rule, rel: &str, line: usize, snippet: String) -> Violation {
    Violation {
        rule: ID.into(),
        level: Level::Error,
        file: rel.into(),
        line,
        column: 1,
        message: format!(
            "{} (gitleaks rule `{}`)",
            rule.description.trim_end_matches('.'),
            rule.id
        ),
        note: Some(NOTE.into()),
        snippet: (!snippet.is_empty()).then_some(snippet),
    }
}

/// Reports must not leak what they found: keep 4 characters of the secret.
fn redact(line: &str, secret: &str) -> String {
    let keep: String = secret.chars().take(4).collect();
    let line = line.trim();
    let shown = if secret.is_empty() {
        line.to_string()
    } else {
        line.replace(secret, &format!("{keep}…[redacted]"))
    };
    shown.chars().take(160).collect()
}

#[cfg(test)]
mod tests;
