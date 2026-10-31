//! Secret detection with gitleaks' default ruleset (MIT, `assets/gitleaks.toml`,
//! v8.30 rules, 222 detectors): keyword prefilter, regex, secret group, entropy
//! and allowlists with gitleaks' semantics. Findings are reported redacted.

use super::{Level, RuleInfo, Violation};
use anyhow::Result;
use model::{Allow, RawConfig, Rule, allow, compile};
use std::sync::OnceLock;

mod decode;
mod model;

pub const ID: &str = "secrets";
const CONFIG: &str = include_str!("../../assets/gitleaks.toml");

pub struct Secrets {
    rules: Vec<Rule>,
    global: Allow,
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
        let mut hits = self.scan(rel, content, None);
        // Like gitleaks: secrets hidden in base64 (JWT payloads, k8s secrets,
        // data URIs) are scanned decoded and reported where the encoding is.
        for (start, encoded, decoded) in decode::base64_segments(content) {
            let line_no = content[..start].matches('\n').count();
            let line = content.lines().nth(line_no).unwrap_or("");
            hits.extend(self.scan(rel, &decoded, Some((line_no, line, encoded))));
        }
        // As gitleaks does: a generic finding inside a specific one on the same
        // line is the same secret, reported once.
        let generic = |id: &str| id.to_lowercase().contains("generic");
        let dup = |(id, line, secret, _): &Hit| {
            generic(id)
                && hits.iter().any(|(id2, line2, secret2, _)| {
                    line2 == line && id2 != id && !generic(id2) && secret2.contains(secret.as_str())
                })
        };
        let keep: Vec<bool> = hits.iter().map(|h| !dup(h)).collect();
        hits.into_iter()
            .zip(keep)
            .filter(|(_, k)| *k)
            .map(|((.., v), _)| v)
            .collect()
    }

    /// Findings in `text`; `origin` places decoded text: (line index, line, encoded).
    fn scan(&self, rel: &str, text: &str, origin: Option<(usize, &str, &str)>) -> Vec<Hit> {
        let lower = text.to_lowercase();
        let mut hits = Vec::new();
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
                if rule.pattern.is_none() && origin.is_none() {
                    hits.push((
                        rule.id.clone(),
                        0,
                        String::new(),
                        finding(rule, rel, 0, String::new(), false),
                    ));
                }
                continue;
            };
            for caps in regex.captures_iter(text) {
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
                let (line_no, line, shown) = match origin {
                    Some((n, line, encoded)) => (n, line, encoded),
                    None => {
                        let n = text[..whole.start()].matches('\n').count();
                        (n, text.lines().nth(n).unwrap_or(""), secret)
                    }
                };
                let allowed = std::iter::once(&self.global)
                    .chain(&rule.allows)
                    .any(|a| a.allows(rel, secret, whole.as_str(), line));
                if !allowed {
                    let v = finding(
                        rule,
                        rel,
                        line_no + 1,
                        redact(line, shown),
                        origin.is_some(),
                    );
                    hits.push((rule.id.clone(), line_no + 1, secret.to_string(), v));
                }
            }
        }
        hits
    }
}

/// (rule id, line, secret, finding)
type Hit = (String, usize, String, Violation);

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

const NOTE: &str = "Remove it from the code and load it from the environment or a secret manager. \
Treat it as leaked: revoke and rotate it at the provider, because git history keeps it.";

fn finding(rule: &Rule, rel: &str, line: usize, snippet: String, decoded: bool) -> Violation {
    Violation {
        rule: ID.into(),
        level: Level::Error,
        file: rel.into(),
        line,
        column: 1,
        message: format!(
            "{} (gitleaks rule `{}`{})",
            rule.description.trim_end_matches('.'),
            rule.id,
            if decoded { ", inside base64" } else { "" }
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
