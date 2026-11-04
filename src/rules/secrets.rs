//! Secret detection with gitleaks' default ruleset (MIT, `assets/gitleaks.toml`,
//! v8.30 rules, 222 detectors): keyword prefilter, regex, secret group, entropy
//! and allowlists with gitleaks' semantics. Findings are reported redacted.

use super::lines::LineIndex;
use super::{Level, RuleInfo, Violation};
use anyhow::Result;
use keywords::Keywords;
use model::{Allow, RawConfig, Rule, allow, compile};
use std::sync::OnceLock;

mod decode;
mod keywords;
mod model;

pub const ID: &str = "secrets";
const CONFIG: &str = include_str!("../../assets/gitleaks.toml");

pub struct Secrets {
    rules: Vec<Rule>,
    keywords: Keywords,
    global: Allow,
}

impl Secrets {
    pub fn new() -> Result<Self> {
        let raw: RawConfig = toml::from_str(CONFIG)?;
        let lists: Vec<Vec<String>> = raw
            .rules
            .iter()
            .map(|r| r.keywords.iter().map(|k| k.to_lowercase()).collect())
            .collect();
        let (keywords, ids) = Keywords::new(&lists)?;
        let rules = raw
            .rules
            .into_iter()
            .zip(ids)
            .map(|(r, keywords)| Rule {
                path: r.path.as_deref().and_then(compile),
                keywords,
                allows: r.allowlists.into_iter().map(allow).collect(),
                generic: r.id.to_lowercase().contains("generic"),
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
            keywords,
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
        let lines = LineIndex::new(content);
        let mut hits = self.scan(rel, content, None, &lines);
        // Like gitleaks: secrets hidden in base64 (JWT payloads, k8s secrets,
        // data URIs) are scanned decoded and reported where the encoding is.
        for (start, encoded, decoded) in decode::base64_segments(content) {
            let line_no = lines.line_of(start);
            let line = lines.line(line_no).unwrap_or("");
            hits.extend(self.scan(rel, &decoded, Some((line_no, line, encoded)), &lines));
        }
        // As gitleaks does: a generic finding inside a specific one on the same
        // line is the same secret, reported once.
        let dup = |h: &Hit| {
            h.rule.generic
                && hits.iter().any(|o| {
                    o.line == h.line
                        && o.rule.id != h.rule.id
                        && !o.rule.generic
                        && o.secret.contains(h.secret.as_str())
                })
        };
        let keep: Vec<bool> = hits.iter().map(|h| !dup(h)).collect();
        hits.into_iter()
            .zip(keep)
            .filter(|(_, k)| *k)
            .map(|(hit, _)| hit.finding)
            .collect()
    }

    /// Findings in `text`; `origin` places decoded text: (line index, line,
    /// encoded). Without one, `lines` indexes `text`.
    fn scan(
        &self,
        rel: &str,
        text: &str,
        origin: Option<(usize, &str, &str)>,
        lines: &LineIndex,
    ) -> Vec<Hit<'_>> {
        let present = self.keywords.found_in(text);
        let mut hits = Vec::new();
        for rule in &self.rules {
            if !rule.keywords.is_empty() && !rule.keywords.iter().any(|k| present[*k]) {
                continue;
            }
            if let Some(p) = &rule.path
                && !p.is_match(rel)
            {
                continue;
            }
            let Some(regex) = rule.regex() else {
                if rule.pattern.is_none() && origin.is_none() {
                    hits.push(Hit {
                        rule,
                        line: 0,
                        secret: String::new(),
                        finding: finding(rule, rel, 0, String::new(), false),
                    });
                }
                continue;
            };
            // The fast engine finds each match; groups are then read on that
            // match alone: capturing over a whole 60 MB file ran the slow one.
            for found in regex.find_iter(text) {
                let mut end = (found.end() + 64).min(text.len());
                while !text.is_char_boundary(end) {
                    end += 1;
                }
                let Some(caps) = regex.captures_at(&text[..end], found.start()) else {
                    continue;
                };
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
                        let n = lines.line_of(whole.start());
                        (n, lines.line(n).unwrap_or(""), secret)
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
                    hits.push(Hit {
                        rule,
                        line: line_no + 1,
                        secret: secret.to_string(),
                        finding: v,
                    });
                }
            }
        }
        hits
    }
}

/// A finding with what telling duplicates apart needs.
struct Hit<'r> {
    rule: &'r Rule,
    line: usize,
    secret: String,
    finding: Violation,
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
