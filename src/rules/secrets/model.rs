//! gitleaks' configuration format: rules with keywords, regex, secret group,
//! entropy and allowlists.

use regex::{Regex, RegexBuilder};
use serde::Deserialize;
use std::sync::OnceLock;

#[derive(Deserialize)]
pub(super) struct RawConfig {
    pub(super) allowlist: RawAllow,
    pub(super) rules: Vec<RawRule>,
}

#[derive(Deserialize)]
pub(super) struct RawRule {
    pub(super) id: String,
    pub(super) description: String,
    pub(super) regex: Option<String>,
    pub(super) path: Option<String>,
    #[serde(default, rename = "secretGroup")]
    pub(super) secret_group: usize,
    pub(super) entropy: Option<f32>,
    #[serde(default)]
    pub(super) keywords: Vec<String>,
    #[serde(default)]
    pub(super) allowlists: Vec<RawAllow>,
}

#[derive(Deserialize, Default)]
pub(super) struct RawAllow {
    #[serde(default)]
    pub(super) regexes: Vec<String>,
    #[serde(default, rename = "regexTarget")]
    pub(super) target: Option<String>,
    #[serde(default)]
    pub(super) paths: Vec<String>,
    #[serde(default)]
    pub(super) stopwords: Vec<String>,
    pub(super) condition: Option<String>,
}

pub(super) struct Allow {
    pub(super) regexes: Vec<Regex>,
    /// What `regexes` test: the secret (default), the whole match, or the line.
    pub(super) target: String,
    pub(super) paths: Vec<Regex>,
    pub(super) stopwords: Vec<String>,
    pub(super) all: bool,
}

pub(super) struct Rule {
    pub(super) id: String,
    pub(super) description: String,
    /// Compiled on first use: most files never pass a rule's keyword prefilter,
    /// and compiling all 222 patterns up front costs more than a whole check.
    pub(super) pattern: Option<String>,
    pub(super) regex: OnceLock<Option<Regex>>,
    pub(super) path: Option<Regex>,
    pub(super) secret_group: usize,
    pub(super) entropy: Option<f32>,
    /// Ids (in `Keywords`) of the keywords of which one must be in the text.
    pub(super) keywords: Vec<usize>,
    pub(super) allows: Vec<Allow>,
    /// A broad `generic-*` detector, whose finding yields to a specific one
    /// on the same line.
    pub(super) generic: bool,
}

pub(super) fn compile(pattern: &str) -> Option<Regex> {
    RegexBuilder::new(&ascii_boundaries(pattern))
        .size_limit(64 << 20)
        .build()
        .ok()
}

/// gitleaks patterns are RE2, where `\b`, `\w`, `\d` and `\s` are ASCII. In
/// Rust they are Unicode, which keeps the fast DFA off non-ASCII text and
/// blows up its states, leaving a 60 MB file to the slow engine. The ASCII
/// forms are both what gitleaks means and fast.
fn ascii_boundaries(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len() + 32);
    let mut chars = pattern.chars().peekable();
    let mut in_class = false;
    while let Some(c) = chars.next() {
        match c {
            '[' if !in_class => {
                in_class = true;
                out.push(c);
                // `[]` or `[^]` at the start is a literal bracket.
                if chars.peek() == Some(&'^') {
                    out.push(chars.next().unwrap_or('^'));
                }
                if chars.peek() == Some(&']') {
                    out.push(chars.next().unwrap_or(']'));
                }
            }
            ']' if in_class => {
                in_class = false;
                out.push(c);
            }
            '\\' => {
                let Some(e) = chars.next() else {
                    out.push(c);
                    break;
                };
                let ascii = match e {
                    'w' => Some("0-9A-Za-z_"),
                    'd' => Some("0-9"),
                    's' => Some("\\t\\n\\x0B\\f\\r "),
                    _ => None,
                };
                match (ascii, in_class, e) {
                    (Some(set), true, _) => out.push_str(set),
                    (Some(set), false, _) => {
                        out.push('[');
                        out.push_str(set);
                        out.push(']');
                    }
                    (None, false, 'b' | 'B') => {
                        out.push_str("(?-u:\\");
                        out.push(e);
                        out.push(')');
                    }
                    _ => {
                        out.push('\\');
                        out.push(e);
                    }
                }
            }
            _ => out.push(c),
        }
    }
    out
}

pub(super) fn allow(raw: RawAllow) -> Allow {
    Allow {
        regexes: raw.regexes.iter().filter_map(|r| compile(r)).collect(),
        target: raw.target.unwrap_or_else(|| "secret".into()),
        paths: raw.paths.iter().filter_map(|r| compile(r)).collect(),
        stopwords: raw.stopwords.iter().map(|s| s.to_lowercase()).collect(),
        all: raw.condition.as_deref() == Some("AND"),
    }
}

impl Allow {
    pub(super) fn allows(&self, path: &str, secret: &str, whole: &str, line: &str) -> bool {
        let target = match self.target.as_str() {
            "match" => whole,
            "line" => line,
            _ => secret,
        };
        let checks = [
            (!self.regexes.is_empty()).then(|| self.regexes.iter().any(|r| r.is_match(target))),
            (!self.paths.is_empty()).then(|| self.paths.iter().any(|r| r.is_match(path))),
            (!self.stopwords.is_empty()).then(|| {
                let lower = secret.to_lowercase();
                self.stopwords.iter().any(|s| lower.contains(s))
            }),
        ];
        let mut present = checks.iter().flatten();
        if self.all {
            checks.iter().flatten().count() > 0 && present.all(|c| *c)
        } else {
            present.any(|c| *c)
        }
    }
}

impl Rule {
    pub(super) fn regex(&self) -> Option<&Regex> {
        self.regex
            .get_or_init(|| self.pattern.as_deref().and_then(compile))
            .as_ref()
    }
}
