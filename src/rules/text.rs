//! Regex rules over files ast-grep has no grammar for: templates (EJS,
//! Handlebars, Jinja, Blade, ERB…), HTML, config formats.

use super::{Level, RuleInfo, Violation};
use crate::config::TextRuleConfig;
use crate::files::SourceFile;
use anyhow::{Context, Result};
use globset::GlobSet;
use regex::Regex;

pub struct TextRule {
    id: String,
    level: Level,
    message: String,
    note: Option<String>,
    files: GlobSet,
    globs: String,
    regex: Regex,
    not: Option<Regex>,
    /// (other file, regex): the rule is off while one matches.
    unless: Vec<(Option<std::path::PathBuf>, Regex)>,
}

impl TextRule {
    pub fn new(cfg: &TextRuleConfig, root: &std::path::Path) -> Result<Self> {
        let compile =
            |r: &str| Regex::new(r).with_context(|| format!("text rule `{}`: regex `{r}`", cfg.id));
        Ok(Self {
            id: cfg.id.clone(),
            level: cfg.severity.unwrap_or_default(),
            message: cfg.message.clone(),
            note: cfg.note.clone(),
            files: crate::files::globset(&cfg.files)?,
            globs: cfg.files.join(", "),
            regex: compile(&cfg.regex)?,
            not: cfg.not.as_deref().map(compile).transpose()?,
            unless: cfg
                .unless
                .iter()
                .map(|c| Ok((c.file.as_ref().map(|f| root.join(f)), compile(&c.regex)?)))
                .collect::<Result<_>>()?,
        })
    }

    pub fn check(&self, file: &SourceFile) -> Vec<Violation> {
        if !self.files.is_match(&file.rel) {
            return Vec::new();
        }
        let text = &file.content;
        let holds = |(other, re): &(Option<std::path::PathBuf>, Regex)| match other {
            None => re.is_match(text),
            Some(path) => std::fs::read_to_string(path).is_ok_and(|t| re.is_match(&t)),
        };
        if self.unless.iter().any(holds) {
            return Vec::new();
        }
        self.regex
            .find_iter(text)
            .filter(|m| !self.not.as_ref().is_some_and(|n| n.is_match(m.as_str())))
            .map(|m| {
                let before = &text[..m.start()];
                let line_start = before.rfind('\n').map_or(0, |i| i + 1);
                let line_end = text[m.start()..]
                    .find('\n')
                    .map_or(text.len(), |i| m.start() + i);
                Violation {
                    rule: self.id.clone(),
                    level: self.level,
                    file: file.rel.clone(),
                    line: before.matches('\n').count() + 1,
                    column: before[line_start..].chars().count() + 1,
                    message: self.message.clone(),
                    note: self.note.clone(),
                    snippet: Some(text[line_start..line_end].trim().to_string()),
                }
            })
            .collect()
    }

    pub fn info(&self) -> RuleInfo {
        RuleInfo {
            id: self.id.clone(),
            level: self.level,
            scope: self.globs.clone(),
            message: self.message.clone(),
            note: self.note.clone(),
        }
    }

    pub fn applies_to(&self, rel: &str) -> bool {
        self.files.is_match(rel)
    }
}

#[cfg(test)]
mod tests {
    use crate::config::TextRuleConfig;

    #[test]
    fn matches_lines_of_listed_files_except_the_not_regex() {
        let cfg: TextRuleConfig = serde_saphyr::from_str(
            "id: t\nfiles: ['**/*.ejs']\nregex: '<%-[^%]*%>'\nnot: '^<%-\\s*include\\b'\nmessage: raw output\n",
        )
        .unwrap();
        let rule = super::TextRule::new(&cfg, std::path::Path::new(".")).unwrap();
        let file = |rel: &str| crate::files::SourceFile {
            rel: rel.into(),
            content: "<%- include('head') %>\n<p><%= safe %></p>\n  <b><%- user.name %></b>\n"
                .into(),
        };
        let v = rule.check(&file("views/a.ejs"));
        assert_eq!(
            v.iter().map(|v| (v.line, v.column)).collect::<Vec<_>>(),
            [(3, 6)]
        );
        assert_eq!(v[0].snippet.as_deref(), Some("<b><%- user.name %></b>"));
        assert!(rule.check(&file("src/a.js")).is_empty());
    }
}
