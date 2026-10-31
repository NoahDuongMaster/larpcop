//! ast-grep rules (YAML, tree-sitter based) — one engine for 25+ languages.
//!
//! Inline suppression comments are deliberately NOT honoured: exceptions must go
//! through config, where they are visible in review and blocked for locked rules.

use super::{Level, RuleInfo, Violation};
use crate::files::SourceFile;
use anyhow::{Context, Result, anyhow, bail};
use ast_grep_config::{GlobalRules, RuleCollection, RuleConfig, Severity, from_yaml_string};
use ast_grep_core::Language;
use ast_grep_language::{LanguageExt, SupportLang};
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

pub struct AstRules {
    collection: RuleCollection<SupportLang>,
    infos: Vec<RuleInfo>,
}

impl AstRules {
    pub fn load(dirs: &[PathBuf], disabled: &BTreeSet<String>) -> Result<Self> {
        let mut configs = Vec::new();
        let mut origin: BTreeMap<String, PathBuf> = BTreeMap::new();
        for file in rule_files(dirs)? {
            let text =
                fs::read_to_string(&file).with_context(|| format!("reading {}", file.display()))?;
            let parsed = from_yaml_string::<SupportLang>(&text, &GlobalRules::default())
                .map_err(|e| anyhow!("invalid rule file {}: {}", file.display(), chain(&e)))?;
            for rule in parsed {
                if rule.id.is_empty() {
                    bail!("rule without `id` in {}", file.display());
                }
                if let Some(prev) = origin.insert(rule.id.clone(), file.clone()) {
                    bail!(
                        "duplicate rule id `{}` in {} and {}",
                        rule.id,
                        prev.display(),
                        file.display()
                    );
                }
                if !disabled.contains(&rule.id) && !matches!(rule.severity, Severity::Off) {
                    configs.push(rule);
                }
            }
        }
        let infos = configs.iter().map(info).collect();
        let collection =
            RuleCollection::try_new(configs).context("invalid files/ignores glob in rules")?;
        Ok(Self { collection, infos })
    }

    pub fn is_empty(&self) -> bool {
        self.infos.is_empty()
    }

    pub fn infos(&self) -> &[RuleInfo] {
        &self.infos
    }

    pub fn check(&self, file: &SourceFile) -> Vec<Violation> {
        let rules = self.collection.for_path(&file.rel);
        let Some(lang) = SupportLang::from_path(&file.rel) else {
            return Vec::new();
        };
        if rules.is_empty() {
            return Vec::new();
        }
        let grep = lang.ast_grep(&file.content);
        let mut out = Vec::new();
        for rule in rules {
            for m in grep.root().find_all(&rule.matcher) {
                let pos = m.start_pos();
                out.push(Violation {
                    rule: rule.id.clone(),
                    level: level(&rule.severity),
                    file: file.rel.clone(),
                    line: pos.line() + 1,
                    column: pos.column(m.get_node()) + 1,
                    message: rule.get_message(&m),
                    note: rule.note.clone(),
                    snippet: Some(snippet(&file.content, pos.line())),
                });
            }
        }
        out
    }
}

fn rule_files(dirs: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for dir in dirs {
        if !dir.is_dir() {
            bail!("rule directory {} does not exist", dir.display());
        }
        collect_yaml(dir, &mut files)?;
    }
    Ok(files)
}

fn collect_yaml(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            collect_yaml(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "yml" || e == "yaml") {
            out.push(path);
        }
    }
    Ok(())
}

fn level(severity: &Severity) -> Level {
    match severity {
        Severity::Error => Level::Error,
        Severity::Warning => Level::Warning,
        Severity::Info => Level::Info,
        Severity::Hint | Severity::Off => Level::Hint,
    }
}

fn info(rule: &RuleConfig<SupportLang>) -> RuleInfo {
    RuleInfo {
        id: rule.id.clone(),
        level: level(&rule.severity),
        scope: rule.language.to_string(),
        message: rule.message.clone(),
        note: rule.note.clone(),
    }
}

/// The source line where the match starts, trimmed and capped for display.
fn snippet(content: &str, line: usize) -> String {
    let text = content.lines().nth(line).unwrap_or("").trim();
    match text.char_indices().nth(120) {
        Some((cut, _)) => format!("{}…", &text[..cut]),
        None => text.to_string(),
    }
}

fn chain(err: &dyn Error) -> String {
    let mut parts = vec![err.to_string()];
    let mut cur = err.source();
    while let Some(e) = cur {
        parts.push(e.to_string());
        cur = e.source();
    }
    parts.join(": ")
}
