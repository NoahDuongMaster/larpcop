//! ast-grep rules (YAML, tree-sitter based) — one engine for 25+ languages.
//!
//! Inline suppression comments are deliberately NOT honoured: exceptions must go
//! through config, where they are visible in review and blocked for locked rules.

use super::values::{Resolve, Settings};
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
    /// (id, language) → `metadata.resolve` of the rule.
    resolve: std::collections::HashMap<(String, String), Resolve>,
    settings: Settings,
}

/// Rule fixtures directory (ast-grep's convention), inside or next to a rule dir.
pub const TESTS_DIR: &str = "rule-tests";

/// Every rule defined in `dirs`, enabled or not (`larpcop test` checks them all).
pub fn load_all(dirs: &[PathBuf]) -> Result<Vec<RuleConfig<SupportLang>>> {
    use rayon::prelude::*;
    // Reading and parsing rule files is what every command pays first: in
    // parallel it costs one file's worth instead of all of them.
    let parsed: Vec<(PathBuf, Vec<RuleConfig<SupportLang>>)> = rule_files(dirs)?
        .into_par_iter()
        .map(|file| {
            let text =
                fs::read_to_string(&file).with_context(|| format!("reading {}", file.display()))?;
            let text = super::pattern_fixes::rewrite_rule_file(&text).unwrap_or(text);
            let rules = from_yaml_string::<SupportLang>(&text, &GlobalRules::default())
                .map_err(|e| anyhow!("invalid rule file {}: {}", file.display(), chain(&e)))?;
            Ok((file, rules))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut out = Vec::new();
    // One id may exist once per language (`no-eval` for TypeScript, Tsx and
    // JavaScript): disabling or locking the id covers all of them.
    let mut origin: BTreeMap<(String, String), PathBuf> = BTreeMap::new();
    for (file, rules) in parsed {
        for rule in rules {
            if rule.id.is_empty() {
                bail!("rule without `id` in {}", file.display());
            }
            let key = (rule.id.clone(), rule.language.to_string());
            if let Some(prev) = origin.insert(key, file.clone()) {
                bail!(
                    "duplicate rule id `{}` for {} in {} and {}",
                    rule.id,
                    rule.language,
                    prev.display(),
                    file.display()
                );
            }
            out.push(rule);
        }
    }
    Ok(out)
}

impl AstRules {
    pub fn load(dirs: &[PathBuf], disabled: &BTreeSet<String>, root: &Path) -> Result<Self> {
        let configs: Vec<_> = load_all(dirs)?
            .into_iter()
            .filter(|r| !disabled.contains(&r.id) && !matches!(r.severity, Severity::Off))
            .collect();
        let infos = merge_languages(configs.iter().map(info));
        let mut resolve = std::collections::HashMap::new();
        for r in &configs {
            if let Some(spec) = Resolve::of(r)? {
                resolve.insert((r.id.clone(), r.language.to_string()), spec);
            }
        }
        let collection =
            RuleCollection::try_new(configs).context("invalid files/ignores glob in rules")?;
        Ok(Self {
            collection,
            infos,
            resolve,
            settings: Settings::new(root),
        })
    }

    pub fn is_empty(&self) -> bool {
        self.infos.is_empty()
    }

    pub fn infos(&self) -> &[RuleInfo] {
        &self.infos
    }

    pub fn infos_for(&self, rel: &str) -> Vec<RuleInfo> {
        if SupportLang::from_path(rel).is_none() {
            return Vec::new();
        }
        self.collection
            .for_path(rel)
            .into_iter()
            .map(info)
            .collect()
    }

    pub fn check(&self, file: &SourceFile) -> Vec<Violation> {
        let rules = self.collection.for_path(&file.rel);
        let Some(lang) = SupportLang::from_path(&file.rel) else {
            return Vec::new();
        };
        if rules.is_empty() {
            return Vec::new();
        }
        let grep = lang.ast_grep(super::macros::expand(lang, &file.content));
        let mut out = Vec::new();
        for rule in rules {
            let note = match (&rule.note, rule.fixer.is_empty()) {
                (note, true) => note.clone(),
                (note, false) => Some(format!(
                    "{}Auto-fixable: run `larpcop fix {}`.",
                    note.as_deref()
                        .map(|n| format!("{n}\n"))
                        .unwrap_or_default(),
                    file.rel
                )),
            };
            let resolve = self
                .resolve
                .get(&(rule.id.clone(), rule.language.to_string()));
            let kept = |m: &ast_grep_core::NodeMatch<_>| {
                resolve.is_none_or(|r| r.keeps(m, &self.settings))
            };
            // `any:` branches matching a node and its parent at the same start
            // (a call and its statement) report once.
            let mut seen = std::collections::HashSet::new();
            for m in grep.root().find_all(&rule.matcher).filter(kept) {
                let pos = m.start_pos();
                if !seen.insert((pos.line(), pos.column(m.get_node()))) {
                    continue;
                }
                out.push(Violation {
                    rule: rule.id.clone(),
                    level: level(&rule.severity),
                    file: file.rel.clone(),
                    line: pos.line() + 1,
                    column: pos.column(m.get_node()) + 1,
                    message: rule.get_message(&m),
                    note: note.clone(),
                    snippet: Some(snippet(&file.content, pos.line())),
                });
            }
        }
        out
    }

    /// Applies every `fix:` of the rules matching `file`; `None` if nothing changed.
    pub fn fix(&self, file: &SourceFile) -> Option<(String, usize)> {
        let lang = SupportLang::from_path(&file.rel)?;
        let rules: Vec<_> = self.collection.for_path(&file.rel);
        let (text, total) = apply_fixes(lang, &file.content, &rules);
        (total > 0).then_some((text, total))
    }
}

/// Fixes can expose new matches, so this repeats (bounded); overlapping edits
/// wait for the next pass. Returns the new text and how many fixes were applied.
pub fn apply_fixes(
    lang: SupportLang,
    source: &str,
    rules: &[&RuleConfig<SupportLang>],
) -> (String, usize) {
    let mut text = source.to_string();
    let mut total = 0;
    for _ in 0..5 {
        let grep = lang.ast_grep(&text);
        let mut edits: Vec<_> = rules
            .iter()
            .filter(|r| !r.fixer.is_empty())
            .flat_map(|rule| {
                grep.root()
                    .find_all(&rule.matcher)
                    .map(|m| m.make_edit(&rule.matcher, &rule.fixer[0]))
                    .collect::<Vec<_>>()
            })
            .collect();
        if edits.is_empty() {
            break;
        }
        edits.sort_by_key(|e| e.position);
        let mut bytes = text.clone().into_bytes();
        let mut next_start = usize::MAX;
        for e in edits.iter().rev() {
            if e.position + e.deleted_length > next_start {
                continue;
            }
            let range = e.position..e.position + e.deleted_length;
            bytes.splice(range, e.inserted_text.iter().copied());
            next_start = e.position;
            total += 1;
        }
        match String::from_utf8(bytes) {
            Ok(t) => text = t,
            Err(_) => break,
        }
    }
    (text, total)
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
            // Fixtures for `larpcop test`, not rules.
            if path.file_name().is_some_and(|n| n == TESTS_DIR) {
                continue;
            }
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

/// One entry per id; per-language variants list their languages together.
fn merge_languages(infos: impl Iterator<Item = RuleInfo>) -> Vec<RuleInfo> {
    let mut out: Vec<RuleInfo> = Vec::new();
    for i in infos {
        match out.iter_mut().find(|o| o.id == i.id) {
            Some(o) => o.scope = format!("{}, {}", o.scope, i.scope),
            None => out.push(i),
        }
    }
    out
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
