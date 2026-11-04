//! ast-grep rules (YAML, tree-sitter based) — one engine for 25+ languages.
//!
//! Inline suppression comments are deliberately NOT honoured: exceptions must go
//! through config, where they are visible in review and blocked for locked rules.

use super::lines::LineIndex;
use super::values::{Resolve, Settings};
use super::{Level, RuleInfo, Violation};
use crate::files::SourceFile;
use anyhow::{Context, Result, anyhow, bail};
use ast_grep_config::{GlobalRules, RuleCollection, RuleConfig, Severity, from_yaml_string};
use ast_grep_core::{Doc, Language, Node};
use ast_grep_language::SupportLang;
use std::cell::OnceCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

pub struct AstRules {
    collection: RuleCollection<SupportLang>,
    infos: Vec<RuleInfo>,
    /// id → (language, `metadata.resolve`) of the rules that have one.
    resolve: HashMap<String, Vec<(SupportLang, Resolve)>>,
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
            let rewritten = super::pattern_fixes::rewrite_rule_file(&text)
                .map_err(|e| anyhow!("invalid rule file {}: {}", file.display(), chain(&e)))?;
            let text = rewritten.unwrap_or(text);
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
        let mut resolve: HashMap<String, Vec<(SupportLang, Resolve)>> = HashMap::new();
        for r in &configs {
            if let Some(spec) = Resolve::of(r)? {
                resolve
                    .entry(r.id.clone())
                    .or_default()
                    .push((r.language, spec));
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

    /// The rules for this path: its language, the rule's `files:` and `ignores:`.
    pub fn rules_for_path(&self, rel: &str) -> Vec<&RuleConfig<SupportLang>> {
        self.collection.for_path(rel)
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

    /// `rules` (those of `file`'s path) on a tree that has already been parsed.
    pub fn check_root<D: Doc>(
        &self,
        rules: &[&RuleConfig<SupportLang>],
        file: &SourceFile,
        root: &Node<D>,
    ) -> Vec<Violation> {
        if rules.is_empty() {
            return Vec::new();
        }
        let buckets = super::ast_walk::Buckets::new(root);
        let lines = LineIndex::new(&file.content);
        let mut out = Vec::new();
        for rule in rules {
            let resolve = self.resolve_of(rule);
            let kept = |m: &ast_grep_core::NodeMatch<_>| {
                resolve.is_none_or(|r| r.keeps(m, &self.settings))
            };
            // Most rules match nothing in most files: the note waits for a match.
            let note = OnceCell::new();
            // `any:` branches matching a node and its parent at the same start
            // (a call and its statement) report once.
            let mut seen = std::collections::HashSet::new();
            let matches = buckets.matches(root, &rule.matcher, kept);
            for m in matches {
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
                    note: note.get_or_init(|| note_of(rule, &file.rel)).clone(),
                    snippet: Some(snippet(&lines, pos.line())),
                });
            }
        }
        out
    }

    /// The `metadata.resolve` of `rule`, if it has one.
    fn resolve_of(&self, rule: &RuleConfig<SupportLang>) -> Option<&Resolve> {
        self.resolve
            .get(&rule.id)?
            .iter()
            .find(|(lang, _)| *lang == rule.language)
            .map(|(_, spec)| spec)
    }

    /// Applies every `fix:` of the rules matching `file`; `None` if nothing changed.
    pub fn fix(&self, file: &SourceFile) -> Option<(String, usize)> {
        let lang = SupportLang::from_path(&file.rel)?;
        let rules: Vec<_> = self.collection.for_path(&file.rel);
        let (text, total) = super::ast_fix::apply_fixes(lang, &file.content, &rules);
        (total > 0).then_some((text, total))
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
    for path in sorted_entries(dir)? {
        if path.is_dir() {
            // Fixtures for `larpcop test`, not rules.
            if path.file_name().is_some_and(|n| n == TESTS_DIR) {
                continue;
            }
            collect_yaml(&path, out)?;
        } else if is_yaml(&path) {
            out.push(path);
        }
    }
    Ok(())
}

/// The entries of `dir`, sorted; one that cannot be read is an error.
pub(super) fn sorted_entries(dir: &Path) -> Result<Vec<PathBuf>> {
    let reading = || format!("reading directory {}", dir.display());
    let mut entries = Vec::new();
    for entry in fs::read_dir(dir).with_context(reading)? {
        entries.push(entry.with_context(reading)?.path());
    }
    entries.sort();
    Ok(entries)
}

pub(super) fn is_yaml(path: &Path) -> bool {
    path.extension().is_some_and(|e| e == "yml" || e == "yaml")
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

/// The rule's note, and for a fixable one where to run the fix.
fn note_of(rule: &RuleConfig<SupportLang>, rel: &str) -> Option<String> {
    if rule.fixer.is_empty() {
        return rule.note.clone();
    }
    Some(format!(
        "{}Auto-fixable: run `larpcop fix {rel}`.",
        rule.note
            .as_deref()
            .map(|n| format!("{n}\n"))
            .unwrap_or_default(),
    ))
}

/// The source line where the match starts, trimmed and capped for display.
fn snippet(lines: &LineIndex, line: usize) -> String {
    let text = lines.line(line).unwrap_or("").trim();
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
