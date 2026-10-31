//! `larpcop learn`: turn a standard written in words (an instruction, or the
//! team's recurring review comments) into deterministic ast-grep rules.
//! The model only proposes; a rule is kept only if it parses and passes the
//! valid/invalid examples the model wrote for it. Failures go back to the
//! model with the exact error, a few times, then are dropped.

use super::{Llm, extract_json};
use crate::config::Config;
use crate::files::{self, Scope, SourceFile};
use anyhow::{Context, Result, bail};
use ast_grep_language::{Language, LanguageExt, SupportLang};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fmt::Write;
use std::path::{Path, PathBuf};

pub struct Learned {
    pub id: String,
    pub language: String,
    pub cases: usize,
    /// Places in the repository that already violate it (to baseline or fix).
    pub existing: usize,
}

pub struct Outcome {
    pub kept: Vec<Learned>,
    pub dropped: Vec<(String, String)>,
    pub dir: PathBuf,
}

pub fn learn(
    cfg: &Config,
    known: &[String],
    from: &str,
    out: &Path,
    attempts: usize,
) -> Result<Outcome> {
    let llm = Llm::new(&cfg.llm)?;
    let sources = files::collect(&cfg.root, &Scope::All, &files::globset(&cfg.exclude)?)?;
    let mut ask = format!(
        "{}\n\n{}\n\n## What to turn into rules\n\n{from}\n",
        GUIDE,
        super::sources::languages(&sources)
    );
    let mut kept = Vec::new();
    let mut dropped = BTreeMap::new();
    for attempt in 1..=attempts {
        let answer = llm.ask(&ask, attempt == 1)?;
        let Some(Value::Array(proposals)) = extract_json(&answer) else {
            bail!(
                "`{}` did not answer with a JSON array:\n{}",
                llm.name(),
                answer.trim()
            );
        };
        let mut failed = Vec::new();
        for p in proposals {
            let id = p["id"].as_str().unwrap_or("").to_string();
            match validate(&p, known, &kept) {
                Ok(cases) => {
                    write(out, &p)?;
                    dropped.remove(&id);
                    kept.push(Learned {
                        existing: existing(&p, &sources),
                        language: languages(&p).join(","),
                        id,
                        cases,
                    });
                }
                Err(e) => {
                    dropped.insert(id, format!("{e:#}"));
                    failed.push((p, format!("{e:#}")));
                }
            }
        }
        if failed.is_empty() {
            break;
        }
        ask = format!(
            "{GUIDE}\n\nThese proposed rules failed validation. Return corrected versions of these \
only, in the same JSON format (drop one if it cannot be expressed as a rule):\n"
        );
        for (p, e) in failed {
            let _ = write!(
                ask,
                "\n### Proposal\n{}\n### Error\n{e}\n",
                serde_json::to_string_pretty(&p)?
            );
        }
    }
    Ok(Outcome {
        kept,
        dropped: dropped.into_iter().collect(),
        dir: out.to_path_buf(),
    })
}

fn validate(p: &Value, known: &[String], kept: &[Learned]) -> Result<usize> {
    let id = p["id"].as_str().context("missing `id`")?;
    if !id
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        bail!("id `{id}` must be kebab-case");
    }
    if known.iter().any(|k| k == id) || kept.iter().any(|k| k.id == id) {
        bail!("a rule `{id}` already exists; pick another id");
    }
    if languages(p).is_empty() {
        bail!("missing `language` (or `languages`)");
    }
    let (valid, invalid) = (cases(p, "valid"), cases(p, "invalid"));
    if valid.is_empty() || invalid.is_empty() {
        bail!("needs at least one `valid` and one `invalid` example");
    }
    let tmp = tempfile::tempdir()?;
    write(tmp.path(), p)?;
    let report = crate::rules::testing::run(&crate::rules::testing::Defined {
        rule_dirs: vec![tmp.path().join("rules")],
        ..Default::default()
    })?;
    if report.failures > 0 {
        bail!("{}", report.text.trim());
    }
    Ok(valid.len() + invalid.len())
}

fn cases(p: &Value, key: &str) -> Vec<String> {
    p[key]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| v.as_str().map(String::from))
        .collect()
}

/// `"languages": [..]` or `"language": ".."`.
fn languages(p: &Value) -> Vec<String> {
    match p["languages"].as_array() {
        Some(list) => list
            .iter()
            .filter_map(|l| l.as_str().map(String::from))
            .collect(),
        None => p["language"]
            .as_str()
            .map(String::from)
            .into_iter()
            .collect(),
    }
}

/// `<dir>/rules/<id>.yml` (one document per language) and `<dir>/rule-tests/<id>-test.yml`.
fn write(dir: &Path, p: &Value) -> Result<()> {
    let id = p["id"].as_str().unwrap_or("rule");
    let mut docs = Vec::new();
    for language in languages(p) {
        let mut rule = json!({ "id": id, "language": language,
            "severity": p["severity"].as_str().unwrap_or("error"),
            "message": p["message"], "note": p["note"], "rule": p["rule"] });
        if let Some(fix) = p["fix"].as_str() {
            rule["fix"] = json!(fix);
        }
        docs.push(serde_saphyr::to_string(&rule)?);
    }
    let tests = json!({ "id": id, "valid": cases(p, "valid"), "invalid": cases(p, "invalid") });
    for (sub, name, body) in [
        ("rules", format!("{id}.yml"), docs.join("---\n")),
        (
            "rule-tests",
            format!("{id}-test.yml"),
            serde_saphyr::to_string(&tests)?,
        ),
    ] {
        std::fs::create_dir_all(dir.join(sub))?;
        let yaml = format!("# Learned by `larpcop learn`; review before merging.\n{body}");
        std::fs::write(dir.join(sub).join(name), yaml)?;
    }
    Ok(())
}

fn existing(p: &Value, sources: &[SourceFile]) -> usize {
    let Ok(tmp) = tempfile::tempdir() else {
        return 0;
    };
    write(tmp.path(), p)
        .ok()
        .and_then(|_| crate::rules::ast_rules(&[tmp.path().join("rules")]).ok())
        .map_or(0, |rules| {
            sources
                .iter()
                .map(|f| {
                    rules
                        .iter()
                        .filter(|r| SupportLang::from_path(&f.rel) == Some(r.language))
                        .map(|r| {
                            r.language
                                .ast_grep(&f.content)
                                .root()
                                .find_all(&r.matcher)
                                .count()
                        })
                        .sum::<usize>()
                })
                .sum()
        })
}

const GUIDE: &str = include_str!("learn_guide.md");

/// CLI entry: gathers the input, learns, prints what was kept and dropped.
pub fn run(
    ctx: &crate::context::Ctx,
    instruction: Option<String>,
    reviews: Option<usize>,
    out: Option<PathBuf>,
    attempts: usize,
) -> Result<u8> {
    let (cfg, engine) = ctx.load()?;
    let mut from = instruction.unwrap_or_default();
    if let Some(n) = reviews {
        from.push_str(&super::sources::review_comments(&cfg.root, n)?);
    }
    let out = out.map_or_else(
        || {
            cfg.rule_dirs
                .iter()
                .find(|d| d.starts_with(&cfg.root))
                .and_then(|d| d.parent().map(Path::to_path_buf))
                .unwrap_or_else(|| cfg.root.join(".larpcop"))
        },
        |o| cfg.root.join(o),
    );
    let known: Vec<String> = engine.rules().into_iter().map(|r| r.id).collect();
    let result = learn(&cfg, &known, &from, &out, attempts)?;
    for k in &result.kept {
        println!(
            "✓ {:<28} {:<11} {} test case(s), {} existing violation(s)",
            k.id, k.language, k.cases, k.existing
        );
    }
    for (id, why) in &result.dropped {
        println!("✗ {id}: {}", why.lines().next().unwrap_or(""));
    }
    if result.kept.is_empty() {
        println!("larpcop: no rule passed its tests.");
        return Ok(1);
    }
    let dir = result
        .dir
        .strip_prefix(&cfg.root)
        .unwrap_or(&result.dir)
        .display()
        .to_string();
    println!(
        "larpcop: wrote {} rule(s) to {dir}/rules. Review them, then make sure `.larpcop.yaml` lists `rule_dirs: [{dir}/rules]`.",
        result.kept.len()
    );
    Ok(0)
}
