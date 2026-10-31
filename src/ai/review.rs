//! `agentkit review`: plain-language rules judged by a model, file by file.
//! Findings are warnings, never errors: a model is not deterministic, and a
//! gate must be. On a diff, only lines the diff touches are reported.

use super::{Llm, extract_json};
use crate::config::{Config, LlmRule};
use crate::files::{self, Scope, SourceFile};
use crate::rules::{Level, Violation};
use anyhow::Result;
use globset::GlobSet;
use rayon::prelude::*;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;
use std::path::Path;
use std::process::Command;

/// Files larger than this are skipped: the answer would be unreliable.
const MAX_BYTES: usize = 120_000;

pub fn review(cfg: &Config, scope: &Scope, cached: bool) -> Result<(usize, Vec<Violation>)> {
    let llm = Llm::new(&cfg.llm)?;
    let rules: Vec<(&LlmRule, GlobSet)> = cfg
        .llm
        .rules
        .iter()
        .filter(|r| !cfg.disabled.contains(&r.id))
        .map(|r| Ok((r, files::globset(&r.files)?)))
        .collect::<Result<_>>()?;
    let exclude = files::globset(&cfg.exclude)?;
    let sources = files::collect(&cfg.root, scope, &exclude)?;
    let changed = changed_lines(&cfg.root, scope);
    let jobs: Vec<(&SourceFile, Vec<&LlmRule>)> = sources
        .iter()
        .filter(|f| f.content.len() <= MAX_BYTES)
        .map(|f| {
            let applicable = rules
                .iter()
                .filter(|(r, g)| r.files.is_empty() || g.is_match(&f.rel))
                .map(|(r, _)| *r)
                .collect::<Vec<_>>();
            (f, applicable)
        })
        .filter(|(f, rs)| !rs.is_empty() && changed.as_ref().is_none_or(|c| c.contains_key(&f.rel)))
        .collect();
    let pool = rayon::ThreadPoolBuilder::new().num_threads(4).build()?;
    let results: Vec<Result<Vec<Violation>>> = pool.install(|| {
        jobs.par_iter()
            .map(|(file, rules)| {
                let lines = changed.as_ref().and_then(|c| c.get(&file.rel));
                let answer = llm.ask(&prompt(file, rules, lines), cached)?;
                Ok(parse(&answer, file, rules, lines))
            })
            .collect()
    });
    let mut out = Vec::new();
    for r in results {
        out.extend(r?);
    }
    crate::rules::sort(&mut out);
    Ok((jobs.len(), out))
}

fn prompt(file: &SourceFile, rules: &[&LlmRule], changed: Option<&BTreeSet<usize>>) -> String {
    let mut p = String::from(
        "You review code against the team's rules. Report only clear violations of these rules, \
nothing else (no style nits, no general advice).\n\nRules:\n",
    );
    for r in rules {
        let _ = writeln!(p, "- `{}`: {}", r.id, r.prompt.trim());
    }
    let focus = if changed.is_some() {
        "Lines marked `>` were changed; report violations on those lines only."
    } else {
        "Review the whole file."
    };
    let _ = writeln!(
        p,
        "\nAnswer with a JSON array only, `[]` if there is nothing: \
[{{\"rule\": \"<id>\", \"line\": <number>, \"message\": \"<what is wrong and how to fix it, one sentence>\"}}]\n\
{focus}\n\nFile `{}`:\n",
        file.rel
    );
    for (i, line) in file.content.lines().enumerate() {
        let mark = if changed.is_some_and(|c| c.contains(&(i + 1))) {
            '>'
        } else {
            ' '
        };
        let _ = writeln!(p, "{mark}{:>5} | {line}", i + 1);
    }
    p
}

fn parse(
    answer: &str,
    file: &SourceFile,
    rules: &[&LlmRule],
    changed: Option<&BTreeSet<usize>>,
) -> Vec<Violation> {
    let Some(serde_json::Value::Array(items)) = extract_json(answer) else {
        return Vec::new();
    };
    let lines = file.content.lines().count();
    items
        .iter()
        .filter_map(|i| {
            let id = i["rule"].as_str()?;
            let rule = rules.iter().find(|r| r.id == id)?;
            let line = usize::try_from(i["line"].as_u64()?).ok()?;
            let on_diff = changed.is_none_or(|c| c.contains(&line));
            (line >= 1 && line <= lines && on_diff).then(|| Violation {
                rule: rule.id.clone(),
                level: Level::Warning,
                file: file.rel.clone(),
                line,
                column: 1,
                message: i["message"].as_str().unwrap_or("").trim().to_string(),
                note: Some(format!("AI review: {}", rule.prompt.trim())),
                snippet: file
                    .content
                    .lines()
                    .nth(line - 1)
                    .map(|l| l.trim().to_string()),
            })
        })
        .collect()
}

/// Lines added or modified per file; `None` when the scope is not a diff.
fn changed_lines(root: &Path, scope: &Scope) -> Option<BTreeMap<String, BTreeSet<usize>>> {
    let range = match scope {
        Scope::Staged => vec!["--cached".to_string()],
        Scope::Changed => vec!["HEAD".to_string()],
        Scope::Since(base) => vec![format!("{base}...HEAD")],
        Scope::All | Scope::Paths(_) => return None,
    };
    let out = Command::new("git")
        .args(["diff", "-U0", "--no-color", "--relative"])
        .args(&range)
        .current_dir(root)
        .output()
        .ok()?;
    let mut map = parse_diff(&String::from_utf8_lossy(&out.stdout));
    // Untracked files are new in full.
    if matches!(scope, Scope::Changed) {
        for rel in files::list(root, scope).ok()? {
            map.entry(rel).or_insert_with_key(|rel| {
                let n = std::fs::read_to_string(root.join(rel)).map_or(0, |c| c.lines().count());
                (1..=n).collect()
            });
        }
    }
    Some(map)
}

fn parse_diff(diff: &str) -> BTreeMap<String, BTreeSet<usize>> {
    let mut map: BTreeMap<String, BTreeSet<usize>> = BTreeMap::new();
    let mut file = None;
    for line in diff.lines() {
        if let Some(path) = line.strip_prefix("+++ ") {
            file = path.strip_prefix("b/").map(String::from);
        } else if let (Some(f), Some(hunk)) = (&file, line.strip_prefix("@@ ")) {
            // @@ -a,b +c,d @@
            let Some(new) = hunk
                .split_whitespace()
                .nth(1)
                .and_then(|s| s.strip_prefix('+'))
            else {
                continue;
            };
            let (start, count) = new.split_once(',').unwrap_or((new, "1"));
            let (Ok(start), Ok(count)) = (start.parse::<usize>(), count.parse::<usize>()) else {
                continue;
            };
            map.entry(f.clone())
                .or_default()
                .extend(start..start + count);
        }
    }
    map
}

#[cfg(test)]
mod tests {
    #[test]
    fn added_lines_from_a_zero_context_diff() {
        let diff = "diff --git a/x.ts b/x.ts\n--- a/x.ts\n+++ b/x.ts\n@@ -2,0 +3,2 @@\n+a\n+b\n@@ -9 +11 @@\n-c\n+d\n\
                    --- a/gone.ts\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n";
        let map = super::parse_diff(diff);
        assert_eq!(map["x.ts"].iter().copied().collect::<Vec<_>>(), [3, 4, 11]);
        assert_eq!(map.len(), 1);
    }
}
