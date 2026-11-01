//! Arms of a `switch` / `when` / `match` on a plain name whose labels are
//! fixed values: inside the arm the name equals one of them, so it carries no
//! request data there (`case "name": query("ORDER BY " + sort)`). A Kotlin
//! `in ALLOWED ->` arm is an allow-list. `default`/`else` arms, labels that
//! are variables or calls, and arms a non-fixed arm falls through into stay
//! as they are.

use super::NAMES;
use super::guards::Guard;
use super::kotlin::Part;
use ast_grep_core::{Doc, Node};
use std::collections::HashSet;

/// Java, JS/TS/C#/PHP, Go, Kotlin, Python.
pub(super) const SWITCHES: [&str; 5] = [
    "switch_expression",
    "switch_statement",
    "expression_switch_statement",
    "when_expression",
    "match_statement",
];

const ARMS: [&str; 11] = [
    "switch_block_statement_group",
    "switch_rule",
    "switch_case",
    "switch_default",
    "switch_section",
    "expression_case",
    "default_case",
    "case_statement",
    "default_statement",
    "when_entry",
    "case_clause",
];

/// Arms that run on into the next one unless they end with a jump.
const FALLING: [&str; 4] = [
    "switch_block_statement_group",
    "switch_case",
    "switch_default",
    "case_statement",
];

const JUMPS: [&str; 5] = [
    "break_statement",
    "return_statement",
    "throw_statement",
    "continue_statement",
    "yield_statement",
];

pub(super) fn arms<D: Doc>(n: &Node<D>) -> Vec<Guard> {
    let Some(subject) = subject(n) else {
        return Vec::new();
    };
    if !NAMES.contains(&subject.kind().as_ref()) {
        return Vec::new();
    }
    let names: HashSet<String> = [subject.text().to_string()].into();
    let holder = n.part("body").unwrap_or_else(|| n.clone());
    let mut out = Vec::new();
    // What runs into the next arm: nothing before the first one.
    let mut into_next_clean = true;
    for arm in holder
        .children()
        .filter(|c| ARMS.contains(&c.kind().as_ref()))
    {
        let fixed = labels(&arm).is_some_and(|ls| !ls.is_empty() && ls.iter().all(fixed));
        let falls = FALLING.contains(&arm.kind().as_ref());
        let safe = fixed && (!falls || into_next_clean);
        if safe {
            out.push(Guard::Within(arm.range(), names.clone()));
        }
        into_next_clean = safe || !falls || ends(&arm);
    }
    out
}

fn subject<'a, D: Doc>(n: &Node<'a, D>) -> Option<Node<'a, D>> {
    let mut s = n
        .part("condition")
        .or_else(|| n.part("value"))
        .or_else(|| n.part("subject"))?;
    while s.kind() == "parenthesized_expression" {
        let inner = s.children().find(|c| c.is_named())?;
        s = inner;
    }
    Some(s)
}

/// The values an arm is taken for; `None` for a default arm.
fn labels<'a, D: Doc>(arm: &Node<'a, D>) -> Option<Vec<Node<'a, D>>> {
    let named =
        |n: &Node<'a, D>| -> Vec<Node<'a, D>> { n.children().filter(|c| c.is_named()).collect() };
    match arm.kind().as_ref() {
        "switch_block_statement_group" | "switch_rule" => {
            let mut out = Vec::new();
            for label in arm.children().filter(|c| c.kind() == "switch_label") {
                let values = named(&label);
                if values.is_empty() {
                    return None;
                }
                out.extend(values);
            }
            Some(out)
        }
        "switch_case" | "case_statement" => Some(vec![arm.part("value")?]),
        "expression_case" => Some(named(&arm.part("value")?)),
        "switch_section" => {
            let patterns: Vec<Node<D>> = arm
                .children()
                .filter(|c| c.kind().ends_with("pattern"))
                .collect();
            (!patterns.is_empty()).then_some(patterns)
        }
        "when_entry" => {
            let conditions: Vec<Node<D>> = arm
                .children()
                .filter(|c| c.kind() == "when_condition")
                .collect();
            (!conditions.is_empty()).then_some(conditions)
        }
        "case_clause" => {
            let pattern = arm.children().find(|c| c.kind() == "case_pattern")?;
            if arm.part("guard").is_some() {
                return Some(vec![arm.clone()]);
            }
            let inner = pattern.children().find(|c| c.is_named())?;
            if inner.kind() == "union_pattern" {
                return Some(named(&inner));
            }
            // `case x:` binds anything to `x`.
            (!NAMES.contains(&inner.kind().as_ref())).then(|| vec![inner])
        }
        _ => None,
    }
}

/// A literal, a constant by name (`RED`, `Color.RED`), or Kotlin `in ALLOWED`.
fn fixed<D: Doc>(label: &Node<D>) -> bool {
    let text = label.text();
    let text = text.trim();
    if label.kind() == "when_condition" && text.starts_with("in ") {
        return true;
    }
    if label.kind() == "case_clause" {
        return false;
    }
    let literal = !label.dfs().any(|d| NAMES.contains(&d.kind().as_ref()));
    let segments: Vec<&str> = text.split('.').collect();
    let named = segments
        .iter()
        .all(|s| !s.is_empty() && s.chars().all(|c| c.is_alphanumeric() || c == '_'));
    let last = segments.last().copied().unwrap_or_default();
    let constant = named
        && last.chars().any(|c| c.is_ascii_uppercase())
        && last
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
    literal || constant
}

/// Does the arm end with a jump (`break`, `return`, …)?
fn ends<D: Doc>(arm: &Node<D>) -> bool {
    arm.children()
        .filter(|c| c.is_named() && !c.kind().contains("comment"))
        .last()
        .is_some_and(|l| {
            JUMPS.contains(&l.kind().as_ref())
                || l.children().any(|c| JUMPS.contains(&c.kind().as_ref()))
        })
}
