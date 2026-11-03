//! Multi-rule taint checking orchestrator evaluating compatible rules in a single AST pass.

use super::TaintRule;
use super::check::class_of;
use super::fields;
use super::flow::Ctx;
use super::multi_hits::MultiHits;
use super::multi_mask::{RuleMask, TaintEnv};
use super::multi_summary::MultiSummaries;
use super::multi_walk::{MultiCtx, MultiReached};
use super::scan::FileIndex;
use super::summary::Summaries;
use crate::files::SourceFile;
use crate::rules::Violation;
use ast_grep_core::{Doc, Node};
use ast_grep_language::SupportLang;
use std::collections::HashMap;

/// Checks all taint rules across a parsed and indexed file simultaneously.
pub fn check_indexed_multi<D: Doc>(
    rules: &[TaintRule],
    file: &SourceFile,
    lang: SupportLang,
    index: &FileIndex<D>,
) -> Vec<Violation> {
    let candidates: Vec<(usize, &TaintRule)> = rules
        .iter()
        .enumerate()
        .filter(|(_, r)| r.handles(lang) && !r.exclude.is_match(&file.rel))
        .collect();

    if candidates.is_empty() {
        return Vec::new();
    }

    let mut all_violations = Vec::new();
    for batch in candidates.chunks(128) {
        let mut original_indices = Vec::new();
        let mut surviving_rules = Vec::new();
        let mut surviving_ctxs = Vec::new();
        let mut surviving_hits = Vec::new();

        for &(orig_idx, rule) in batch {
            if let Some((ctx, hits)) = rule.prepare(lang, index, file, 0) {
                original_indices.push(orig_idx);
                surviving_rules.push(rule);
                surviving_ctxs.push(ctx);
                surviving_hits.push(hits);
            }
        }
        if surviving_rules.is_empty() {
            continue;
        }

        let ctx_refs: Vec<&Ctx> = surviving_ctxs.iter().collect();
        let multi_hits = MultiHits::from_prepared(&surviving_rules, &ctx_refs, &surviving_hits);
        let summaries_per_rule: Vec<(RuleMask, &Summaries)> = surviving_ctxs
            .iter()
            .enumerate()
            .map(|(i, c)| (1u128 << i, &c.summaries))
            .collect();
        let multi_summaries = MultiSummaries::merge(&summaries_per_rule);

        let active_rules: RuleMask = if surviving_rules.len() >= 128 {
            !0u128
        } else {
            (1u128 << surviving_rules.len()) - 1
        };
        let bare_calls = surviving_ctxs.iter().any(|c| c.bare_calls);
        let numbers = surviving_ctxs.iter().any(|c| c.numbers);

        let ctx = MultiCtx {
            active_rules,
            hits: &multi_hits,
            summaries: &multi_summaries,
            bare_calls,
            numbers,
        };

        let root = &index.root;
        let mut out: Vec<(usize, Violation)> = Vec::new();
        let mut fields: HashMap<(usize, usize), HashMap<String, RuleMask>> = HashMap::new();

        for _ in 0..2 {
            let own = |n: &Node<D>| {
                let mut env = TaintEnv::new();
                for (k, rule) in surviving_rules.iter().enumerate() {
                    let bit = 1u128 << k;
                    for name in rule.own_names(n) {
                        env.or_mask(name, bit);
                    }
                }
                if let Some(f_map) = class_of(n).and_then(|c| fields.get(&c)) {
                    for (name, &mask) in f_map {
                        if name.contains('.') || !fields::declares(n, name) {
                            env.or_mask(name, mask);
                        }
                    }
                }
                env
            };

            let mut stored: HashMap<(usize, usize), HashMap<String, RuleMask>> = HashMap::new();
            ctx.run(root, own(root), &own, &mut |r| match r {
                MultiReached::Sink {
                    arg,
                    mask,
                    sink_mask,
                    typed,
                } => {
                    let reached = mask & sink_mask;
                    for (k, rule) in surviving_rules.iter().enumerate() {
                        let bit = 1u128 << k;
                        if (reached & bit) != 0 {
                            let rule_typed = typed
                                .iter()
                                .find(|(id, _)| *id == (k as u8))
                                .map(|(_, t)| t.as_slice())
                                .unwrap_or(&[]);
                            if rule.typed.holds(lang, file, rule_typed) {
                                out.push((original_indices[k], rule.violation(file, &arg, None)));
                            }
                        }
                    }
                }
                MultiReached::Call {
                    arg,
                    mask: _,
                    into,
                    rule_id,
                } => {
                    let k = rule_id as usize;
                    if let (Some(rule), Some(&orig_idx)) =
                        (surviving_rules.get(k), original_indices.get(k))
                    {
                        out.push((orig_idx, rule.violation(file, &arg, Some(into))));
                    }
                }
                MultiReached::Responds { f, value, mask } => {
                    for (k, rule) in surviving_rules.iter().enumerate() {
                        let bit = 1u128 << k;
                        if (mask & bit) != 0
                            && rule.responds.as_ref().is_some_and(|r| r.holds(&f, &value))
                        {
                            out.push((original_indices[k], rule.violation(file, &value, None)));
                        }
                    }
                }
                MultiReached::Field(left, mask) => {
                    if let Some(c) = class_of(&left) {
                        let name =
                            super::entries::entry(&left).unwrap_or_else(|| left.text().to_string());
                        *stored.entry(c).or_default().entry(name).or_default() |= mask;
                    }
                }
                _ => {}
            });

            let known = |(c, stored_map): (&(usize, usize), &HashMap<String, RuleMask>)| {
                fields.get(c).is_some_and(|f_map| {
                    stored_map
                        .iter()
                        .all(|(k, m)| (m & !f_map.get(k).copied().unwrap_or(0)) == 0)
                })
            };
            if stored.iter().all(known) {
                break;
            }
            for (c, stored_map) in stored {
                let f_map = fields.entry(c).or_default();
                for (k, m) in stored_map {
                    *f_map.entry(k).or_default() |= m;
                }
            }
        }

        all_violations.extend(out);
    }

    all_violations.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| (a.1.line, a.1.column).cmp(&(b.1.line, b.1.column)))
    });
    all_violations.dedup_by(|a, b| a.0 == b.0 && a.1.line == b.1.line && a.1.column == b.1.column);
    all_violations.into_iter().map(|(_, v)| v).collect()
}
