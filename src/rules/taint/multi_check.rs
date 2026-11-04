//! A file's check for many taint rules at once, in batches of [`BATCH`]: each
//! rule is prepared on its own, then one walk judges them all.

use super::TaintRule;
use super::check::{Stored, class_of, fixpoint};
use super::events::Hits;
use super::fields;
use super::flow::Ctx;
use super::multi_hits::MultiHits;
use super::multi_mask::{BATCH, RuleMask, TaintEnv, bit, rules_in};
use super::multi_summary::MultiSummaries;
use super::multi_walk::{MultiCtx, MultiReached};
use super::scan::FileIndex;
use super::summary::Summaries;
use crate::files::SourceFile;
use crate::rules::Violation;
use ast_grep_core::{Doc, Node};
use ast_grep_language::SupportLang;
use std::collections::HashMap;

/// What a batch's walk found: the rule (in the whole list), where, and the
/// summary the sink was reached through.
struct Found<'a, D: Doc> {
    rule: usize,
    at: Node<'a, D>,
    into: Option<String>,
}

/// Checks all taint rules across a parsed and indexed file simultaneously.
pub fn check_indexed_multi<'a, D: Doc>(
    rules: &[TaintRule],
    file: &SourceFile,
    lang: SupportLang,
    index: &FileIndex<'a, D>,
) -> Vec<Violation> {
    let candidates: Vec<(usize, &TaintRule)> = rules
        .iter()
        .enumerate()
        .filter(|(_, r)| r.handles(lang) && !r.exclude.is_match(&file.rel))
        .collect();
    let mut found: Vec<Found<'a, D>> = Vec::new();
    for batch in candidates.chunks(BATCH) {
        check_batch(batch, file, lang, index, &mut found);
    }
    // A sink reached directly and through a summary is one finding.
    found.sort_by_key(|f| (f.rule, f.at.range().start));
    found.dedup_by_key(|f| (f.rule, f.at.range().start));
    found
        .into_iter()
        .map(|f| rules[f.rule].violation(file, &f.at, f.into))
        .collect()
}

/// What rule `k` of a batch stores per class: the fields its methods put
/// request data in.
impl Stored for HashMap<String, RuleMask> {
    fn covered_by(&self, known: &Self) -> bool {
        self.iter()
            .all(|(name, m)| m & !known.get(name).copied().unwrap_or(0) == 0)
    }

    fn absorb(&mut self, more: Self) {
        for (name, mask) in more {
            *self.entry(name).or_default() |= mask;
        }
    }
}

fn check_batch<'a, D: Doc>(
    batch: &[(usize, &TaintRule)],
    file: &SourceFile,
    lang: SupportLang,
    index: &FileIndex<'a, D>,
    found: &mut Vec<Found<'a, D>>,
) {
    let mut listed: Vec<usize> = Vec::new();
    let mut rules: Vec<&TaintRule> = Vec::new();
    let mut ctxs: Vec<Ctx> = Vec::new();
    let mut hits: Vec<Hits<'a, D>> = Vec::new();
    for &(listing, rule) in batch {
        if let Some((ctx, h)) = rule.prepare(lang, index, file, 0) {
            listed.push(listing);
            rules.push(rule);
            ctxs.push(ctx);
            hits.push(h);
        }
    }
    if rules.is_empty() {
        return;
    }
    let ctx_refs: Vec<&Ctx> = ctxs.iter().collect();
    let multi_hits =
        MultiHits::from_prepared(&ctx_refs, &hits, &index.root, index.skeletons.clone());
    let summaries: Vec<&Summaries> = ctxs.iter().map(|c| &c.summaries).collect();
    let multi_summaries = MultiSummaries::merge(&summaries);
    let ctx = MultiCtx::new(&multi_hits, &multi_summaries, &ctx_refs, &rules);
    let root = &index.root;
    // Fields a method stores request data in, by class: read by the class's
    // other methods, so a second walk starts them tainted.
    fixpoint(
        |stored_before: &HashMap<(usize, usize), HashMap<String, RuleMask>>| {
            let own = |n: &Node<'a, D>| {
                let mut env = TaintEnv::new();
                for (k, rule) in rules.iter().enumerate() {
                    for name in rule.own_names(n) {
                        env.or_mask(&name, bit(k as u8));
                    }
                }
                if let Some(known) = class_of(n).and_then(|c| stored_before.get(&c)) {
                    for (name, &mask) in known {
                        // A bare field name is shadowed by a parameter or local.
                        if name.contains('.') || !fields::declares(n, name) {
                            env.or_mask(name, mask);
                        }
                    }
                }
                env
            };
            let mut stored: HashMap<(usize, usize), HashMap<String, RuleMask>> = HashMap::new();
            ctx.run(root, own(root), &own, false, &mut |r| match r {
                MultiReached::Sink {
                    arg,
                    rules: reached,
                    sink,
                } => {
                    for k in rules_in(reached) {
                        let typed = multi_hits.sinks[sink]
                            .typed
                            .iter()
                            .find(|(id, _)| *id == k)
                            .map_or(&[][..], |(_, t)| t.as_slice());
                        if rules[k as usize].typed.holds(lang, file, typed) {
                            let rule = listed[k as usize];
                            found.push(Found {
                                rule,
                                at: arg.clone(),
                                into: None,
                            });
                        }
                    }
                }
                MultiReached::Call { arg, into, rule } => {
                    let rule = listed[rule as usize];
                    found.push(Found {
                        rule,
                        at: arg,
                        into: Some(into),
                    });
                }
                MultiReached::Responds { f, value, mask } => {
                    for k in rules_in(mask) {
                        if rules[k as usize]
                            .responds
                            .as_ref()
                            .is_some_and(|r| r.holds(&f, &value))
                        {
                            let rule = listed[k as usize];
                            found.push(Found {
                                rule,
                                at: value.clone(),
                                into: None,
                            });
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
                MultiReached::Return(..) => {}
            });
            stored
        },
    );
}
