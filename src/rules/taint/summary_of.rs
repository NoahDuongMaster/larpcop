//! The summary of one function: per parameter, the sinks it reaches, whether
//! it is returned, the objects it fills; the static fields and globals it
//! reads; whether it returns source data.

use super::TaintRule;
use super::events::Hits;
use super::flow::{Ctx, Reached};
use super::summary::Summary;
use crate::files::SourceFile;
use ast_grep_core::{Doc, Node};
use ast_grep_language::SupportLang;
use std::collections::HashSet;

impl TaintRule {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn summary_of<'a, D: Doc>(
        &self,
        round: &Ctx,
        params_only: &Ctx,
        name: &String,
        f: &Node<'a, D>,
        params: &[String],
        lang: SupportLang,
        file: &SourceFile,
        hits: &Hits<'a, D>,
    ) -> Summary {
        let own = |n: &Node<'a, D>| self.own_names(n);
        let mut s = Summary {
            method: super::defs::class_of(f).is_some(),
            supers: super::defs::supers_of(f),
            ..Summary::default()
        };
        for (i, p) in params.iter().enumerate().filter(|(_, p)| !p.is_empty()) {
            let start: HashSet<String> = [p.clone()].into();
            // Every sink of `p` under the same parameter's call, or not.
            let mut condition: Option<Option<super::lambdas::Condition>> = None;
            let mut under = |at: &Node<'a, D>| {
                let c = super::lambdas::condition_param(at, f, params);
                condition = Some(match condition {
                    None => c,
                    Some(prev) if prev == c => c,
                    Some(_) => None,
                });
            };
            params_only.run(f, start, hits, &|_| HashSet::new(), &mut |r| match r {
                Reached::Sink(arg, typed) => {
                    if self.typed.holds(lang, file, &typed) {
                        under(&arg);
                        s.sinks.push((i, self.into(name, &arg, &file.rel)));
                    }
                }
                Reached::Call(at, into) => {
                    under(&at);
                    s.sinks.push((i, format!("`{name}` → {into}")))
                }
                Reached::Return(_) => {
                    s.returns.insert(i);
                }
                Reached::Filled(object) => {
                    if let Some(j) = params.iter().position(|p| *p == object)
                        && j != i
                    {
                        s.fills.insert((i, j));
                    }
                }
                Reached::Field(_) | Reached::Responds(..) => {}
            });
            if let Some(Some(g)) = condition {
                s.conditions.insert(i, g);
            }
        }
        for key in super::statics::read(f) {
            let start: HashSet<String> = [key.clone()].into();
            params_only.run(f, start, hits, &|_| HashSet::new(), &mut |r| match r {
                Reached::Sink(arg, typed) if self.typed.holds(lang, file, &typed) => {
                    s.statics
                        .push((key.clone(), self.into(name, &arg, &file.rel)));
                }
                Reached::Call(_, into) => {
                    s.statics.push((key.clone(), format!("`{name}` → {into}")))
                }
                _ => {}
            });
        }
        s.statics.dedup_by(|a, b| a.0 == b.0);
        s.validates = super::validators::validated(f, params, &round.guards);
        round.run(f, own(f), hits, &own, &mut |r| {
            if let Reached::Return(_) = r {
                s.returns_source = true;
            }
        });
        s.sinks.sort();
        s.sinks.dedup_by_key(|(i, _)| *i);
        s
    }

    fn into<D: Doc>(&self, name: &str, arg: &Node<D>, rel: &str) -> String {
        let sink = arg
            .ancestors()
            .find(|a| super::flow::CALLS.contains(&a.kind().as_ref()))
            .map_or_else(|| arg.text().to_string(), |c| c.text().to_string());
        let short: String = sink
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .chars()
            .take(60)
            .collect();
        format!(
            "`{name}` → `{short}` at {rel}:{}",
            arg.start_pos().line() + 1
        )
    }
}
