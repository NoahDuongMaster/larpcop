//! Function summaries, so taint follows calls: which parameters reach a sink
//! inside the function, which ones its return value carries, and whether it
//! returns source data itself.

use super::TaintRule;
use super::events::Hits;
use super::flow::{Ctx, Reached};
use crate::files::SourceFile;
use ast_grep_core::{Doc, Node};
use ast_grep_language::SupportLang;
use std::collections::{BTreeSet, HashMap, HashSet};

pub use super::defs::{functions, param_names};

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Summary {
    /// (parameter index, where it ends up: "`run` → db.query(sql) at src/db.ts:4").
    pub sinks: Vec<(usize, String)>,
    pub returns: BTreeSet<usize>,
    pub returns_source: bool,
    /// Parameters it validates: it fails (null, false) unless they pass a guard.
    pub validates: BTreeSet<usize>,
    /// Defined in a class (a method), whatever the class is called.
    pub method: bool,
    /// Parameter → the function-typed parameter whose call guards every
    /// sink it reaches (`if (cond.get()) read(name)`).
    pub conditions: std::collections::BTreeMap<usize, super::lambdas::Condition>,
}

/// Callee as written (`f`, `db.run`, `utils.clean`) → its summary.
pub type Summaries = HashMap<String, Summary>;

/// Rounds of re-summarizing, so a function calling another one that sinks a
/// parameter sinks it too (call chains up to this depth).
const ROUNDS: usize = 3;

/// Callee of a call, whitespace removed: `f`, `mod.f`, `a.b.f`.
pub fn callee<D: Doc>(call: &Node<D>) -> Option<String> {
    let squeeze = |n: Node<D>| -> String { n.text().split_whitespace().collect() };
    let text = match call.field("function") {
        Some(f) => squeeze(f),
        // Java `obj.name(…)` / `new Type(…)`, PHP `$obj->name(…)`, Ruby `obj.name …`
        None => {
            let name = call
                .field("name")
                .or_else(|| call.field("method"))
                .or_else(|| call.field("type"))?;
            let object = call
                .field("object")
                .or_else(|| call.field("receiver"))
                .or_else(|| call.field("scope"));
            match object {
                Some(o) => format!("{}.{}", squeeze(o), squeeze(name)),
                None => squeeze(name),
            }
        }
    };
    let plain = text
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '.' || c == '$');
    if plain {
        return Some(text);
    }
    constructed(call)
}

/// The name a call calls, without its receiver: `run` in `a.b.run(…)`,
/// `Helper` in `new Helper<T>(…)`; `None` when it is not a plain name.
pub fn called_name<D: Doc>(call: &Node<D>) -> Option<String> {
    let target = match call.field("function") {
        Some(f) => ["property", "attribute", "field", "name"]
            .iter()
            .find_map(|k| f.field(k))
            .unwrap_or(f),
        None => call
            .field("name")
            .or_else(|| call.field("method"))
            .or_else(|| call.field("type"))?,
    };
    let text = target.text();
    let name = text.split('<').next()?.trim();
    name.chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '$')
        .then(|| name.to_string())
}

/// `new Helper().run(…)`, `(new Helper()).run(…)`: `Helper.run`.
fn constructed<D: Doc>(call: &Node<D>) -> Option<String> {
    let member = call.field("function");
    let member = member.as_ref().unwrap_or(call);
    let mut object = member
        .field("expression")
        .or_else(|| member.field("object"))?;
    while object.kind() == "parenthesized_expression" {
        let inner = object.children().find(|c| c.is_named())?;
        object = inner;
    }
    if !matches!(
        object.kind().as_ref(),
        "object_creation_expression" | "new_expression"
    ) {
        return None;
    }
    let class = object
        .field("type")
        .or_else(|| object.field("constructor"))?;
    let method = member.field("name").or_else(|| member.field("property"))?;
    let class = class.text();
    Some(format!(
        "{}.{}",
        class.split('<').next()?.trim(),
        method.text()
    ))
}

/// Positional arguments of a call (keyword arguments end the list).
pub fn args<'a, D: Doc>(call: &Node<'a, D>) -> Vec<Node<'a, D>> {
    let Some(list) = call.field("arguments") else {
        return Vec::new();
    };
    list.children()
        .filter(|c| c.is_named() && c.kind() != "comment")
        .take_while(|c| c.kind() != "keyword_argument")
        .collect()
}

/// Adds `*.method` for every method name the known classes define alike
/// (one class, or several that behave the same: the same method seen as
/// `Class.m` and `module.Class.m`).
pub fn with_unique_methods(mut s: Summaries) -> Summaries {
    type Behaviour = (Vec<usize>, BTreeSet<usize>, bool, BTreeSet<usize>);
    let mut seen: HashMap<String, (HashSet<Behaviour>, String)> = HashMap::new();
    for (key, summary) in s.iter().filter(|(_, v)| v.method) {
        if let Some((_, method)) = key.rsplit_once('.') {
            let behaviour = (
                summary.sinks.iter().map(|(i, _)| *i).collect(),
                summary.returns.clone(),
                summary.returns_source,
                summary.validates.clone(),
            );
            let entry = seen.entry(method.to_string()).or_default();
            entry.0.insert(behaviour);
            entry.1 = key.clone();
        }
    }
    for (method, (behaviours, key)) in seen {
        if behaviours.len() == 1
            && let Some(summary) = s.get(&key).cloned()
        {
            s.insert(format!("*.{method}"), summary);
        }
    }
    s
}

impl TaintRule {
    /// Summaries of the named functions in `root`, given what is known of
    /// functions defined elsewhere (`known`, by callee name).
    pub(super) fn summarize<'a, D: Doc>(
        &self,
        index: &super::scan::FileIndex<'a, D>,
        lang: SupportLang,
        file: &SourceFile,
        ctx: &Ctx,
        hits: &Hits<'a, D>,
        known: &Summaries,
    ) -> Summaries {
        let defs = index.functions();
        let own = |n: &Node<'a, D>| self.own_names(n);
        let mut out = known.clone();
        for _ in 0..ROUNDS {
            let before = out.clone();
            let mut round = Ctx {
                sources: ctx.sources.clone(),
                sanitizers: ctx.sanitizers.clone(),
                guards: ctx.guards.clone(),
                summaries: out.clone(),
                source_texts: ctx.source_texts.clone(),
                sourcing: Default::default(),
                bare_calls: ctx.bare_calls,
                safe_prefix: ctx.safe_prefix.clone(),
                summarized: Default::default(),
            };
            let validating = super::validators::calls(index, &round);
            round.guards.extend(validating);
            let params_only = round.clone_without_sources();
            // An interface's or abstract method says nothing of what runs:
            // leaving it out lets `*.run` stand for the one implementation.
            for (name, f, params) in defs.iter().filter(|(_, f, _)| !super::defs::bodiless(f)) {
                let mut s = Summary {
                    method: super::defs::class_of(f).is_some(),
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
                        Reached::Field(_) | Reached::Responds(..) => {}
                    });
                    if let Some(Some(g)) = condition {
                        s.conditions.insert(i, g);
                    }
                }
                s.validates = super::validators::validated(f, params, &round.guards);
                round.run(f, own(f), hits, &own, &mut |r| {
                    if let Reached::Return(_) = r {
                        s.returns_source = true;
                    }
                });
                s.sinks.sort();
                s.sinks.dedup_by_key(|(i, _)| *i);
                out.insert(name.clone(), s);
            }
            // Nothing new reached this round: later rounds would repeat it.
            if out == before {
                break;
            }
        }
        out
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

impl Ctx {
    fn clone_without_sources(&self) -> Ctx {
        Ctx {
            sources: Vec::new(),
            sanitizers: self.sanitizers.clone(),
            guards: self.guards.clone(),
            summaries: self.summaries.clone(),
            source_texts: Vec::new(),
            sourcing: Default::default(),
            bare_calls: self.bare_calls,
            safe_prefix: self.safe_prefix.clone(),
            summarized: Default::default(),
        }
    }
}
