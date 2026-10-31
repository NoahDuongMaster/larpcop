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

/// Adds `*.method` for every method name exactly one known class defines.
pub fn with_unique_methods(mut s: Summaries) -> Summaries {
    let mut seen: HashMap<String, Vec<String>> = HashMap::new();
    for key in s.keys() {
        if let Some((class, method)) = key.rsplit_once('.')
            && class.chars().next().is_some_and(char::is_uppercase)
        {
            seen.entry(method.to_string())
                .or_default()
                .push(key.clone());
        }
    }
    for (method, keys) in seen {
        if let [only] = keys.as_slice()
            && let Some(summary) = s.get(only).cloned()
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
            let round = Ctx {
                sources: ctx.sources.clone(),
                sanitizers: ctx.sanitizers.clone(),
                guards: ctx.guards.clone(),
                summaries: out.clone(),
                source_texts: ctx.source_texts.clone(),
                sourcing: Default::default(),
                bare_calls: ctx.bare_calls,
            };
            let params_only = round.clone_without_sources();
            for (name, f, params) in defs {
                let mut s = Summary::default();
                for (i, p) in params.iter().enumerate().filter(|(_, p)| !p.is_empty()) {
                    let start: HashSet<String> = [p.clone()].into();
                    params_only.run(f, start, hits, &|_| HashSet::new(), &mut |r| match r {
                        Reached::Sink(arg, typed) => {
                            if self.typed.holds(lang, file, &typed) {
                                s.sinks.push((i, self.into(name, &arg, &file.rel)));
                            }
                        }
                        Reached::Call(_, into) => s.sinks.push((i, format!("`{name}` → {into}"))),
                        Reached::Return => {
                            s.returns.insert(i);
                        }
                        Reached::Field(_) => {}
                    });
                }
                round.run(f, own(f), hits, &own, &mut |r| {
                    if let Reached::Return = r {
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
        }
    }
}
