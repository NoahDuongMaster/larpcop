//! Function summaries, so taint follows calls: which parameters reach a sink
//! inside the function, which ones its return value carries, and whether it
//! returns source data itself.

use super::TaintRule;
use super::events::Hits;
use super::flow::Ctx;
use super::kotlin::Part;
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
    /// (parameter, parameter it is stored in): `fill(o, x)` calling
    /// `o.setNote(x)` is (1, 0).
    pub fills: BTreeSet<(usize, usize)>,
    /// The direct supertypes of its class (`class DbStore implements Store`).
    pub supers: Vec<String>,
    /// (static field of another class it reads, as `Cls[field]`; where it
    /// ends up), see statics.rs.
    pub statics: Vec<(String, String)>,
}

/// Callee as written (`f`, `db.run`, `utils.clean`) → its summary.
pub type Summaries = HashMap<String, Summary>;

/// Rounds of re-summarizing, so a function calling another one that sinks a
/// parameter sinks it too (call chains up to this depth).
const ROUNDS: usize = 3;

/// Callee of a call, whitespace removed: `f`, `mod.f`, `a.b.f`.
pub fn callee<D: Doc>(call: &Node<D>) -> Option<String> {
    let squeeze = |n: Node<D>| -> String { n.text().split_whitespace().collect() };
    let text = match call.part("function") {
        Some(f) => squeeze(f),
        // Java `obj.name(…)` / `new Type(…)`, PHP `$obj->name(…)`, Ruby `obj.name …`
        None => {
            let name = call
                .part("name")
                .or_else(|| call.part("method"))
                .or_else(|| call.part("type"))?;
            let object = call
                .part("object")
                .or_else(|| call.part("receiver"))
                .or_else(|| call.part("scope"));
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
    let target = match call.part("function") {
        Some(f) => ["property", "attribute", "field", "name"]
            .iter()
            .find_map(|k| f.part(k))
            .unwrap_or(f),
        None => call
            .part("name")
            .or_else(|| call.part("method"))
            .or_else(|| call.part("type"))?,
    };
    let text = target.text();
    let name = text.split('<').next()?.trim();
    name.chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '$')
        .then(|| name.to_string())
}

/// `new Helper().run(…)`, `(new Helper()).run(…)`: `Helper.run`.
fn constructed<D: Doc>(call: &Node<D>) -> Option<String> {
    let member = call.part("function");
    let member = member.as_ref().unwrap_or(call);
    let mut object = member
        .part("expression")
        .or_else(|| member.part("object"))?;
    while object.kind() == "parenthesized_expression" {
        let inner = object.children().find(|c| c.is_named())?;
        object = inner;
    }
    // Kotlin builds without `new`: `UserRepo().byName(…)`.
    let kotlin = (object.kind() == "call_expression")
        .then(|| object.part("function"))
        .flatten()
        .filter(|f| f.kind() == "simple_identifier" && f.text().starts_with(char::is_uppercase));
    if kotlin.is_none()
        && !matches!(
            object.kind().as_ref(),
            "object_creation_expression" | "new_expression"
        )
    {
        return None;
    }
    let class = kotlin
        .or_else(|| object.part("type"))
        .or_else(|| object.part("constructor"))?;
    let method = member.part("name").or_else(|| member.part("property"))?;
    let class = class.text();
    Some(format!(
        "{}.{}",
        class.split('<').next()?.trim(),
        method.text()
    ))
}

/// Positional arguments of a call (keyword arguments end the list).
pub fn args<'a, D: Doc>(call: &Node<'a, D>) -> Vec<Node<'a, D>> {
    let Some(list) = call.part("arguments") else {
        return Vec::new();
    };
    list.children()
        .filter(|c| c.is_named() && c.kind() != "comment")
        .take_while(|c| c.kind() != "keyword_argument")
        .collect()
}

pub use super::unique::with_unique_methods;

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
        let mut out = known.clone();
        // Per class: the fields its methods store source data in.
        let mut fields: HashMap<(usize, usize), HashSet<String>> = HashMap::new();
        for _ in 0..ROUNDS {
            let before = out.clone();
            let fields_before = fields.clone();
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
                built: Default::default(),
                cleaners: ctx.cleaners.clone(),
                writes: ctx.writes.clone(),
                writes_clean: ctx.writes_clean,
                numbers: ctx.numbers,
            };
            let validating = super::validators::calls(index, &round);
            round.guards.extend(validating);
            let params_only = round.clone_without_sources();
            // An interface's or abstract method says nothing of what runs:
            // leaving it out lets `*.run` stand for the one implementation.
            for (name, f, params) in defs.iter().filter(|(_, f, _)| !super::defs::bodiless(f)) {
                let class = super::check::class_of(f);
                let mine = class
                    .and_then(|c| fields_before.get(&c))
                    .cloned()
                    .unwrap_or_default();
                let (s, stored) = self.summary_of(
                    &round,
                    &params_only,
                    name,
                    f,
                    params,
                    lang,
                    file,
                    hits,
                    &mine,
                );
                if let Some(c) = class {
                    fields.entry(c).or_default().extend(stored);
                }
                // `f($x, $vuln = False)`: one summary per value of the flag.
                for (k, default) in super::flags::flags(f, params) {
                    for value in [true, false] {
                        let (v, _) = hits.seeded(f, &params[k], value, || {
                            self.summary_of(
                                &round,
                                &params_only,
                                name,
                                f,
                                params,
                                lang,
                                file,
                                hits,
                                &mine,
                            )
                        });
                        if v != s {
                            if default == Some(value) {
                                out.insert(super::flags::key(name, k, None), v.clone());
                            }
                            out.insert(super::flags::key(name, k, Some(value)), v);
                        }
                    }
                }
                out.insert(name.clone(), s);
                // `render(rows, f)` running `f.apply(row)`: with a cleaning `f`.
                for (k, p) in params.iter().enumerate().filter(|(_, p)| !p.is_empty()) {
                    let runs = super::higher::applications(f, p);
                    if runs.is_empty() {
                        continue;
                    }
                    let (r, po) = (
                        round.with_sanitizers(&runs),
                        params_only.with_sanitizers(&runs),
                    );
                    let (s, _) = self.summary_of(&r, &po, name, f, params, lang, file, hits, &mine);
                    out.insert(super::higher::key(name, k), s);
                }
            }
            // Nothing new reached this round: later rounds would repeat it.
            if out == before && fields == fields_before {
                break;
            }
        }
        out
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
            built: Default::default(),
            cleaners: self.cleaners.clone(),
            writes: std::sync::Arc::new(self.writes.copies_only()),
            writes_clean: self.writes_clean,
            numbers: self.numbers,
        }
    }
}
