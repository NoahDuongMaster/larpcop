//! Function summaries, so taint follows calls: which parameters reach a sink
//! inside the function, which ones its return value carries, and whether it
//! returns source data itself.

use super::TaintRule;
use super::events::Hits;
use super::flow::{Ctx, Reached};
use crate::files::SourceFile;
use crate::rules::complexity::is_function;
use ast_grep_core::{Doc, Node};
use ast_grep_language::SupportLang;
use std::collections::{BTreeSet, HashMap, HashSet};

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
    let f = call.field("function")?;
    let text: String = f.text().split_whitespace().collect();
    let plain = text
        .chars()
        .all(|c| c.is_alphanumeric() || c == '_' || c == '.' || c == '$');
    plain.then_some(text)
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

/// Named functions defined in `root`: (name, function node, parameter names).
pub fn functions<'a, D: Doc>(root: &Node<'a, D>) -> Vec<(String, Node<'a, D>, Vec<String>)> {
    let mut out: Vec<(String, Node<'a, D>, Vec<String>)> = named(root).collect();
    // Methods are also known as `Class.method`, the way callers outside name them.
    let qualified: Vec<_> = out
        .iter()
        .filter_map(|(name, f, p)| Some((format!("{}.{name}", class_of(f)?), f.clone(), p.clone())))
        .collect();
    out.extend(qualified);
    out
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

/// The class a method is defined in.
fn class_of<D: Doc>(f: &Node<D>) -> Option<String> {
    let class = f.ancestors().take_while(|a| !is_function(a)).find(|a| {
        matches!(
            a.kind().as_ref(),
            "class_definition" | "class_declaration" | "class"
        )
    })?;
    Some(class.field("name")?.text().to_string())
}

fn named<'a, D: Doc>(
    root: &Node<'a, D>,
) -> impl Iterator<Item = (String, Node<'a, D>, Vec<String>)> {
    root.dfs().filter(|n| is_function(n)).filter_map(|f| {
        let name = f.field("name").map(|n| n.text().to_string()).or_else(|| {
            // `const f = (…) => …`, `f := func(…)`
            let parent = f.parent()?;
            (parent.kind() == "variable_declarator")
                .then(|| parent.field("name"))
                .flatten()
                .map(|n| n.text().to_string())
        })?;
        let default = f.parent().is_some_and(|p| {
            p.kind() == "export_statement" && p.text().starts_with("export default")
        });
        let name = if default { "default".to_string() } else { name };
        Some((name, f.clone(), params(&f)))
    })
}

/// Parameter names of a function, as a set.
pub fn param_names<D: Doc>(f: &Node<D>) -> HashSet<String> {
    params(f).into_iter().filter(|p| !p.is_empty()).collect()
}

fn params<D: Doc>(f: &Node<D>) -> Vec<String> {
    if let Some(one) = f.field("parameter") {
        return vec![one.text().to_string()]; // `x => …`
    }
    let Some(list) = f.field("parameters") else {
        return Vec::new();
    };
    // Python's `self` / `cls` are not among the call's arguments.
    let receiver = |p: &Node<D>| matches!(p.text().as_ref(), "self" | "cls");
    list.children()
        .filter(|c| !(f.kind() == "function_definition" && receiver(c)))
        .filter(|c| c.is_named() && c.kind() != "comment")
        .map(|p| {
            if p.kind() == "identifier" {
                return p.text().to_string();
            }
            ["pattern", "name", "left"]
                .iter()
                .find_map(|k| p.field(k))
                .or_else(|| p.dfs().find(|n| n.kind() == "identifier"))
                .map(|n| n.text().to_string())
                .unwrap_or_default()
        })
        .collect()
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
        }
    }
}
