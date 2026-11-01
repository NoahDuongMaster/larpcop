//! Which function a call calls: its name among the summaries, the class a
//! local was built as (`Base b = new Impl(); b.run(x)`), or the one method of
//! that name among the known classes (`*.run`).

use super::flow::Ctx;
use super::kotlin::Part;
use super::summary::{Summary, callee};
use crate::rules::complexity::is_function;
use ast_grep_core::{Doc, Node};
use std::collections::HashMap;

/// Per function: the classes its locals are built as.
pub(super) type Built = std::collections::HashMap<String, Option<String>>;

impl Ctx {
    /// What is known of the function a call calls: by its name, or for
    /// `obj.method(…)` on an object of unknown class, the one method of that
    /// name among the known classes (`*.method`).
    pub fn summary<D: Doc>(&self, call: &Node<D>) -> Option<&Summary> {
        self.summary_guessed(call).map(|(s, _)| s)
    }

    /// The summary, and whether it was found by method name alone.
    pub(super) fn summary_guessed<D: Doc>(&self, call: &Node<D>) -> Option<(&Summary, bool)> {
        // Most calls are of nothing summarized: tell by the called name
        // before building the whole callee.
        if let Some(last) = super::summary::called_name(call) {
            let known = self.summarized.get_or_init(|| {
                self.summaries
                    .keys()
                    .map(|k| k.rsplit('.').next().unwrap_or(k).to_string())
                    .collect()
            });
            if !known.contains(last.as_str()) {
                // `void (*fp)(char *) = sink; fp(data)`: the function it holds.
                let held = super::summary::callee(call)
                    .filter(|c| *c == last)
                    .and_then(|_| self.built_as(call, &format!("(*){last}")))?;
                return self.summaries.get(&held).map(|s| (s, false));
            }
        }
        let name = callee(call)?;
        if let Some(s) = self.pick(&name, call) {
            return Some((s, false));
        }
        let (receiver, method) = name.rsplit_once('.')?;
        // `Base b = new Impl(); b.run(x)`: the class the object was built as.
        if let Some(class) = self.built_as(call, receiver)
            && let Some(s) = self.pick(&format!("{class}.{method}"), call)
        {
            return Some((s, false));
        }
        // `Store s; s.save(x)`: every known implementation of its type.
        if let Some(object) = receiver_node(call)
            && let Some(ty) = super::declared::declared_type(&object)
            && let Some(s) = self.pick(
                &format!("{}.{method}", ty.split('<').next().unwrap_or(&ty).trim()),
                call,
            )
        {
            return Some((s, false));
        }
        self.pick(&format!("*.{method}"), call).map(|s| (s, true))
    }

    /// The summary under `key`; for `render(rows, escape)`, the one with
    /// `escape`'s calls clean (higher.rs).
    fn pick<D: Doc>(&self, key: &str, call: &Node<D>) -> Option<&Summary> {
        let s = self.summaries.get(key)?;
        Some(self.specialized(key, call).unwrap_or(s))
    }

    fn built_as<D: Doc>(&self, call: &Node<D>, name: &str) -> Option<String> {
        let f = call.ancestors().find(|a| is_function(a))?;
        let start = f.range().start;
        let known = self.built.borrow().get(&start).cloned();
        let built = known.unwrap_or_else(|| {
            let b = std::rc::Rc::new(constructions(&f));
            self.built.borrow_mut().insert(start, b.clone());
            b
        });
        built.get(name).cloned().flatten()
    }
}

/// The plain name a method is called on: `s` of `s.save(x)`.
fn receiver_node<'a, D: Doc>(call: &Node<'a, D>) -> Option<Node<'a, D>> {
    let object = call
        .part("object")
        .or_else(|| {
            call.part("function")
                .and_then(|f| f.part("object").or_else(|| f.part("expression")))
        })
        .or_else(|| call.part("receiver"))?;
    matches!(object.kind().as_ref(), "identifier" | "simple_identifier").then_some(object)
}

/// The classes the locals of function `f` are built as, by name
/// (`Base b = new Impl();` gives `b` → `Impl`); `None` for a name assigned
/// more than once or not with `new`. C function pointers too, as `(*)fp`.
fn constructions<D: Doc>(f: &Node<D>) -> HashMap<String, Option<String>> {
    let mut out: HashMap<String, Option<String>> = HashMap::new();
    for n in f.dfs() {
        if !matches!(
            n.kind().as_ref(),
            "variable_declarator" | "assignment_expression" | "init_declarator"
        ) {
            continue;
        }
        // C `void (*fp)(char *) = sink;`, `fp = sink;`: the function `fp`
        // holds, under `(*)fp`.
        if n.kind() != "variable_declarator"
            && let Some((left, right)) = super::flow::assignment(&n)
            && right.kind() == "identifier"
            && (n.kind() == "assignment_expression"
                || n.field("declarator")
                    .is_some_and(|d| d.dfs().any(|c| c.kind() == "function_declarator")))
        {
            out.entry(format!("(*){}", left.text()))
                .and_modify(|seen| *seen = None)
                .or_insert_with(|| Some(right.text().to_string()));
        }
        if n.kind() == "init_declarator" {
            continue;
        }
        // C#'s `T b = new Impl()` leaves the value without a field name.
        let Some((left, right)) = super::flow::assignment(&n) else {
            continue;
        };
        // PHP `new Input()` names the class in an unnamed child.
        let class = (right.kind() == "object_creation_expression")
            .then(|| {
                right.part("type").or_else(|| {
                    right
                        .children()
                        .find(|c| matches!(c.kind().as_ref(), "name" | "qualified_name"))
                })
            })
            .flatten()
            .and_then(|t| {
                let ty = t.text();
                Some(ty.split('<').next()?.rsplit('.').next()?.trim().to_string())
            });
        out.entry(left.text().to_string())
            .and_modify(|seen| *seen = None)
            .or_insert(class);
    }
    out
}
