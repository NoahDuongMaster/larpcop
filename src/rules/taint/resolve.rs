//! Which function a call calls: its name among the summaries, the class a
//! local was built as (`Base b = new Impl(); b.run(x)`), or the one method of
//! that name among the known classes (`*.run`).

use super::flow::Ctx;
use super::summary::{Summary, callee};
use crate::rules::complexity::is_function;
use ast_grep_core::{Doc, Node};

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
                return None;
            }
        }
        let name = callee(call)?;
        if let Some(s) = self.summaries.get(&name) {
            return Some((s, false));
        }
        let (receiver, method) = name.rsplit_once('.')?;
        // `Base b = new Impl(); b.run(x)`: the class the object was built as.
        if let Some(class) = self.built_as(call, receiver)
            && let Some(s) = self.summaries.get(&format!("{class}.{method}"))
        {
            return Some((s, false));
        }
        // `Store s; s.save(x)`: every known implementation of its type.
        if let Some(object) = receiver_node(call)
            && let Some(ty) = super::declared::declared_type(&object)
            && let Some(s) = self.summaries.get(&format!(
                "{}.{method}",
                ty.split('<').next().unwrap_or(&ty).trim()
            ))
        {
            return Some((s, false));
        }
        self.summaries
            .get(&format!("*.{method}"))
            .map(|s| (s, true))
    }

    fn built_as<D: Doc>(&self, call: &Node<D>, name: &str) -> Option<String> {
        let f = call.ancestors().find(|a| is_function(a))?;
        let start = f.range().start;
        let known = self.built.borrow().get(&start).cloned();
        let built = known.unwrap_or_else(|| {
            let b = std::rc::Rc::new(super::declared::constructions(&f));
            self.built.borrow_mut().insert(start, b.clone());
            b
        });
        built.get(name).cloned().flatten()
    }
}

/// The plain name a method is called on: `s` of `s.save(x)`.
fn receiver_node<'a, D: Doc>(call: &Node<'a, D>) -> Option<Node<'a, D>> {
    use super::kotlin::Part;
    let object = call
        .part("object")
        .or_else(|| {
            call.part("function")
                .and_then(|f| f.part("object").or_else(|| f.part("expression")))
        })
        .or_else(|| call.part("receiver"))?;
    matches!(object.kind().as_ref(), "identifier" | "simple_identifier").then_some(object)
}
