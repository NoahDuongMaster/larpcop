//! The writes of a scope's local names: which expression a name holds at a
//! point, when its last write before it is unconditional.

use super::constant::{Value, eval};
use crate::rules::complexity::is_function;
use ast_grep_core::{Doc, Node};
use std::collections::HashMap;
use std::ops::Range;

/// One write of a local name.
struct Write<'a, D: Doc> {
    /// Where it takes effect (its end).
    at: usize,
    /// The value assigned; `None` for `+=`, `++`, loop variables.
    value: Option<Node<'a, D>>,
    /// Inside a branch, loop or `try` of the scope: it may not run.
    maybe: bool,
    /// The loops it is in (a later iteration sees it before earlier code).
    loops: Vec<Range<usize>>,
}

/// The writes of a scope's local names, nested functions left out.
pub(crate) struct Env<'a, D: Doc> {
    writes: HashMap<String, Vec<Write<'a, D>>>,
}

const LOOP_KINDS: [&str; 8] = [
    "for_statement",
    "for_in_statement",
    "enhanced_for_statement",
    "while_statement",
    "do_statement",
    "for_expression",
    "while_expression",
    "loop_expression",
];

impl<'a, D: Doc> Env<'a, D> {
    pub fn new(scope: &Node<'a, D>) -> Self {
        let mut env = Env {
            writes: HashMap::new(),
        };
        env.collect(scope, false, &mut Vec::new());
        env
    }

    fn collect(&mut self, n: &Node<'a, D>, maybe: bool, loops: &mut Vec<Range<usize>>) {
        for c in n.children() {
            if is_function(&c) {
                continue;
            }
            let kind = c.kind();
            if let Some((left, right)) = super::flow::assignment(&c)
                && matches!(left.kind().as_ref(), "identifier" | "simple_identifier")
            {
                let value = Some(right).filter(|v| {
                    matches!(
                        kind.as_ref(),
                        "variable_declarator"
                            | "assignment"
                            | "assignment_expression"
                            | "property_declaration"
                    ) && !super::paths::compound(&c, &left, v)
                });
                let looping = super::flow::LOOPS.contains(&kind.as_ref());
                self.push(&left.text(), c.range().end, value, maybe || looping, loops);
            } else if (kind == "update_expression" || kind == "postfix_unary_expression")
                && let Some(name) = c.children().find(|x| x.kind() == "identifier")
            {
                self.push(&name.text(), c.range().end, None, true, loops);
            }
            let is_loop = LOOP_KINDS.contains(&kind.as_ref());
            if is_loop {
                loops.push(c.range());
            }
            let inner = maybe || is_loop || super::paths::CONDITIONAL.contains(&kind.as_ref());
            self.collect(&c, inner, loops);
            if is_loop {
                loops.pop();
            }
        }
    }

    fn push(
        &mut self,
        name: &str,
        at: usize,
        value: Option<Node<'a, D>>,
        maybe: bool,
        loops: &[Range<usize>],
    ) {
        self.writes
            .entry(name.to_string())
            .or_default()
            .push(Write {
                at,
                value,
                maybe,
                loops: loops.to_vec(),
            });
    }

    /// The value `name` holds at `at`, when it is known.
    pub(super) fn value(&self, name: &str, at: usize, depth: usize) -> Option<Value> {
        eval(&self.assigned(name, at)?, self, depth + 1)
    }

    /// The expression `name` was last unconditionally assigned before `at`.
    fn assigned(&self, name: &str, at: usize) -> Option<Node<'a, D>> {
        let writes = self.writes.get(name)?;
        // A write in a loop around `at` may come back before it.
        if writes
            .iter()
            .any(|w| w.loops.iter().any(|l| l.contains(&at)))
        {
            return None;
        }
        let last = writes.iter().filter(|w| w.at <= at).max_by_key(|w| w.at)?;
        if last.maybe {
            return None;
        }
        last.value.clone()
    }

    /// The expressions `name` may hold at `at`: its last write before it when
    /// that one always runs, else every write that can reach `at` (earlier
    /// ones, and any in a loop around it).
    pub(crate) fn candidates(&self, name: &str, at: usize) -> Vec<Node<'a, D>> {
        let Some(writes) = self.writes.get(name) else {
            return Vec::new();
        };
        let in_loop = |w: &Write<'a, D>| w.loops.iter().any(|l| l.contains(&at));
        let reaching: Vec<&Write<'a, D>> =
            writes.iter().filter(|w| w.at <= at || in_loop(w)).collect();
        let last = reaching.iter().filter(|w| w.at <= at).max_by_key(|w| w.at);
        match last {
            Some(w) if !w.maybe && !reaching.iter().any(|w| in_loop(w)) => {
                w.value.iter().cloned().collect()
            }
            _ => reaching.iter().filter_map(|w| w.value.clone()).collect(),
        }
    }

    /// Is `name` written in the scope at all (a local, not a field)?
    pub(crate) fn writes(&self, name: &str) -> bool {
        self.writes.contains_key(name)
    }
}
