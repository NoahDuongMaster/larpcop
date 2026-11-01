//! Branches decided before the program runs. A branch whose condition has a
//! known value either never runs (its events are dropped) or always runs
//! (what it assigns is no longer conditional).

use super::constant::{Env, Value, eval};
use super::kotlin::Part;
use crate::rules::complexity::is_function;
use ast_grep_core::{Doc, Node};
use std::collections::{HashMap, HashSet};
use std::ops::Range;

type Key = (usize, usize);

fn key<D: Doc>(n: &Node<D>) -> Key {
    let r = n.range();
    (r.start, r.end)
}

#[derive(Default)]
pub(super) struct Branches {
    /// Code that never runs.
    dead: Vec<Range<usize>>,
    /// Conditional constructs whose live part always runs.
    always: HashSet<Key>,
    /// Ternaries with a known side: whether it is the first (`a` in `c ? a : b`).
    chosen: HashMap<Key, bool>,
}

impl Branches {
    pub fn of<D: Doc>(scope: &Node<D>) -> Self {
        let mut out = Branches::default();
        const DECIDABLE: [&str; 6] = [
            "if_statement",
            "conditional_expression",
            "ternary_expression",
            "match_statement",
            "switch_expression",
            "switch_statement",
        ];
        if !scope.dfs().any(|n| DECIDABLE.contains(&n.kind().as_ref())) {
            return out;
        }
        let env = Env::new(scope);
        out.visit(scope, &env);
        out
    }

    pub fn is_dead<D: Doc>(&self, n: &Node<D>) -> bool {
        let r = n.range();
        self.dead
            .iter()
            .any(|d| d.start <= r.start && r.end <= d.end)
    }

    pub fn dead(&self) -> &[Range<usize>] {
        &self.dead
    }

    pub fn always<D: Doc>(&self, n: &Node<D>) -> bool {
        self.always.contains(&key(n))
    }

    /// The side of a decided ternary that is taken, through parentheses.
    pub fn live<'a, D: Doc>(&self, n: Node<'a, D>) -> Node<'a, D> {
        let mut n = n;
        loop {
            let next = if n.kind() == "parenthesized_expression" {
                n.children().find(|c| c.is_named())
            } else if let Some(first) = self.chosen.get(&key(&n)) {
                sides(&n).map(|(_, a, b)| if *first { a } else { b })
            } else {
                None
            };
            match next {
                Some(inner) => n = inner,
                None => return n,
            }
        }
    }

    fn visit<D: Doc>(&mut self, n: &Node<D>, env: &Env<D>) {
        for c in n.children() {
            if is_function(&c) || self.is_dead(&c) {
                continue;
            }
            match c.kind().as_ref() {
                "if_statement" => self.if_chain(&c, env),
                "conditional_expression" | "ternary_expression" => {
                    if let Some((cond, a, b)) = sides(&c)
                        && let Some(Value::Bool(v)) = eval(&cond, env, 0)
                    {
                        self.dead.push(if v { b.range() } else { a.range() });
                        self.always.insert(key(&c));
                        self.chosen.insert(key(&c), v);
                    }
                }
                "match_statement" => self.match_cases(&c, env),
                "switch_expression" | "switch_statement" => self.switch_groups(&c, env),
                _ => {}
            }
            self.visit(&c, env);
        }
    }

    /// `if … elif … else …` (Python), `if … else …` (Java, JS, C#, Go).
    fn if_chain<D: Doc>(&mut self, n: &Node<D>, env: &Env<D>) {
        let Some(cond) = n.part("condition") else {
            return;
        };
        let Some(Value::Bool(v)) = eval(&cond, env, 0) else {
            return;
        };
        self.always.insert(key(n));
        let Some(then) = n.part("consequence") else {
            return;
        };
        let rest: Vec<Node<D>> = n
            .children()
            .filter(|c| c.is_named() && c.range().start >= then.range().end)
            .collect();
        if v {
            self.dead.extend(rest.iter().map(|r| r.range()));
            return;
        }
        self.dead.push(then.range());
        // Python: the first `elif`/`else` now decides; Java's bare `else` statement always runs.
        let mut prior_false = true;
        for clause in rest {
            match clause.kind().as_ref() {
                "elif_clause" if prior_false => {
                    match clause.part("condition").and_then(|c| eval(&c, env, 0)) {
                        Some(Value::Bool(true)) => {
                            self.always.insert(key(&clause));
                            self.skip_after(n, &clause);
                            return;
                        }
                        Some(Value::Bool(false)) => self.dead.push(clause.range()),
                        _ => prior_false = false,
                    }
                }
                "else_clause" if prior_false => {
                    self.always.insert(key(&clause));
                }
                _ => {}
            }
        }
    }

    fn skip_after<D: Doc>(&mut self, n: &Node<D>, clause: &Node<D>) {
        let end = clause.range().end;
        self.dead.extend(
            n.children()
                .filter(|c| c.is_named() && c.range().start >= end)
                .map(|c| c.range()),
        );
    }

    /// Python `match` on a known value with literal cases.
    fn match_cases<D: Doc>(&mut self, n: &Node<D>, env: &Env<D>) {
        let Some(subject) = n.part("subject").and_then(|s| eval(&s, env, 0)) else {
            return;
        };
        let Some(body) = n.part("body") else { return };
        let clauses: Vec<Node<D>> = body
            .children()
            .filter(|c| c.kind() == "case_clause")
            .collect();
        if clauses.is_empty() {
            return;
        }
        let mut matches = Vec::new();
        for clause in &clauses {
            if clause.part("guard").is_some() {
                return;
            }
            let Some(pattern) = clause.children().find(|c| c.kind() == "case_pattern") else {
                return;
            };
            let alternatives: Vec<Node<D>> = match pattern.children().find(|c| c.is_named()) {
                Some(u) if u.kind() == "union_pattern" => {
                    u.children().filter(|c| c.is_named()).collect()
                }
                Some(single) => vec![single],
                None if pattern.text() == "_" => {
                    matches.push(true);
                    continue;
                }
                None => return,
            };
            let mut hit = false;
            for alt in alternatives {
                let Some(v) = eval(&alt, env, 0) else { return };
                hit |= v == subject;
            }
            matches.push(hit);
        }
        self.decide(n, &clauses, &matches, false);
    }

    /// Java `switch` on a known value: from the matching group (or
    /// `default`) up to the first group that breaks, falling through.
    fn switch_groups<D: Doc>(&mut self, n: &Node<D>, env: &Env<D>) {
        let Some(subject) = n.part("condition").and_then(|s| eval(&s, env, 0)) else {
            return;
        };
        let Some(body) = n.part("body") else { return };
        let groups: Vec<Node<D>> = body
            .children()
            .filter(|c| {
                matches!(
                    c.kind().as_ref(),
                    "switch_block_statement_group" | "switch_rule"
                )
            })
            .collect();
        if groups.is_empty() {
            return;
        }
        let mut matches = Vec::new();
        let mut default = None;
        for (i, g) in groups.iter().enumerate() {
            let mut hit = false;
            for label in g.children().filter(|c| c.kind() == "switch_label") {
                let values: Vec<Node<D>> = label.children().filter(|c| c.is_named()).collect();
                if values.is_empty() {
                    default = Some(i);
                }
                for v in values {
                    let Some(v) = eval(&v, env, 0) else { return };
                    hit |= v == subject;
                }
            }
            matches.push(hit);
        }
        if !matches.contains(&true)
            && let Some(d) = default
        {
            matches[d] = true;
        }
        self.decide(n, &groups, &matches, true);
    }

    /// Keeps the first matching arm (and, falling through, those after it
    /// up to one that breaks); the others never run.
    fn decide<D: Doc>(&mut self, n: &Node<D>, arms: &[Node<D>], matches: &[bool], falls: bool) {
        let first = matches.iter().position(|m| *m);
        self.always.insert(key(n));
        let mut running = false;
        for (i, arm) in arms.iter().enumerate() {
            if Some(i) == first {
                running = true;
                self.always.insert(key(arm));
            } else if !running || !falls {
                self.dead.push(arm.range());
                continue;
            }
            let last = arm.children().filter(|c| c.is_named()).last();
            let ends = arm.kind() == "switch_rule"
                || last.is_some_and(|l| {
                    matches!(
                        l.kind().as_ref(),
                        "break_statement"
                            | "return_statement"
                            | "throw_statement"
                            | "jump_expression"
                    )
                });
            if falls && ends {
                self.dead.extend(arms[i + 1..].iter().map(|a| a.range()));
                return;
            }
        }
    }
}

/// (condition, first side, second side) of a ternary: `c ? a : b` (fields)
/// or Python's `a if c else b` (in that order).
pub(super) fn sides<'a, D: Doc>(
    n: &Node<'a, D>,
) -> Option<(Node<'a, D>, Node<'a, D>, Node<'a, D>)> {
    // PHP names the first result `body`.
    if let (Some(c), Some(a), Some(b)) = (
        n.part("condition"),
        n.part("consequence").or_else(|| n.part("body")),
        n.part("alternative"),
    ) {
        return Some((c, a, b));
    }
    let parts: Vec<Node<D>> = n.children().filter(|c| c.is_named()).collect();
    match parts.as_slice() {
        [a, c, b] if n.kind() == "conditional_expression" => {
            Some((c.clone(), a.clone(), b.clone()))
        }
        _ => None,
    }
}
