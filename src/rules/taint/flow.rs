//! The flow walk shared by the check and by function summaries: assignments
//! taint or clean names in source order; sinks, calls and returns are judged
//! with the state at that point.

use super::NAMES;
use super::events::Hits;
use super::fields::is_field;
use super::kotlin::Part;
use super::summary::{Summaries, args};
use crate::rules::complexity::is_function;
use ast_grep_core::{Doc, Node};
use std::collections::HashSet;
use std::ops::Range;

/// Targets (left) and value (right) of the assignment kinds we follow.
pub(super) const ASSIGNMENTS: [(&str, &str, &str); 16] = [
    ("variable_declarator", "name", "value"),
    // C/C++ `char *p = …`, `char data[100] = …`.
    ("init_declarator", "declarator", "value"),
    ("property_declaration", "name", "value"),
    ("let_declaration", "pattern", "value"),
    ("var_spec", "name", "value"),
    ("assignment_expression", "left", "right"),
    ("augmented_assignment_expression", "left", "right"),
    ("assignment", "left", "right"),
    ("augmented_assignment", "left", "right"),
    ("short_var_declaration", "left", "right"),
    ("assignment_statement", "left", "right"),
    ("operator_assignment", "left", "right"),
    // Loops bind each element of the collection: `for (Cookie c : cookies)`,
    // `for (const x of xs)`, `for x in xs:`, `for _, x := range xs`.
    ("enhanced_for_statement", "name", "value"),
    ("for_in_statement", "left", "right"),
    ("for_statement", "left", "right"),
    ("range_clause", "left", "right"),
];

/// The target and value of an assignment (any kind in `ASSIGNMENTS`). C#'s
/// `var x = …` leaves the value without a field name: the last other child.
pub(crate) fn assignment<'a, D: Doc>(n: &Node<'a, D>) -> Option<(Node<'a, D>, Node<'a, D>)> {
    let kind = n.kind();
    let (_, l, r) = ASSIGNMENTS.iter().find(|(k, ..)| kind == *k)?;
    let mut left = n.part(l)?;
    // C declarators wrap the name: `*p`, `data[100]`.
    if kind == "init_declarator" {
        let name = left.dfs().find(|c| c.kind() == "identifier");
        left = name?;
    }
    let right = n.part(r).or_else(|| {
        n.children()
            .filter(|c| c.is_named() && c.range() != left.range())
            .last()
    })?;
    Some((left, right))
}

/// Loop kinds among `ASSIGNMENTS`: they bind before the body, not at the end.
pub(super) const LOOPS: [&str; 4] = [
    "enhanced_for_statement",
    "for_in_statement",
    "for_statement",
    "range_clause",
];

/// Call kinds: JS/TS/Go/Rust, Python/Ruby, Java (`m()`, `new T()`), C#, PHP.
pub(super) const CALLS: [&str; 8] = [
    "call_expression",
    "call",
    "method_invocation",
    "object_creation_expression",
    "invocation_expression",
    "function_call_expression",
    "member_call_expression",
    "scoped_call_expression",
];

pub(super) enum Reached<'a, D: Doc> {
    /// Tainted data at a sink argument.
    Sink(Node<'a, D>, Vec<(usize, Node<'a, D>)>),
    /// Tainted argument into a function that sinks that parameter; where it ends up.
    Call(Node<'a, D>, String),
    /// A tainted value is returned.
    Return(Node<'a, D>),
    /// A function nested in the walked scope returns a tainted value.
    Responds(Node<'a, D>, Node<'a, D>),
    /// A tainted value is stored in a field of the object (`this.x`, `self.x`),
    /// which the other methods of its class read.
    Field(Node<'a, D>),
    /// A call stored a tainted value in the object of this name
    /// (`o.setNote(x)`, `list.add(x)`).
    Filled(String),
}

/// What a walk of one scope found, before its nested functions are walked.
pub(super) enum Seen<'a, D: Doc> {
    Reached(Reached<'a, D>),
    /// A nested function (callback, closure) and the tainted names it captures.
    Nested(Node<'a, D>, HashSet<String>),
}

pub(super) struct Ctx {
    pub sources: Vec<Range<usize>>,
    pub sanitizers: Vec<Range<usize>>,
    pub guards: Vec<super::guards::Check>,
    pub summaries: Summaries,
    pub source_texts: Vec<String>,
    /// Does any known function return source data? (computed on first use)
    pub sourcing: std::cell::OnceCell<bool>,
    /// Ruby: a bare name may call a method (`custom_fields`).
    pub bare_calls: bool,
    /// The rule's `safe_prefix`: a name that starts safely stays clean through `+=`.
    pub safe_prefix: Option<regex::Regex>,
    /// Last segments of the summaries' names (computed on first use).
    pub summarized: std::cell::OnceCell<HashSet<String>>,
    /// Per function (by start): the classes its locals are built as.
    pub built:
        std::cell::RefCell<std::collections::HashMap<usize, std::rc::Rc<super::resolve::Built>>>,
    /// The rule's sanitizers by name, for functions passed by reference.
    pub cleaners: std::sync::Arc<super::mapping::Cleaners>,
    /// Calls writing into an argument (`fgets(buf, …)`, `strcpy(dst, src)`).
    pub writes: std::sync::Arc<super::outputs::Writes>,
    /// Stream writes do not carry taint (deserialization rules).
    pub writes_clean: bool,
}

fn within(r: &Range<usize>, outer: &Range<usize>) -> bool {
    outer.start <= r.start && r.end <= outer.end
}

impl Ctx {
    fn any_sourcing(&self) -> bool {
        *self
            .sourcing
            .get_or_init(|| self.summaries.values().any(|s| s.returns_source))
    }

    /// Does `node` carry source data (not passed through a sanitizer)?
    pub fn tainted<D: Doc>(&self, node: &Node<D>, names: &HashSet<String>) -> bool {
        // A function value is code, not data; what it captures is followed when
        // its body is walked.
        if is_function(node) {
            return false;
        }
        let r = node.range();
        if self.sanitizers.iter().any(|s| within(&r, s)) {
            return false;
        }
        if self.sources.iter().any(|s| within(&r, s)) {
            return true;
        }
        let text = node.text();
        // `m['k']`, `m.get("k")`: that entry, or the whole map.
        let holds_source = self
            .sources
            .iter()
            .any(|s| s.start < r.end && r.start < s.end);
        let entries = names.iter().any(|n| n.ends_with(']'));
        if entries
            && !holds_source
            && let Some(entry) = super::entries::entry(node)
        {
            let base = entry.split('[').next().unwrap_or_default();
            // The key is a literal: nothing else in the read can carry taint.
            return super::entries::read_as(&entry)
                .iter()
                .any(|e| names.contains(e))
                || names.contains(base);
        }
        // A map read whole holds its tainted entries.
        if entries
            && NAMES.contains(&node.kind().as_ref())
            && super::entries::holds_tainted(&text, names)
        {
            return true;
        }
        // Nothing below can be tainted: no source in it, no tainted name
        // spelled in it, no call that could return source data.
        if !holds_source
            // An entry `m[k]` is spelled through its map's name.
            && !names
                .iter()
                .any(|n| text.contains(n.split('[').next().unwrap_or(n)))
            && !((text.contains('(') || self.bare_calls) && self.any_sourcing())
        {
            return false;
        }
        let kind = node.kind();
        if (NAMES.contains(&kind.as_ref()) || is_field(node)) && names.contains(text.as_ref()) {
            // `int n = rs.getInt(1)`: a number holds no injected text.
            return !super::declared::scalar(node);
        }
        // `c ? a : b` is `a` or `b`, never `c`; a guard in `c` cleans the
        // side it protects (`isLocal(u) ? u : "/"`).
        if matches!(
            kind.as_ref(),
            "ternary_expression" | "conditional_expression" | "conditional"
        ) && let Some((cond, a, b)) = super::deadcode::sides(node)
        {
            let (holds, fails) = super::guards::safe(&cond, &self.guards);
            return self.tainted(&a, &(names - &holds)) || self.tainted(&b, &(names - &fails));
        }
        // Ruby: `custom_fields` alone may be a call of a method returning
        // request data.
        if self.bare_calls
            && kind == "identifier"
            && let Some(s) = self.summaries.get(text.as_ref())
        {
            return s.returns_source;
        }
        // A mapped collection carries what its callback returns.
        if let Some(t) = super::iteration::mapped(self, node, names) {
            return t;
        }
        // A function we have a summary for: only what it really passes through.
        if CALLS.contains(&kind.as_ref())
            && let Some((s, guessed)) = self.summary_guessed(node)
        {
            let passed = s.returns_source
                || args(node)
                    .iter()
                    .enumerate()
                    .any(|(i, a)| s.returns.contains(&i) && self.tainted(a, names));
            // `obj.get(k)` matched to the project's only `get` by name is a
            // guess: request data it is called on (`request.GET.get('q')`)
            // still flows out.
            let receiver = node
                .part("function")
                .and_then(|f| f.part("object"))
                .or_else(|| node.part("object"))
                .or_else(|| node.part("receiver"));
            // `order.getNote()` on an order holding request data: a getter
            // reads the object's state, which its summary does not follow.
            let getter = args(node).is_empty()
                && super::summary::called_name(node).is_some_and(|m| {
                    m.len() > 3 && m.starts_with("get") && m[3..].starts_with(char::is_uppercase)
                });
            return passed
                || ((guessed || getter) && receiver.is_some_and(|r| self.tainted(&r, names)));
        }
        node.children().any(|c| self.tainted(&c, names))
    }

    /// Walks `scope` from `names`, then each function nested in it (callbacks,
    /// closures) with the tainted names it captures plus `own(nested)`, reporting
    /// what tainted data reaches.
    pub fn run<'a, D: Doc>(
        &self,
        scope: &Node<'a, D>,
        names: HashSet<String>,
        hits: &Hits<'a, D>,
        own: &impl Fn(&Node<'a, D>) -> HashSet<String>,
        on: &mut dyn FnMut(Reached<'a, D>),
    ) {
        let mut nested = Vec::new();
        self.run_scope(scope, names, hits, &mut |s| match s {
            Seen::Reached(r) => on(r),
            Seen::Nested(f, captured) => nested.push((f, captured)),
        });
        for (f, captured) in nested {
            let params = super::summary::param_names(&f);
            let text = f.text();
            let element = super::callbacks::bound(self, &f, &captured);
            // Only what the nested function mentions can reach it.
            let mut names: HashSet<String> = captured
                .into_iter()
                .filter(|n| !params.contains(n) && text.contains(n.as_str()))
                .chain(element)
                .collect();
            names.extend(own(&f));
            // A nested function's `return` is not this scope's.
            self.run(&f, names, hits, own, &mut |reached| match reached {
                Reached::Return(value) => on(Reached::Responds(f.clone(), value)),
                other => on(other),
            });
        }
    }
}

pub(super) fn enclosing<'a, D: Doc>(node: &Node<'a, D>, root: &Node<'a, D>) -> Node<'a, D> {
    node.ancestors()
        .find(|a| is_function(a))
        .unwrap_or_else(|| root.clone())
}
