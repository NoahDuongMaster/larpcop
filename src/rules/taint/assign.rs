//! The assignment kinds the walk follows, loops binding each element
//! included, and their target and value.

use super::kotlin::Part;
use ast_grep_core::{Doc, Node};

/// Targets (left) and value (right) of the assignment kinds we follow.
const ASSIGNMENTS: [(&str, &str, &str); 17] = [
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
    // PHP `foreach ($rows as $row)`, `as $k => $v`, `as &$r`: no field names.
    ("foreach_statement", "", ""),
];

/// The target and value of an assignment (any kind in `ASSIGNMENTS`). C#'s
/// `var x = …` leaves the value without a field name: the last other child.
pub(crate) fn assignment<'a, D: Doc>(n: &Node<'a, D>) -> Option<(Node<'a, D>, Node<'a, D>)> {
    let kind = n.kind();
    let (_, l, r) = ASSIGNMENTS.iter().find(|(k, ..)| kind == *k)?;
    if kind == "foreach_statement" {
        return foreach(n);
    }
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
pub(crate) const LOOPS: [&str; 5] = [
    "enhanced_for_statement",
    "for_in_statement",
    "for_statement",
    "range_clause",
    "foreach_statement",
];

/// PHP `foreach`: the collection, then what each element is bound to (the
/// value of a `$k => $v` pair, the variable of `&$r`).
fn foreach<'a, D: Doc>(n: &Node<'a, D>) -> Option<(Node<'a, D>, Node<'a, D>)> {
    let mut named = n
        .children()
        .filter(|c| c.is_named() && c.kind() != "comment");
    let (right, mut left) = (named.next()?, named.next()?);
    if matches!(left.kind().as_ref(), "pair" | "by_ref") {
        left = left.children().filter(|c| c.is_named()).last()?;
    }
    if left.kind() == "by_ref" {
        let inner = left.children().find(|c| c.is_named());
        left = inner?;
    }
    Some((left, right))
}
