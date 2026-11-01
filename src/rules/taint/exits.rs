//! Branches that always leave: `return`, `throw`, `break`, `continue`, and
//! calls that end the request (PHP `die()`, Go `panic()`, Flask `abort()`),
//! as their last statement.

use super::kotlin::Part;
use ast_grep_core::{Doc, Node};

/// Calls that end the request: PHP `die()`, Go `panic()`, Flask `abort()`.
const EXIT_CALLS: [&str; 14] = [
    "raise ",
    "raise(",
    "fail ",
    "halt",
    "die(",
    "exit(",
    "panic(",
    "abort(",
    "sys.exit(",
    "os.Exit(",
    "process.exit(",
    "log.Fatal(",
    "log.Fatalf(",
    "log.Fatalln(",
];
const EXITS: [&str; 9] = [
    "exit_statement",
    // Kotlin `return`, `throw`, `break`, `continue`.
    "jump_expression",
    "return",
    "return_statement",
    "return_expression",
    "throw_statement",
    "raise_statement",
    "continue_statement",
    "break_statement",
];
/// Blocks that may end in the exit: Go's `statement_list`, the block of an `else`.
const BLOCKS: [&str; 7] = [
    "statement_list",
    "block",
    "statement_block",
    "compound_statement",
    "else_clause",
    // Kotlin `if (…) { … }`.
    "control_structure_body",
    "statements",
];

/// Does this branch always leave (return, throw, …)?
pub(super) fn exits<D: Doc>(branch: &Node<D>) -> bool {
    if EXITS.contains(&branch.kind().as_ref()) {
        return true;
    }
    let last = branch
        .children()
        .filter(|c| c.is_named() && c.kind() != "comment")
        .last();
    last.is_some_and(|l| {
        (BLOCKS.contains(&l.kind().as_ref()) && exits(&l))
            || EXITS.contains(&l.kind().as_ref())
            || (l.kind() == "expression_statement"
                && l.children().any(|c| EXITS.contains(&c.kind().as_ref())))
            || (matches!(l.kind().as_ref(), "expression_statement" | "call" | "identifier")
                && EXIT_CALLS.iter().any(|e| l.text().starts_with(e)))
            // Ruby: `redirect_to root_path and return`.
            || (l.kind() == "binary"
                && l.part("right").is_some_and(|r| EXITS.contains(&r.kind().as_ref())))
    })
}
