//! Per-function size and cyclomatic complexity from the tree-sitter tree, for
//! every language ast-grep parses (unknown node kinds simply never match).
//!
//! Complexity is McCabe's: 1 + one per branch point (if/loop/case/catch,
//! ternary, `&&`/`||`/`??`). Nested functions are measured on their own.

use ast_grep_core::{Doc, Node};
use ast_grep_language::{LanguageExt, SupportLang};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Function {
    pub name: String,
    /// 1-based line of the function's first line.
    pub line: usize,
    pub lines: usize,
    pub complexity: usize,
}

const FUNCTIONS: [&str; 19] = [
    "function_declaration",
    "function_expression",
    "generator_function_declaration",
    "arrow_function",
    "method_definition",
    "function_definition",
    "method_declaration",
    "constructor_declaration",
    "func_literal",
    "function_item",
    "closure_expression",
    "lambda_expression",
    "local_function_statement",
    "lambda",
    "method",
    "singleton_method",
    "function",
    // Kotlin `{ x -> … }`, `fun(x: T) { … }`.
    "lambda_literal",
    "anonymous_function",
];

const BRANCHES: [&str; 26] = [
    "if_statement",
    "if_expression",
    "elif_clause",
    "for_statement",
    "for_in_statement",
    "enhanced_for_statement",
    "for_expression",
    "while_statement",
    "while_expression",
    "loop_expression",
    "do_statement",
    "switch_case",
    "case_clause",
    "expression_case",
    "type_case",
    "communication_case",
    "match_arm",
    "catch_clause",
    "except_clause",
    "rescue",
    "conditional_expression",
    "ternary_expression",
    "conditional",
    "boolean_operator",
    "switch_section",
    "when",
];

/// Named nodes only: keyword tokens share some kinds (`function`, `when`).
pub(super) fn is_function<D: Doc>(node: &Node<D>) -> bool {
    node.is_named() && FUNCTIONS.contains(&node.kind().as_ref())
}

/// What a node kind means for the metrics. A kind id always has the same name
/// and named-ness, so this is decided once per kind and file, not per node.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Class {
    Unknown,
    Other,
    Function,
    Branch,
    /// A branch only when its operator is `&&`, `||`, `??`, `and` or `or`.
    Binary,
}

#[derive(Default)]
struct Classes(Vec<Class>);

impl Classes {
    fn of<D: Doc>(&mut self, node: &Node<D>) -> Class {
        let id = usize::from(node.kind_id());
        if id >= self.0.len() {
            self.0.resize(id + 1, Class::Unknown);
        }
        if self.0[id] == Class::Unknown {
            self.0[id] = classify(node);
        }
        self.0[id]
    }
}

fn classify<D: Doc>(node: &Node<D>) -> Class {
    let kind = node.kind();
    if !node.is_named() {
        Class::Other
    } else if FUNCTIONS.contains(&kind.as_ref()) {
        Class::Function
    } else if BRANCHES.contains(&kind.as_ref()) {
        Class::Branch
    } else if kind == "binary_expression" {
        Class::Binary
    } else {
        Class::Other
    }
}

fn logical<D: Doc>(node: &Node<D>) -> bool {
    node.field("operator")
        .is_some_and(|op| matches!(op.text().as_ref(), "&&" | "||" | "??" | "and" | "or"))
}

fn name<D: Doc>(node: &Node<D>) -> String {
    if let Some(n) = node.field("name") {
        return n.text().to_string();
    }
    // `const handler = () => …`: the binding names the function.
    node.parent()
        .and_then(|p| p.field("name").or_else(|| p.field("left")))
        .map(|n| n.text().to_string())
        .unwrap_or_else(|| "<anonymous>".into())
}

pub fn functions(lang: SupportLang, source: &str) -> Vec<Function> {
    let grep = lang.ast_grep(source);
    functions_of(&grep.root())
}

/// The functions of a tree that has already been parsed, in document order.
/// One pre-order walk: a branch point counts for the innermost function that
/// is still open (a node starting at or after its end is outside it).
pub fn functions_of<D: Doc>(root: &Node<D>) -> Vec<Function> {
    let mut classes = Classes::default();
    let mut out: Vec<Function> = Vec::new();
    // End byte and index in `out` of the functions around the current node.
    let mut open: Vec<(usize, usize)> = Vec::new();
    for node in root.dfs() {
        let range = node.range();
        while open.last().is_some_and(|(end, _)| range.start >= *end) {
            open.pop();
        }
        let branch = match classes.of(&node) {
            Class::Function => {
                let (start, end) = (node.start_pos().line(), node.end_pos().line());
                open.push((range.end, out.len()));
                out.push(Function {
                    name: name(&node),
                    line: start + 1,
                    lines: end - start + 1,
                    complexity: 1,
                });
                false
            }
            Class::Branch => true,
            Class::Binary => logical(&node),
            Class::Unknown | Class::Other => false,
        };
        if let (true, Some((_, at))) = (branch, open.last()) {
            out[*at].complexity += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_branches_per_function() {
        let ts = "function a(x: number) {\n  if (x > 1 && x < 5) { return 1; }\n  for (const i of [1]) {}\n  \
const inner = () => (x ? 1 : 2);\n  return x ?? 0;\n}\n";
        let f = functions(SupportLang::TypeScript, ts);
        let a = f.iter().find(|f| f.name == "a").unwrap();
        // 1 + if + && + for + ?? (the ternary belongs to `inner`)
        assert_eq!((a.complexity, a.lines), (5, 6));
        let inner = f.iter().find(|f| f.name == "inner").unwrap();
        assert_eq!(inner.complexity, 2);

        let py = "def g(x):\n    if x and x > 2:\n        return 1\n    elif x:\n        return 2\n    return 3\n";
        assert_eq!(functions(SupportLang::Python, py)[0].complexity, 4);
        let go = "package m\nfunc h(x int) int {\n\tswitch x {\n\tcase 1:\n\t\treturn 1\n\tcase 2:\n\t\treturn 2\n\t}\n\treturn 0\n}\n";
        assert_eq!(functions(SupportLang::Go, go)[0].complexity, 3);
        let rs = "fn k(x: Option<u8>) -> u8 { match x { Some(v) if v > 1 => v, Some(_) => 1, None => 0 } }\n";
        assert_eq!(functions(SupportLang::Rust, rs)[0].complexity, 4);
    }

    #[test]
    fn a_branch_after_a_nested_function_belongs_to_the_outer_one() {
        let py = "def outer(x):\n    def inner(y):\n        if y:\n            return 1\n    if x:\n        return 2\n    return 3\n";
        let f = functions(SupportLang::Python, py);
        let by = |n: &str| f.iter().find(|f| f.name == n).unwrap().complexity;
        assert_eq!((by("outer"), by("inner")), (2, 2));
        // Two functions side by side: the second one's branches are its own.
        let ts = "function a() { if (1) {} }\nfunction b() { if (2) {} if (3) {} }\n";
        let f = functions(SupportLang::TypeScript, ts);
        assert_eq!(f.iter().map(|f| f.complexity).collect::<Vec<_>>(), [2, 3]);
    }
}
