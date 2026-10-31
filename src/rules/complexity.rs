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

const FUNCTIONS: [&str; 17] = [
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

fn is_branch<D: Doc>(node: &Node<D>) -> bool {
    if !node.is_named() {
        return false;
    }
    let kind = node.kind();
    if BRANCHES.contains(&kind.as_ref()) {
        return true;
    }
    kind == "binary_expression"
        && node
            .field("operator")
            .is_some_and(|op| matches!(op.text().as_ref(), "&&" | "||" | "??" | "and" | "or"))
}

/// Branch points below `node`, not counting nested functions.
fn branches<D: Doc>(node: &Node<D>) -> usize {
    node.children()
        .map(|c| {
            if is_function(&c) {
                0
            } else {
                usize::from(is_branch(&c)) + branches(&c)
            }
        })
        .sum()
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
    grep.root()
        .dfs()
        .filter(|n| is_function(n))
        .map(|f| {
            let (start, end) = (f.start_pos().line(), f.end_pos().line());
            Function {
                name: name(&f),
                line: start + 1,
                lines: end - start + 1,
                complexity: 1 + branches(&f),
            }
        })
        .collect()
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
}
