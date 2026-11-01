//! The declared type of a name, read from the source: a local variable,
//! parameter or field declared with a type (`Yaml y = …`, `ExpressRunner r`,
//! `x: Pool`), or `var x = new T(…)`. Typed languages state it, so a
//! `sink_types` constraint needs no language server there.

use super::kotlin::Part;
use ast_grep_core::{Doc, Node};

/// Statements and members that declare names with a type, per grammar.
pub(super) const DECLARATIONS: [&str; 7] = [
    "local_variable_declaration",
    "field_declaration",
    "local_declaration_statement",
    "variable_declaration",
    "lexical_declaration",
    "public_field_definition",
    "property_declaration",
];
/// Parameter lists, and the parameters in them.
/// Java's try-with-resources declares its resources like parameters.
const PARAMETER_LISTS: [&str; 6] = [
    "formal_parameters",
    "parameter_list",
    "parameters",
    "resource_specification",
    // Kotlin functions, and `class C(private val db: Db)`.
    "function_value_parameters",
    "primary_constructor",
];
pub(super) const PARAMETERS: [&str; 7] = [
    "class_parameter",
    "resource",
    "formal_parameter",
    "spread_parameter",
    "parameter",
    "required_parameter",
    "optional_parameter",
];

/// Types whose values cannot carry an injected string.
const SCALARS: [&str; 30] = [
    "int",
    "long",
    "short",
    "byte",
    "double",
    "float",
    "boolean",
    "Integer",
    "Long",
    "Short",
    "Byte",
    "Double",
    "Float",
    "Boolean",
    "BigDecimal",
    "BigInteger",
    "UUID",
    "bool",
    "decimal",
    "uint",
    "ulong",
    "ushort",
    "sbyte",
    "Guid",
    "Int",
    "UInt",
    "ULong",
    "Int32",
    "Int64",
    "Char",
];

/// Is `at` a name declared with a numeric, boolean or UUID type, in a
/// language that holds a value to its declared type at run time (Java, C#,
/// Kotlin)? A TypeScript annotation (`id: number`) is not checked when the
/// program runs, so it does not count.
pub(super) fn scalar<D: Doc>(at: &Node<D>) -> bool {
    declared(at).is_some_and(|(ty, annotation)| !annotation && SCALARS.contains(&ty.as_str()))
}

/// The type `name` is declared with in a scope enclosing `at`, nearest first.
/// Only the direct members of each enclosing scope are read (statements of a
/// block, fields of a class, parameters of a function), not whole subtrees.
pub(super) fn declared_type<D: Doc>(at: &Node<D>) -> Option<String> {
    declared(at).map(|(ty, _)| ty)
}

/// The declared type, and whether it was written as a TypeScript-style
/// annotation (`: T`).
fn declared<D: Doc>(at: &Node<D>) -> Option<(String, bool)> {
    if !matches!(at.kind().as_ref(), "identifier" | "simple_identifier") {
        return None;
    }
    let name = at.text();
    let line = at.start_pos().line();
    for scope in at.ancestors() {
        let mut found = None;
        for c in scope.children() {
            let kind = c.kind();
            if DECLARATIONS.contains(&kind.as_ref()) {
                if c.start_pos().line() <= line || kind == "field_declaration" {
                    found = typed(&c, &name).or(found);
                }
            } else if PARAMETER_LISTS.contains(&kind.as_ref()) {
                for p in c
                    .children()
                    .filter(|p| PARAMETERS.contains(&p.kind().as_ref()))
                {
                    found = typed(&p, &name).or(found);
                }
            }
        }
        if found.is_some() {
            return found;
        }
    }
    // `URLUtil.url(x)`: an undeclared capitalized receiver names a class.
    let is_receiver = at.parent().is_some_and(|p| {
        p.part("object")
            .or_else(|| p.part("expression"))
            .is_some_and(|o| o.range() == at.range())
    });
    if is_receiver && name.chars().next().is_some_and(char::is_uppercase) {
        return Some((name.to_string(), false));
    }
    None
}

/// The type of `name` if `decl` declares it, and whether it is an annotation.
pub(super) fn typed<D: Doc>(decl: &Node<D>, name: &str) -> Option<(String, bool)> {
    // Java/C# locals and fields: `T a = …, b;` (C# nests a variable_declaration).
    let declarators: Vec<Node<D>> = decl
        .dfs()
        .filter(|n| n.kind() == "variable_declarator")
        .collect();
    let declares = |n: &Node<D>| {
        n.part("name")
            .or_else(|| n.children().find(|c| c.kind() == "identifier"))
            .is_some_and(|id| id.text() == name)
    };
    let ty = decl.part("type").or_else(|| {
        decl.children()
            .find(|c| c.kind() == "variable_declaration")?
            .part("type")
    });
    if !declarators.is_empty() {
        let declarator = declarators.iter().find(|d| declares(d))?;
        // TypeScript keeps the annotation on the declarator: `const db: Pool`.
        let ty = ty.or_else(|| declarator.part("type"))?.text().to_string();
        let annotation = ty.starts_with(':');
        let ty = ty.trim_start_matches(':').trim().to_string();
        if ty != "var" {
            return Some((ty, annotation));
        }
        // `var x = new T(…)`.
        let created = declarator.part("value").or_else(|| {
            declarator
                .children()
                .find(|c| c.kind().contains("creation"))
        })?;
        return Some((created.part("type")?.text().to_string(), false));
    }
    // Parameters: `T name`, `name: T`.
    let named = decl
        .part("name")
        .or_else(|| decl.part("pattern"))
        .or_else(|| decl.children().find(|c| c.kind() == "identifier"))?;
    if named.text() != name {
        return None;
    }
    let ty = ty?.text().to_string();
    let annotation = ty.starts_with(':');
    Some((ty.trim_start_matches(':').trim().to_string(), annotation))
}

#[cfg(test)]
mod tests {
    use super::{declared_type, scalar};
    use ast_grep_core::tree_sitter::LanguageExt;
    use ast_grep_language::SupportLang;

    fn type_at(lang: SupportLang, src: &str, name: &str, nth: usize) -> Option<String> {
        let root = lang.ast_grep(src);
        let node = root
            .root()
            .dfs()
            .filter(|n| n.kind() == "identifier" && n.text() == name)
            .nth(nth)?;
        declared_type(&node)
    }

    #[test]
    fn java_locals_params_fields_and_var() {
        let src = "class A {\n  private ExpressRunner runner;\n  void f(String q, Yaml y) {\n    var r = new Velocity();\n    Map<String, Object> m = null, n = null;\n    if (q != null) {\n      runner.execute(q); y.load(q); r.go(); n.get(q);\n    }\n  }\n}\n";
        let j = SupportLang::Java;
        assert_eq!(
            type_at(j, src, "runner", 1).as_deref(),
            Some("ExpressRunner")
        );
        assert_eq!(type_at(j, src, "y", 1).as_deref(), Some("Yaml"));
        assert_eq!(type_at(j, src, "r", 1).as_deref(), Some("Velocity"));
        assert_eq!(
            type_at(j, src, "n", 1).as_deref(),
            Some("Map<String, Object>")
        );
        assert_eq!(type_at(j, src, "q", 1).as_deref(), Some("String"));
        assert_eq!(type_at(j, src, "nope", 0), None);
    }

    #[test]
    fn csharp_and_typescript() {
        let cs = "class A {\n  void F(string q) {\n    SqlCommand cmd = new SqlCommand();\n    var c2 = new SqlCommand(q);\n    cmd.Run(q); c2.Run(q);\n  }\n}\n";
        assert_eq!(
            type_at(SupportLang::CSharp, cs, "cmd", 1).as_deref(),
            Some("SqlCommand")
        );
        assert_eq!(
            type_at(SupportLang::CSharp, cs, "c2", 1).as_deref(),
            Some("SqlCommand")
        );
        let ts = "function f(db: Pool, q: string) { const c: PoolClient = x; db.query(q); c.query(q); }\n";
        assert_eq!(
            type_at(SupportLang::TypeScript, ts, "db", 1).as_deref(),
            Some("Pool")
        );
        assert_eq!(
            type_at(SupportLang::TypeScript, ts, "c", 1).as_deref(),
            Some("PoolClient")
        );
    }

    #[test]
    fn scalars_where_the_type_is_enforced() {
        let is_scalar = |lang: SupportLang, src: &str, kind: &str, name: &str| {
            let root = lang.ast_grep(src);
            let node = root
                .root()
                .dfs()
                .filter(|n| n.kind() == kind && n.text() == name)
                .last()
                .unwrap();
            scalar(&node)
        };
        let java = "class A { void f(String s, long id) { int n = 1; Integer m = 2; s.go(n, m, id, s); } }";
        for name in ["n", "m", "id"] {
            assert!(
                is_scalar(SupportLang::Java, java, "identifier", name),
                "{name}"
            );
        }
        assert!(!is_scalar(SupportLang::Java, java, "identifier", "s"));
        let cs = "class A { void F(string s) { int n = 1; Guid g = Guid.NewGuid(); s.Go(n, g); } }";
        assert!(is_scalar(SupportLang::CSharp, cs, "identifier", "n"));
        assert!(is_scalar(SupportLang::CSharp, cs, "identifier", "g"));
        let kt = "fun f(id: Long) { val n: Int = 1; go(n, id) }";
        assert!(is_scalar(SupportLang::Kotlin, kt, "simple_identifier", "n"));
        assert!(is_scalar(
            SupportLang::Kotlin,
            kt,
            "simple_identifier",
            "id"
        ));
        // Not checked when the program runs: `req.query.id` is still a string.
        let ts = "function f(id: number) { const n: number = req.query.n; go(id, n); }";
        assert!(!is_scalar(SupportLang::TypeScript, ts, "identifier", "id"));
        assert!(!is_scalar(SupportLang::TypeScript, ts, "identifier", "n"));
    }
}
