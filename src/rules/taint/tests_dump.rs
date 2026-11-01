//! Temporary: prints a syntax tree.

use ast_grep_core::tree_sitter::LanguageExt;
use ast_grep_language::SupportLang;

fn print(n: &ast_grep_core::Node<ast_grep_core::tree_sitter::StrDoc<SupportLang>>, depth: usize) {
    if !n.is_named() {
        return;
    }
    let text = n.text().replace('\n', " ");
    let short: String = text.chars().take(50).collect();
    let fields: Vec<String> = [
        "name",
        "value",
        "left",
        "right",
        "function",
        "object",
        "body",
        "condition",
    ]
    .iter()
    .filter(|f| n.field(f).is_some())
    .map(|f| f.to_string())
    .collect();
    println!("{}{} {:?} {}", "  ".repeat(depth), n.kind(), fields, short);
    for c in n.children() {
        print(&c, depth + 1);
    }
}

#[test]
#[ignore]
fn dump() {
    let src = std::fs::read_to_string(std::env::var("DUMP").unwrap()).unwrap();
    let lang: SupportLang = std::env::var("LANG_").unwrap().parse().unwrap();
    let root = lang.ast_grep(src);
    print(&root.root(), 0);
}

#[test]
#[ignore]
fn kotlin_probe() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::copy("/tmp/kt/A.kt", dir.path().join("A.kt")).unwrap();
    let r = super::tests_calls::rule(
        "Kotlin",
        dir.path(),
        &["$R.getParameter($K)"],
        &["$J.queryForList($X)", "$R.exec($X)"],
        &[],
    );
    println!(
        "FOUND {:?}",
        super::tests_calls::found(&r, dir.path(), "A.kt")
    );
}

#[test]
#[ignore]
fn kotlin_min() {
    use ast_grep_core::matcher::Pattern;
    let src = "fun f(req: R) {\n  val id = req.getParameter(\"id\")\n  jdbc.queryForList(id)\n}\n";
    let root = SupportLang::Kotlin.ast_grep(src);
    for p in [
        "$R.getParameter($K)",
        "$J.queryForList($X)",
        "jdbc.queryForList($X)",
    ] {
        let pat = Pattern::new(p, SupportLang::Kotlin);
        println!(
            "PAT {p}: {:?}",
            root.root()
                .find_all(&pat)
                .map(|m| m.text().to_string())
                .collect::<Vec<_>>()
        );
    }
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("A.kt"), src).unwrap();
    let r = super::tests_calls::rule(
        "Kotlin",
        dir.path(),
        &["$R.getParameter($K)"],
        &["$J.queryForList($X)"],
        &[],
    );
    println!(
        "FOUND {:?}",
        super::tests_calls::found(&r, dir.path(), "A.kt")
    );
}
