//! Taint in Kotlin: `val`/`var`, string templates, guards that return,
//! expression-bodied functions, Spring parameter annotations, classes of
//! other files.

use super::tests_calls::{found, guarded, rule};
use super::tests_support::guarded_config;
use super::*;
use crate::config::TaintConfig;

fn lines(r: &TaintRule, dir: &std::path::Path, file: &str) -> Vec<usize> {
    found(r, dir, file).iter().map(|(l, _)| *l).collect()
}

#[test]
fn kotlin_locals_templates_and_cleaning() {
    let dir = tempfile::tempdir().unwrap();
    let kt = r#"
fun a(req: HttpServletRequest) {
    val id = req.getParameter("id")
    db.query("SELECT * FROM t WHERE id = $id")
    db.query("SELECT * FROM t WHERE id = ${id.trim()}")
    var n = req.getParameter("n")
    n = "fixed"
    db.query(n)
    val num = req.getParameter("n").toInt()
    db.query("x" + num)
    val (p, q) = Pair(req.getParameter("p"), 1)
    db.query(p)
    for (v in req.getParameterValues("v")) {
        db.query(v)
    }
    val e = req.getParameter("e") ?: return
    db.query(e)
}
"#;
    std::fs::write(dir.path().join("A.kt"), kt).unwrap();
    let r = rule(
        "Kotlin",
        dir.path(),
        &["$R.getParameter($K)", "$R.getParameterValues($K)"],
        &["db.query($X)"],
        &["$X.toInt()"],
    );
    assert_eq!(lines(&r, dir.path(), "A.kt"), [4, 5, 12, 14, 17]);
}

#[test]
fn kotlin_guards_and_functions() {
    let dir = tempfile::tempdir().unwrap();
    let kt = r#"
val ALLOWED = setOf("a", "b")

fun run(sql: String) = db.query(sql)

fun clean(s: String): String {
    return s.replace("'", "")
}

fun a(req: HttpServletRequest) {
    val id = req.getParameter("id")
    if (!ALLOWED.contains(id)) {
        return
    }
    db.query(id)
}

fun b(req: HttpServletRequest) {
    val id = req.getParameter("id")
    run(id)
    db.query(clean(id))
    run(clean(id))
}

fun c(req: HttpServletRequest) {
    val id = req.getParameter("id")
    when (id) {
        "x" -> db.query(id)
        else -> db.query("fixed")
    }
    req.getParameter("l").split(",").forEach { db.query(it) }
}
"#;
    std::fs::write(dir.path().join("A.kt"), kt).unwrap();
    let r = guarded(
        "Kotlin",
        dir.path(),
        &["$R.getParameter($K)"],
        &["db.query($X)"],
        &["$S.replace(\"'\", \"\")"],
        &["$L.contains($X)", "$C.equals($X)"],
    );
    // a: allow-listed; b: through `run`, not through a cleaning function; c:
    // `when` does not compare (yet), and `it` holds the list.
    assert_eq!(lines(&r, dir.path(), "A.kt"), [20, 28, 31]);
}

#[test]
fn kotlin_spring_handlers_and_typed_receivers() {
    let dir = tempfile::tempdir().unwrap();
    let kt = r#"
@RestController
class UserController(private val jdbc: JdbcTemplate, private val other: Cache) {
    @GetMapping("/u")
    fun find(@RequestParam name: String, @PathVariable id: Long, page: Int): String {
        jdbc.queryForList("SELECT * FROM u WHERE name = '$name'")
        jdbc.queryForList("SELECT * FROM u WHERE id = $id")
        other.queryForList(name)
        return "ok"
    }

    fun helper(name: String) = jdbc.queryForList(name)
}
"#;
    std::fs::write(dir.path().join("UserController.kt"), kt).unwrap();
    let cfg = TaintConfig {
        param_decorators: vec!["RequestParam".into(), "PathVariable".into()],
        sink_types: [("S".to_string(), "JdbcTemplate$".to_string())].into(),
        sanitizers: Vec::new(),
        ..guarded_config(
            "Kotlin",
            &["$R.getParameter($K)"],
            &["$S.queryForList($X)"],
            &[],
            &[],
        )
    };
    let root = dir.path().to_path_buf();
    let typed = typed::Typed::new("t", &cfg.sink_types, root, Default::default()).unwrap();
    let r = TaintRule::new(&cfg, typed, dir.path().to_path_buf()).unwrap();
    let file = SourceFile {
        rel: "UserController.kt".into(),
        content: kt.into(),
    };
    let got: Vec<usize> = r.check(&file).iter().map(|v| v.line).collect();
    // `id` is a Long; `other` is not a JdbcTemplate.
    assert_eq!(got, [6]);
}

#[test]
fn kotlin_across_files_and_packages() {
    let dir = tempfile::tempdir().unwrap();
    let src = dir.path().join("src/main/kotlin/org/acme");
    std::fs::create_dir_all(src.join("web")).unwrap();
    std::fs::create_dir_all(src.join("db")).unwrap();
    std::fs::create_dir_all(dir.path().join("src/main/java/org/acme/util")).unwrap();
    std::fs::write(
        src.join("db/UserRepo.kt"),
        "package org.acme.db\n\nclass UserRepo {\n    fun byName(name: String) = db.query(\"SELECT * FROM u WHERE n = '$name'\")\n}\n",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("src/main/java/org/acme/util/Legacy.java"),
        "package org.acme.util;\n\npublic class Legacy {\n    public static void run(String sql) { db.query(sql); }\n}\n",
    )
    .unwrap();
    std::fs::write(
        src.join("web/Helpers.kt"),
        "package org.acme.web\n\nfun lookup(id: String) {\n    db.query(id)\n}\n",
    )
    .unwrap();
    std::fs::write(
        src.join("web/Page.kt"),
        "package org.acme.web\n\nimport org.acme.db.UserRepo\nimport org.acme.util.Legacy\n\nfun page(req: HttpServletRequest) {\n    val n = req.getParameter(\"n\")\n    UserRepo().byName(n)\n    Legacy.run(n)\n    lookup(n)\n}\n",
    )
    .unwrap();
    let r = rule(
        "Kotlin",
        dir.path(),
        &["$R.getParameter($K)"],
        &["db.query($X)"],
        &[],
    );
    let got = lines(&r, dir.path(), "src/main/kotlin/org/acme/web/Page.kt");
    assert_eq!(got, [8, 9, 10]);
}
