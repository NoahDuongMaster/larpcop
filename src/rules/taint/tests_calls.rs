//! Taint through function calls: summaries in the same file and across imports.

pub(super) use super::tests_support::{found, guarded, rule};
use super::tests_support::{guarded_config, with_safe_prefix};

#[test]
fn calls_in_the_same_file() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("a.ts"),
        "\
function run(sql) { return db.query(sql); }
function getName(req) { return req.query.name; }
function clean(x) { return Number(x); }
function wrap(x) { return `(${x})`; }
function a(req) { const s = 'select ' + req.query.id; run(s); }
function b(req) { const n = getName(req); db.query('x' + n); }
function c(req) { db.query('x' + clean(req.query.id)); }
function d(req) { const v = wrap(req.query.id); db.query(v); }
",
    )
    .unwrap();
    let r = rule(
        "TypeScript",
        dir.path(),
        &["req.query"],
        &["$DB.query($X)"],
        &["Number($Y)"],
    );
    let got = found(&r, dir.path(), "a.ts");
    let lines: Vec<usize> = got.iter().map(|(l, _)| *l).collect();
    assert_eq!(lines, [5, 6, 8], "{got:?}");
    assert!(
        got[0].1.contains("`run` → `db.query(sql)` at a.ts:1"),
        "{got:?}"
    );
}

#[test]
fn calls_into_imported_files() {
    let dir = tempfile::tempdir().unwrap();
    let w = |rel: &str, src: &str| {
        let p = dir.path().join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, src).unwrap();
    };
    // TypeScript: named import, path alias, chained helpers.
    w(
        "tsconfig.json",
        "{ // comment\n \"compilerOptions\": { \"paths\": { \"@/*\": [\"./src/*\"] } } }",
    );
    w(
        "src/db.ts",
        "export function runQuery(sql: string) { return pool.query(sql); }\n",
    );
    w(
        "src/repo.ts",
        "import { runQuery } from './db';\nexport function byName(n: string) { return runQuery(`select ${n}`); }\n",
    );
    w(
        "src/routes.ts",
        "import { byName } from '@/repo';\nimport * as db from './db';\n\
export function h(req) {\n  byName(req.query.n);\n  db.runQuery(req.query.q);\n}\n",
    );
    let ts = rule(
        "TypeScript",
        dir.path(),
        &["req.query"],
        &["$DB.query($X)"],
        &[],
    );
    let got = found(&ts, dir.path(), "src/routes.ts");
    assert_eq!(
        got.iter().map(|(l, _)| *l).collect::<Vec<_>>(),
        [4, 5],
        "{got:?}"
    );
    assert!(
        got[0]
            .1
            .contains("`byName` → `runQuery` → `pool.query(sql)` at src/db.ts:1"),
        "{got:?}"
    );

    // Python: relative import.
    w("app/__init__.py", "");
    w("app/db.py", "def run(sql):\n    cursor.execute(sql)\n");
    w(
        "app/views.py",
        "from .db import run\n\ndef v():\n    run('select ' + request.args.get('x'))\n",
    );
    let py = rule(
        "Python",
        dir.path(),
        &["request.args"],
        &["$C.execute($X)"],
        &[],
    );
    assert_eq!(found(&py, dir.path(), "app/views.py").len(), 1);

    // Go: another file of the same package.
    w("go.mod", "module example.com/m\n");
    w(
        "svc/db.go",
        "package svc\n\nfunc Run(q string) { db.Query(q) }\n",
    );
    w(
        "svc/h.go",
        "package svc\n\nfunc H(r *http.Request) {\n\tRun(\"x\" + r.URL.Query().Get(\"id\"))\n}\n",
    );
    let go = rule("Go", dir.path(), &["r.URL.Query()"], &["$D.Query($X)"], &[]);
    assert_eq!(
        found(&go, dir.path(), "svc/h.go")
            .iter()
            .map(|(l, _)| *l)
            .collect::<Vec<_>>(),
        [4]
    );
}

#[test]
fn callbacks_see_the_tainted_names_they_capture() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("a.js"),
        "\
function login(req, res) {
  const { userName } = req.body;
  users.find(userName, (err, user) => {
    if (err) db.query('missing ' + userName);
  });
  users.find(userName, (userName) => db.query(userName));
}
",
    )
    .unwrap();
    let r = rule(
        "JavaScript",
        dir.path(),
        &["req.body"],
        &["$DB.query($X)"],
        &[],
    );
    // The second callback's parameter shadows the captured name.
    assert_eq!(
        found(&r, dir.path(), "a.js")
            .iter()
            .map(|(l, _)| *l)
            .collect::<Vec<_>>(),
        [4]
    );
}

#[test]
fn guards_clean_checked_names() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("a.js"),
        "\
function a(req, res) {
  const next = req.query.next;
  if (!next.startsWith('/') || next.startsWith('//')) {
    return res.redirect('/');
  }
  res.redirect(next);
}
function b(req, res) {
  const next = req.query.next;
  if (next.startsWith('/')) { res.redirect(next); }
  res.redirect(next);
}
function c(req, res) {
  const next = req.query.next;
  if (!next.startsWith('/')) { res.redirect(next); }
  if (next.length > 10) { return; }
  res.redirect(next);
}
",
    )
    .unwrap();
    let guards = ["$X.startsWith($P)"];
    let r = with_safe_prefix(
        guarded_config(
            "JavaScript",
            &["req.query"],
            &["$R.redirect($X)"],
            &[],
            &guards,
        ),
        "^/[^/\\\\]",
        dir.path(),
    );
    let lines: Vec<usize> = found(&r, dir.path(), "a.js")
        .iter()
        .map(|(l, _)| *l)
        .collect();
    // c: `if (!next.startsWith('/')) { res.redirect(next) }` redirects when the check fails.
    assert_eq!(lines, [11, 15, 17]);
}

#[test]
fn containers_hold_what_was_put_in() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("a.js"),
        "\
function a(req) {
  const parts = [];
  parts.push(req.query.id);
  db.query('select ' + parts.join(','));
}
function b(req) {
  const where = {};
  Object.assign(where, req.body);
  db.query(where);
}
function c(req) {
  const parts = ['1'];
  parts.push(Number(req.query.id));
  db.query('select ' + parts.join(','));
}
",
    )
    .unwrap();
    let r = rule(
        "JavaScript",
        dir.path(),
        &["req.query", "req.body"],
        &["$DB.query($X)"],
        &["Number($X)"],
    );
    let lines: Vec<usize> = found(&r, dir.path(), "a.js")
        .iter()
        .map(|(l, _)| *l)
        .collect();
    assert_eq!(lines, [4, 9]);
}

#[test]
fn query_and_fragment_cannot_pick_the_host() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("a.js"),
        "function a(req, res) { res.redirect(\"/search?q=\" + req.query.q); }
function b(req, res) { res.redirect(BASE_URL + \"#\" + req.query.q); }
function c(req, res) { res.redirect(BASE_URL + req.query.q); }
function d(req, res) { res.redirect(`${base}?q=${req.query.q}`); }
function e(req, res) { res.redirect(\"/\" + req.query.q); }
function f(req, res) { res.redirect(\"/\" + \"p/\" + req.query.q); }
",
    )
    .unwrap();
    let r = with_safe_prefix(
        guarded_config("JavaScript", &["req.query"], &["$R.redirect($X)"], &[], &[]),
        "^/[^/\\\\]",
        dir.path(),
    );
    let lines: Vec<usize> = found(&r, dir.path(), "a.js")
        .iter()
        .map(|(l, _)| *l)
        .collect();
    assert_eq!(lines, [3, 4, 5]);
}
