//! Methods: known to callers as `Class.method`, also across imports, with
//! Python's `self` / `cls` not counted among the arguments.

use super::tests_calls::{found, rule};

#[test]
fn methods_of_imported_classes() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("app/dao")).unwrap();
    std::fs::write(
        dir.path().join("app/dao/student.py"),
        "\
class Student:
    @staticmethod
    async def create(conn, name):
        q = \"INSERT INTO students (name) VALUES ('\" + name + \"')\"
        await conn.execute(q)

    def rename(self, conn, name):
        conn.execute(\"UPDATE students SET name = '\" + name + \"'\")
",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("app/views.py"),
        "\
from app.dao.student import Student

async def add(request):
    data = await request.post()
    await Student.create(conn, data['name'])
    await Student.create(data['name'], 'fixed')

def rename(request, student):
    student.rename(conn, request.args['name'])
",
    )
    .unwrap();
    let r = rule(
        "Python",
        dir.path(),
        &["await request.post()", "request.args"],
        &["$C.execute($X)"],
        &[],
    );
    let hits = found(&r, dir.path(), "app/views.py");
    // The second call passes request data as `conn`, which never reaches SQL.
    assert_eq!(
        hits.iter().map(|(l, _)| *l).collect::<Vec<_>>(),
        [5, 9],
        "{hits:?}"
    );
    assert!(hits[0].1.contains("`Student.create`"), "{hits:?}");
}

/// Java: a helper class named in full (`new org.acme.web.Wrapper(req)`), no
/// `import`, is read through the source root.
#[test]
fn java_class_named_in_full() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("src/main/java/org/acme");
    std::fs::create_dir_all(base.join("web")).unwrap();
    std::fs::write(
        base.join("web/Wrapper.java"),
        "package org.acme.web;\npublic class Wrapper {\n  private Req req;\n  public Wrapper(Req req) { this.req = req; }\n  public String getTheParameter(String n) { return req.getParameter(n); }\n}\n",
    )
    .unwrap();
    let rel = "src/main/java/org/acme/App.java";
    std::fs::write(
        dir.path().join(rel),
        "package org.acme;\npublic class App {\n  void f(Req req) {\n    org.acme.web.Wrapper w = new org.acme.web.Wrapper(req);\n    sink(w.getTheParameter(\"q\"));\n  }\n}\n",
    )
    .unwrap();
    let r = super::tests_calls::rule(
        "Java",
        dir.path(),
        &["req.getParameter($K)"],
        &["sink($X)"],
        &[],
    );
    let lines: Vec<usize> = super::tests_calls::found(&r, dir.path(), rel)
        .iter()
        .map(|(l, _)| *l)
        .collect();
    assert_eq!(lines, [5]);
}

/// A call through an interface or abstract class reaches the one
/// implementation: the bodiless declaration does not make the name ambiguous.
#[test]
fn through_interface() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("A.java"),
        r#"interface Runner { void run(String cmd); }
class ShellRunner implements Runner {
  public void run(String cmd) { Runtime.getRuntime().exec(cmd); }
}
class A {
  void f(Req req, Runner r) {
    r.run(req.getParameter("c"));
  }
}
"#,
    )
    .unwrap();
    std::fs::write(
        dir.path().join("a.py"),
        r#"import abc, os
class Store(abc.ABC):
    @abc.abstractmethod
    def save(self, path):
        ...
class FileStore(Store):
    def save(self, path):
        open(path, 'w')
def view(req, store):
    store.save(req.GET['p'])
"#,
    )
    .unwrap();
    let lines = |lang: &str, rel: &str, source: &str, sink: &str| -> Vec<usize> {
        let r = super::tests_calls::rule(lang, dir.path(), &[source], &[sink], &[]);
        super::tests_calls::found(&r, dir.path(), rel)
            .iter()
            .map(|(l, _)| *l)
            .collect()
    };
    assert_eq!(
        lines(
            "Java",
            "A.java",
            "req.getParameter($K)",
            "Runtime.getRuntime().exec($X)"
        ),
        [7]
    );
    assert_eq!(lines("Python", "a.py", "req.GET", "open($X, $$$R)"), [10]);
}

/// Java: a field typed by an interface whose implementation lives in another
/// package and is never imported (Spring injects it).
#[test]
fn java_injected_implementation() {
    let dir = tempfile::tempdir().unwrap();
    let base = dir.path().join("src/main/java/org/acme");
    for d in ["service", "impl", "web"] {
        std::fs::create_dir_all(base.join(d)).unwrap();
    }
    std::fs::write(
        base.join("service/Fetcher.java"),
        "package org.acme.service;\npublic interface Fetcher {\n  String fetch(String url);\n}\n",
    )
    .unwrap();
    std::fs::write(
        base.join("impl/FetcherImpl.java"),
        "package org.acme.impl;\nimport org.acme.service.Fetcher;\npublic class FetcherImpl implements Fetcher {\n  public String fetch(String url) { return sink(url); }\n}\n",
    )
    .unwrap();
    let rel = "src/main/java/org/acme/web/App.java";
    std::fs::write(
        dir.path().join(rel),
        "package org.acme.web;\nimport org.acme.service.Fetcher;\npublic class App {\n  private Fetcher fetcher;\n  String f(Req req) {\n    return fetcher.fetch(req.getParameter(\"u\"));\n  }\n}\n",
    )
    .unwrap();
    let r = super::tests_calls::rule(
        "Java",
        dir.path(),
        &["req.getParameter($K)"],
        &["sink($X)"],
        &[],
    );
    let lines: Vec<usize> = super::tests_calls::found(&r, dir.path(), rel)
        .iter()
        .map(|(l, _)| *l)
        .collect();
    assert_eq!(lines, [6]);
}
