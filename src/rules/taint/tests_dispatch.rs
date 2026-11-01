//! Which method a call on an object runs: the class it was built as, or
//! every implementation of the type it was declared with.

/// `Base b = new Bad(); b.action(x)`: the class the object is built as, when
/// several subclasses define the method differently.
#[test]
fn dispatch_on_constructed_class() {
    let java = "\
abstract class Base { abstract void action(String d); }
class Bad extends Base { void action(String d) { sink(d); } }
class Good extends Base { void action(String d) { sink(\"fixed\"); } }
class A {
  void f(Req req) {
    Base b = new Bad();
    b.action(req.getParameter(\"x\"));
    Base g = new Good();
    g.action(req.getParameter(\"x\"));
  }
}
";
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("A.java"), java).unwrap();
    let r = super::tests_calls::rule(
        "Java",
        dir.path(),
        &["req.getParameter($K)"],
        &["sink($X)"],
        &[],
    );
    let lines: Vec<usize> = super::tests_calls::found(&r, dir.path(), "A.java")
        .iter()
        .map(|(l, _)| *l)
        .collect();
    assert_eq!(lines, [7]);
}

/// A call on a name declared with an interface's type reaches what any
/// implementation does (class hierarchy), not one picked by name.
#[test]
fn calls_through_an_interface_reach_every_implementation() {
    let dir = tempfile::tempdir().unwrap();
    let w = |p: &str, s: &str| std::fs::write(dir.path().join(p), s).unwrap();
    w("Store.java", "interface Store { void save(String v); }\n");
    w(
        "DbStore.java",
        "class DbStore implements Store { public void save(String v) { db.query(\"INSERT \" + v); } }\n",
    );
    w(
        "MemStore.java",
        "class MemStore implements Store { public void save(String v) { cache.put(v); } }\n",
    );
    w("Log.java", "interface Log { void save(String v); }\n");
    w(
        "FileLog.java",
        "class FileLog implements Log { public void save(String v) { out.write(v); } }\n",
    );
    w(
        "C.java",
        "\
class C {
  private final Store store;
  private final Log log;
  void a(HttpServletRequest req) {
    store.save(req.getParameter(\"q\"));
  }
  void b(HttpServletRequest req, Store s) {
    s.save(req.getParameter(\"q\"));
    log.save(req.getParameter(\"q\"));
  }
}
",
    );
    let cfg = super::tests_support::guarded_config(
        "Java",
        &["$R.getParameter($K)"],
        &["db.query($X)"],
        &[],
        &[],
    );
    let rule = super::TaintRule::new(
        &cfg,
        super::typed::Typed::default(),
        dir.path().to_path_buf(),
    )
    .unwrap();
    let lines: Vec<usize> = super::tests_calls::found(&rule, dir.path(), "C.java")
        .iter()
        .map(|(l, _)| *l)
        .collect();
    assert_eq!(lines, [5, 8]);
}

/// C#'s `Base b = new Good()`: the class it was built as, not every
/// implementation of `Base`.
#[test]
fn csharp_dispatch_on_constructed_class() {
    let dir = tempfile::tempdir().unwrap();
    let w = |p: &str, s: &str| std::fs::write(dir.path().join(p), s).unwrap();
    w(
        "Base.cs",
        "abstract class Base { public abstract void Action(string v); }\n",
    );
    w(
        "Bad.cs",
        "class Bad : Base { public override void Action(string v) { db.query(\"x\" + v); } }\n",
    );
    w(
        "Good.cs",
        "class Good : Base { public override void Action(string v) { db.query(\"x\"); } }\n",
    );
    w(
        "C.cs",
        "\
class C {
  void A(HttpRequest req) {
    Base b = new Good();
    b.Action(req.Query[\"q\"]);
  }
  void B(HttpRequest req) {
    Base b = new Bad();
    b.Action(req.Query[\"q\"]);
  }
}
",
    );
    let cfg = super::tests_support::guarded_config(
        "CSharp",
        &["$R.Query[$K]"],
        &["db.query($X)"],
        &[],
        &[],
    );
    let rule = super::TaintRule::new(
        &cfg,
        super::typed::Typed::default(),
        dir.path().to_path_buf(),
    )
    .unwrap();
    let lines: Vec<usize> = super::tests_calls::found(&rule, dir.path(), "C.cs")
        .iter()
        .map(|(l, _)| *l)
        .collect();
    assert_eq!(lines, [8]);
}
