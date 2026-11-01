//! Mapped collections: `map`/`Select`/`array_map` carry what the callback
//! returns.

use super::*;

/// What a mapped collection holds is what its callback returns, in every
/// language: escaped elements are clean, raw ones are not.
#[test]
fn mapped_collections_in_every_language() {
    let java = "\
class A {
  void f(HttpServletRequest req) {
    List<String> xs = Arrays.asList(req.getParameterValues(\"q\"));
    sink(xs.stream().map(x -> esc(x)).collect(toList()));
    sink(xs.stream().map(x -> { String y = esc(x); return y; }).collect(toList()));
    sink(xs.stream().map(Encode::esc).collect(toList()));
    sink(xs.stream().map(x -> { String y = x.trim(); return y; }).collect(toList()));
    sink(xs.stream().map(String::trim).collect(toList()));
  }
}
";
    let found = |lang: &str, rel: &str, src: &str, source: &str| {
        let cfg = super::tests_support::guarded_config(
            lang,
            &[source],
            &["sink($X)"],
            &["esc($X)", "Encode.esc($X)"],
            &[],
        );
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(rel), src).unwrap();
        let rule = TaintRule::new(&cfg, typed::Typed::default(), dir.path().to_path_buf()).unwrap();
        super::tests_calls::found(&rule, dir.path(), rel)
            .iter()
            .map(|(l, _)| *l)
            .collect::<Vec<_>>()
    };
    assert_eq!(
        found("Java", "A.java", java, "$R.getParameterValues($K)"),
        [7, 8]
    );
    let kt = "\
fun f(req: HttpServletRequest) {
    val xs = req.getParameterValues(\"q\").toList()
    sink(xs.map { esc(it) })
    sink(xs.map { x -> val y = esc(x); y })
    sink(xs.map(::esc))
    sink(xs.map { it.trim() })
}
";
    assert_eq!(
        found("Kotlin", "A.kt", kt, "$R.getParameterValues($K)"),
        [6]
    );
    let cs = "\
class A {
  void F(HttpRequest req) {
    var xs = req.Query[\"q\"];
    sink(xs.Select(x => esc(x)));
    sink(xs.Select(x => { var y = esc(x); return y; }));
    sink(xs.Select(x => { var y = x; if (y.Length > 3) { y = esc(x); } return y; }));
  }
}
";
    assert_eq!(found("CSharp", "A.cs", cs, "$R.Query[$K]"), [6]);
    let py = "\
def f(request):
    xs = request.args.getlist('q')
    sink(list(map(lambda x: esc(x), xs)))
    sink(list(map(esc, xs)))
    sink(list(map(str.strip, xs)))
";
    assert_eq!(found("Python", "a.py", py, "request.args.getlist($K)"), [5]);
    let php = "\
<?php
$xs = $_GET['q'];
sink(array_map(fn($x) => esc($x), $xs));
sink(array_map('esc', $xs));
sink(array_map('trim', $xs));
";
    assert_eq!(found("Php", "a.php", php, "$_GET[$K]"), [5]);
}
