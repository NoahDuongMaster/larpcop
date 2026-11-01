//! Sinks found by more than one pattern; values placed into HTML markup.

use super::tests_calls::found;
use super::tests_support::guarded_config;
use super::*;
use crate::config::TaintConfig;
use std::collections::BTreeMap;

#[test]
fn an_untyped_pattern_of_the_same_sink_wins() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("T.java"),
        "\
class T {
    void a(HttpServletRequest request) {
        System.loadLibrary(request.getParameter(\"lib\"));
        Loader.loadLibrary(request.getParameter(\"lib\"));
    }
}
",
    )
    .unwrap();
    let cfg = guarded_config(
        "Java",
        &["request.getParameter($K)"],
        &["$RT.loadLibrary($X)", "System.loadLibrary($X)"],
        &[],
        &[],
    );
    let types = BTreeMap::from([("RT".to_string(), "^Runtime$".to_string())]);
    let typed = typed::Typed::new("t", &types, dir.path().to_path_buf(), BTreeMap::new()).unwrap();
    let r = TaintRule::new(&cfg, typed, dir.path().to_path_buf()).unwrap();
    let lines: Vec<usize> = found(&r, dir.path(), "T.java")
        .into_iter()
        .map(|(l, _)| l)
        .collect();
    // `Loader` is not a `Runtime`; `System.loadLibrary` is a sink by its own pattern.
    assert_eq!(lines, [3]);
}

#[test]
fn values_placed_into_markup() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("low.php"),
        "\
<?php
$name = $_GET['name'];
$html .= '<pre>Hello ' . $name . '</pre>';
$html .= \"<tr><td>{$name}</td></tr>\";
$html .= '<pre>' . htmlspecialchars($name) . '</pre>';
$query = \"SELECT * FROM users WHERE name = '$name'\";
$html = '<p>' . count($rows) . '</p>';
$less = $name . ' < 3';
",
    )
    .unwrap();
    // Superglobals are names, not patterns (`$_GET` alone is a metavariable).
    let cfg = TaintConfig {
        html_fragments: true,
        source_names: vec!["$_GET".into()],
        ..guarded_config("Php", &[], &["echo $X"], &["htmlspecialchars($X)"], &[])
    };
    let r = TaintRule::new(&cfg, typed::Typed::default(), dir.path().to_path_buf()).unwrap();
    let lines: Vec<usize> = found(&r, dir.path(), "low.php")
        .into_iter()
        .map(|(l, _)| l)
        .collect();
    assert_eq!(lines, [3, 4]);
}
