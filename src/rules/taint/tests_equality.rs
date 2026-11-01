//! Equality with a string literal as a guard (equality.rs); what a check
//! pins down and what it does not.

use super::tests_calls::{found, guarded};
use super::tests_support::guarded_config;
use super::*;
use crate::config::TaintConfig;

#[test]
fn equality_with_a_literal_pins_the_value() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("up.php"),
        "\
<?php
$ext = $_GET['ext'];
if ((strtolower($ext) == 'jpg' || strtolower($ext) == 'png') && $size < 100) {
    echo $ext;
}
if (substr($ext, 0, 1) == 'j') {
    echo $ext;
}
if ($ext == 'png' || $other == 'x') {
    echo $ext;
}
if ($ext != 'png') {
    exit;
}
echo $ext;
",
    )
    .unwrap();
    let cfg = TaintConfig {
        source_names: vec!["$_GET".into()],
        ..guarded_config("Php", &[], &["echo $X"], &[], &[])
    };
    let r = TaintRule::new(&cfg, typed::Typed::default(), dir.path().to_path_buf()).unwrap();
    let lines = |r: &TaintRule, f: &str| -> Vec<usize> {
        found(r, dir.path(), f)
            .into_iter()
            .map(|(l, _)| l)
            .collect()
    };
    // A prefix check is not equality; `|| $other == 'x'` does not pin `$ext`.
    assert_eq!(lines(&r, "up.php"), [7, 10]);

    std::fs::write(
        dir.path().join("a.py"),
        "\
def a():
    kind = request.args.get('kind')
    if kind.lower() == 'csv' or kind.lower() == 'tsv':
        os.system('export ' + kind)
    if kind == 'all':
        os.system('export ' + kind)
    if kind != '':
        os.system('export ' + kind)
",
    )
    .unwrap();
    let r = guarded(
        "Python",
        dir.path(),
        &["request.args.get($$$A)"],
        &["os.system($X)"],
        &[],
        &[],
    );
    // `!= ''` only says it is not empty.
    assert_eq!(lines(&r, "a.py"), [8]);
}

#[test]
fn a_check_pins_values_built_only_from_what_it_checks() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("up.php"),
        "\
<?php
$name = $_GET['f'];
$ext = substr($name, strrpos($name, '.') + 1);
$random = bin2hex(random_bytes(16)) . '.' . $ext;
$target = $random;
$mixed = $_GET['dir'] . '/' . $ext;
$copy = $name . $ext;
if (strtolower($ext) == 'jpg' || strtolower($ext) == 'png') {
    echo $target;
    echo $mixed;
    echo $copy;
}
",
    )
    .unwrap();
    let cfg = TaintConfig {
        source_names: vec!["$_GET".into()],
        ..guarded_config("Php", &[], &["echo $X"], &[], &[])
    };
    let r = TaintRule::new(&cfg, typed::Typed::default(), dir.path().to_path_buf()).unwrap();
    let lines: Vec<usize> = found(&r, dir.path(), "up.php")
        .into_iter()
        .map(|(l, _)| l)
        .collect();
    // `$mixed` also holds `$_GET['dir']`, `$copy` the unchecked `$name`.
    assert_eq!(lines, [10, 11]);
}

#[test]
fn searching_a_call_result_says_nothing_of_its_arguments() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("a.py"),
        "\
def a():
    param = ''
    for name in request.form.keys():
        if 'Bench' in request.form.getlist(name):
            param = name
            break
    bar = param
    os.system(bar)
    path = request.args.get('p')
    if '..' in path:
        return
    os.system(path)
",
    )
    .unwrap();
    let cfg = TaintConfig {
        rejects: vec!["\"$S\" in $P".into(), "'$S' in $P".into()],
        ..guarded_config(
            "Python",
            &["request.form", "request.args"],
            &["os.system($X)"],
            &[],
            &[],
        )
    };
    let r = TaintRule::new(&cfg, typed::Typed::default(), dir.path().to_path_buf()).unwrap();
    let lines: Vec<usize> = found(&r, dir.path(), "a.py")
        .into_iter()
        .map(|(l, _)| l)
        .collect();
    // `'..' in path` failing does clean `path`.
    assert_eq!(lines, [8]);
}
