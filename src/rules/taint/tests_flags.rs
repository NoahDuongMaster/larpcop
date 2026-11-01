//! A flag parameter picking the branch a call takes (flags.rs).

use super::TaintRule;
use super::tests_support::{found, guarded_config};

#[test]
fn literal_flags_pick_the_branch() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("a.py"),
        "def run(cmd, safe=True):
    if not safe:
        return os.system(cmd)
    return os.system(shlex.quote(cmd))

def a(request):
    run(request.args['c'])

def b(request):
    run(request.args['c'], False)

def c(request):
    run(request.args['c'], True)

def d(request, flag):
    run(request.args['c'], flag)
",
    )
    .unwrap();
    let cfg = guarded_config(
        "Python",
        &["request.args"],
        &["os.system($X)"],
        &["shlex.quote($X)"],
        &[],
    );
    let r = TaintRule::new(
        &cfg,
        super::typed::Typed::default(),
        dir.path().to_path_buf(),
    )
    .unwrap();
    let lines: Vec<usize> = found(&r, dir.path(), "a.py")
        .iter()
        .map(|(l, _)| *l)
        .collect();
    // `safe=False` and a flag of unknown value reach `os.system(cmd)`.
    assert_eq!(lines, [10, 16]);
}
