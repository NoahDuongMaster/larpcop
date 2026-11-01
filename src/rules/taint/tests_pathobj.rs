//! Path objects used on the file system (pathobj.rs).

use super::tests_calls::found;
use super::tests_support::guarded_config;
use super::*;
use crate::config::{PathObjectsConfig, TaintConfig};

const VIEWS: &str = "\
BASE = pathlib.Path('/srv/files')

def a():
    base = pathlib.Path(DIR)
    p = base / request.args['f']
    if p.exists():
        return 'yes'

def b():
    return Report.objects.filter(name=request.args['f']).exists()

def c():
    p = (BASE / request.args['f']).resolve()
    if not p.is_relative_to(BASE):
        return None
    return p.read_text()

def d():
    return (BASE / request.args['f']).read_text()

def e(root: Path):
    return root.joinpath(request.args['f']).parent.read_bytes()

def f():
    name = request.args['f']
    return (BASE / 'fixed.txt').read_text() + name
";

#[test]
fn path_objects_used_on_the_file_system() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("views.py"), VIEWS).unwrap();
    let cfg = TaintConfig {
        path_objects: Some(PathObjectsConfig {
            types: r"^(pathlib\.)?Path$".into(),
            uses: "^(exists|read_text|read_bytes|open|unlink)$".into(),
        }),
        ..guarded_config(
            "Python",
            &["request.args"],
            &["open($X)"],
            &[],
            &["$X.is_relative_to($B)"],
        )
    };
    let r = TaintRule::new(&cfg, typed::Typed::default(), dir.path().to_path_buf()).unwrap();
    let lines: Vec<usize> = found(&r, dir.path(), "views.py")
        .into_iter()
        .map(|(l, _)| l)
        .collect();
    // b: a queryset's `exists()`; c: checked after the join; f: a fixed path.
    assert_eq!(lines, [6, 19, 22]);
}
