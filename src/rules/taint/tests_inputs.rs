//! A file whose import closure takes no input is not summarized (inputs.rs):
//! the findings stay those of summarizing everything, down to the import
//! depth at which files stop being followed.

use super::tests_support::{found, guarded_config};
use super::*;
use crate::config::TaintConfig;
use std::path::Path;

fn write(dir: &Path, files: &[(&str, &str)]) {
    for (rel, text) in files {
        let path = dir.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }
}

fn python(dir: &Path, cfg: TaintConfig) -> TaintRule {
    let cfg = TaintConfig {
        sources: vec!["request.args".into()],
        sinks: vec!["$C.execute($X)".into()],
        languages: vec!["Python".into()],
        ..cfg
    };
    TaintRule::new(&cfg, typed::Typed::default(), dir.to_path_buf()).unwrap()
}

fn plain(dir: &Path) -> TaintRule {
    python(dir, guarded_config("Python", &[], &[], &[], &[]))
}

fn lines(r: &TaintRule, dir: &Path, rel: &str) -> Vec<usize> {
    found(r, dir, rel).into_iter().map(|(l, _)| l).collect()
}

/// `c0.py` calls what `c1.py` returns, and so on down to `c{n}.py`, which
/// returns request data.
fn chain(dir: &Path, n: usize) {
    for i in 0..n {
        let text = format!(
            "from .c{next} import f{next}\n\ndef f{i}():\n    return f{next}()\n\ndef v{i}():\n    cursor.execute(f{next}())\n",
            next = i + 1
        );
        write(dir, &[(&format!("p/c{i}.py"), &text)]);
    }
    let last = format!("def f{n}():\n    return request.args.get('x')\n");
    write(
        dir,
        &[(&format!("p/c{n}.py"), &last), ("p/__init__.py", "")],
    );
}

#[test]
fn a_source_down_the_import_chain_reaches_a_sink_at_the_top() {
    let dir = tempfile::tempdir().unwrap();
    // c0 is the file checked; c4 is the fourth import down, the last followed.
    chain(dir.path(), 4);
    assert_eq!(lines(&plain(dir.path()), dir.path(), "p/c0.py"), [7]);
}

#[test]
fn a_source_past_the_import_depth_is_not_followed() {
    let dir = tempfile::tempdir().unwrap();
    chain(dir.path(), 5);
    let r = plain(dir.path());
    assert_eq!(lines(&r, dir.path(), "p/c0.py"), Vec::<usize>::new());
    assert!(!r.takes_input(&dir.path().join("p/c1.py"), reach::IMPORT_DEPTH - 1));
    // Checked itself, the file one level up from the source finds it.
    assert_eq!(lines(&r, dir.path(), "p/c1.py"), [7]);
}

/// `a.py` calls `g` of `b.py`, which calls `h` of `c.py`, whose text is `c`.
fn three(dir: &Path, c: &str) {
    write(
        dir,
        &[
            ("p/__init__.py", ""),
            (
                "p/a.py",
                "from .b import g\n\ndef v(x):\n    cursor.execute(g(x))\n",
            ),
            ("p/b.py", "from .c import h\n\ndef g(x):\n    return h(x)\n"),
            ("p/c.py", c),
        ],
    );
}

#[test]
fn imports_that_take_no_input_are_not_summarized() {
    let dir = tempfile::tempdir().unwrap();
    three(
        dir.path(),
        "def h(x):\n    cursor.execute(x)\n    return [x]\n",
    );
    let r = plain(dir.path());
    let top = |rel: &str| r.takes_input(&dir.path().join(rel), reach::IMPORT_DEPTH - 1);
    assert!(!top("p/b.py") && !top("p/c.py"));
    assert_eq!(lines(&r, dir.path(), "p/a.py"), Vec::<usize>::new());
}

#[test]
fn a_source_in_the_last_import_is_found_from_the_first() {
    let dir = tempfile::tempdir().unwrap();
    three(
        dir.path(),
        "def h(x):\n    cursor.execute(x)\n    return request.args\n",
    );
    let r = plain(dir.path());
    assert!(r.takes_input(&dir.path().join("p/b.py"), reach::IMPORT_DEPTH - 1));
    assert_eq!(lines(&r, dir.path(), "p/a.py"), [4]);
}

#[test]
fn a_route_handler_in_an_import_takes_input_but_a_plain_decorator_does_not() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        &[
            ("p/__init__.py", ""),
            (
                "p/a.py",
                "from .routes import page\nfrom .tools import cached\n\ndef v():\n    cursor.execute(page(1))\n    cursor.execute(cached(1))\n",
            ),
            (
                "p/routes.py",
                "@app.get('/p')\ndef page(q):\n    return q\n",
            ),
            (
                "p/tools.py",
                "import functools\n\n@functools.cache\ndef cached(q):\n    return [q][0]\n",
            ),
        ],
    );
    let cfg = TaintConfig {
        handler_decorators: Some(r"^\w+\.(get|post)\(".into()),
        ..guarded_config("Python", &[], &[], &[], &[])
    };
    let r = python(dir.path(), cfg);
    let at = |rel: &str| r.takes_input(&dir.path().join(rel), 0);
    assert!(at("p/routes.py"));
    assert!(!at("p/tools.py"));
    // The handler's parameter comes back from `page(1)`; `cached` has none.
    assert_eq!(lines(&r, dir.path(), "p/a.py"), [5]);
}

#[test]
fn a_name_that_is_a_source_in_an_import_takes_input() {
    let dir = tempfile::tempdir().unwrap();
    write(
        dir.path(),
        &[
            (
                "a.php",
                "<?php\nrequire 'b.php';\nfunction v() {\n    echo h();\n}\n",
            ),
            (
                "b.php",
                "<?php\nfunction h() {\n    return $_GET['x'];\n}\n",
            ),
            (
                "c.php",
                "<?php\nfunction h() {\n    return $_SERVER['argv'];\n}\n",
            ),
        ],
    );
    let cfg = TaintConfig {
        source_names: vec!["$_GET".into()],
        ..guarded_config("Php", &[], &["echo $X"], &[], &[])
    };
    let r = TaintRule::new(&cfg, typed::Typed::default(), dir.path().to_path_buf()).unwrap();
    assert!(r.takes_input(&dir.path().join("b.php"), 0));
    assert!(!r.takes_input(&dir.path().join("c.php"), 0));
    assert_eq!(lines(&r, dir.path(), "a.php"), [4]);
}

#[test]
fn a_resolver_taking_its_arguments_as_a_pattern_in_an_import_takes_input() {
    let dir = tempfile::tempdir().unwrap();
    // Nothing in `b.js` spells `args`, `info`, a decorator or a source.
    write(
        dir.path(),
        &[
            (
                "a.js",
                "import { user } from './b';\nfunction v() {\n  db.query(user());\n}\n",
            ),
            ("b.js", "export const user = (parent, { id }) => id;\n"),
            ("c.js", "export const user = (parent, other) => other;\n"),
        ],
    );
    let cfg = TaintConfig {
        resolver_args: true,
        sources: vec!["req.query".into()],
        sinks: vec!["$D.query($X)".into()],
        ..guarded_config("JavaScript", &[], &[], &[], &[])
    };
    let r = TaintRule::new(&cfg, typed::Typed::default(), dir.path().to_path_buf()).unwrap();
    assert!(r.takes_input(&dir.path().join("b.js"), 0));
    assert!(!r.takes_input(&dir.path().join("c.js"), 0));
    assert_eq!(lines(&r, dir.path(), "a.js"), [3]);
}
