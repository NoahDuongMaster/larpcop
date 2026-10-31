//! AI review and rule learning, against a fake model CLI (a shell script).

mod common;

use common::Repo;
use std::fs;
use std::path::Path;

/// Forward slashes: the fake model runs under `sh`, also on Windows.
fn sh_path(p: &Path) -> String {
    p.display().to_string().replace('\\', "/")
}

/// A model that answers with the files `answers/1`, `answers/2`… in turn and
/// logs one line per call in `calls`.
fn fake_model(dir: &Path, answers: &[&str]) -> String {
    fs::create_dir_all(dir.join("answers")).unwrap();
    for (i, a) in answers.iter().enumerate() {
        fs::write(dir.join("answers").join((i + 1).to_string()), a).unwrap();
    }
    let d = sh_path(dir);
    format!(
        "cat > '{d}/last-prompt'; echo x >> '{d}/calls'; n=$(wc -l < '{d}/calls' | tr -d ' '); \
         [ -f '{d}/answers/'$n ] || n={}; cat '{d}/answers/'$n",
        answers.len()
    )
}

fn calls(dir: &Path) -> usize {
    fs::read_to_string(dir.join("calls")).map_or(0, |c| c.lines().count())
}

fn yaml_str(s: &str) -> String {
    serde_json::to_string(s).unwrap()
}

#[test]
fn review_reports_changed_lines_as_warnings_and_caches_answers() {
    let model = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let answer = r#"Findings:
```json
[{"rule": "thin-controllers", "line": 2, "message": "Queries the database directly; call UserService."},
 {"rule": "thin-controllers", "line": 1, "message": "Unchanged line."},
 {"rule": "made-up", "line": 2, "message": "Not a configured rule."}]
```"#;
    let repo = Repo::new();
    repo.write(
        ".agentkit.yaml",
        &format!(
            "llm:\n  command: {}\n  rules:\n    - id: thin-controllers\n      files: [\"src/controllers/**\"]\n      \
             prompt: Controllers call services, never the database.\n",
            yaml_str(&fake_model(model.path(), &[answer]))
        ),
    );
    repo.write("src/controllers/user.ts", "export function a() {}\n");
    repo.write("src/db.ts", "export const db = {};\n");
    repo.commit_all("base");
    repo.write(
        "src/controllers/user.ts",
        "export function a() {}\nexport const b = () => db.query('select 1');\n",
    );
    repo.write("src/db.ts", "export const db = { x: 1 };\n");

    let env = [("AGENTKIT_CACHE_DIR", cache.path().to_str().unwrap())];
    let run = repo.run_env(&["review", "--changed"], &env);
    let out = run.stdout();
    assert_eq!(run.code(), 0, "{out}{}", run.stderr());
    assert!(
        out.contains("2:1") && out.contains("Queries the database directly"),
        "{out}"
    );
    assert!(
        !out.contains("Unchanged line") && !out.contains("made-up"),
        "{out}"
    );
    // Only the file a rule applies to was sent, with its changed line marked.
    assert_eq!(calls(model.path()), 1);
    let prompt = fs::read_to_string(model.path().join("last-prompt")).unwrap();
    assert!(
        prompt.contains(">    2 | export const b") && prompt.contains("     1 | export function a"),
        "{prompt}"
    );

    let again = repo.run_env(&["review", "--changed"], &env).stdout();
    assert!(again.contains("Queries the database directly"), "{again}");
    assert_eq!(
        calls(model.path()),
        1,
        "an unchanged file is answered from the cache"
    );
    repo.run_env(&["review", "--changed", "--no-cache"], &env);
    assert_eq!(calls(model.path()), 2);
}

const BAD: &str = r#"[{"id": "no-lodash", "language": "TypeScript", "severity": "error",
  "message": "Use native methods instead of lodash.", "note": "Array and Object methods cover it.",
  "rule": {"pattern": "import $X from 'lodash'"},
  "valid": ["import { map } from 'remeda'"],
  "invalid": ["import _ from 'lodash'", "const _ = require('lodash')"]}]"#;

const GOOD: &str = r#"[{"id": "no-lodash", "languages": ["TypeScript", "JavaScript"], "severity": "error",
  "message": "Use native methods instead of lodash.", "note": "Array and Object methods cover it.",
  "rule": {"any": [{"pattern": "import $X from 'lodash'"}, {"pattern": "require('lodash')"}]},
  "valid": ["import { map } from 'remeda'", "import x from 'lodash-es-free'"],
  "invalid": ["import _ from 'lodash'", "const _ = require('lodash')"]}]"#;

#[test]
fn learn_keeps_only_rules_that_pass_their_tests_after_feedback() {
    let model = tempfile::tempdir().unwrap();
    let cache = tempfile::tempdir().unwrap();
    let repo = Repo::new();
    repo.write(
        ".agentkit.yaml",
        &format!(
            "llm:\n  command: {}\n",
            yaml_str(&fake_model(model.path(), &[BAD, GOOD]))
        ),
    );
    repo.write(
        "src/a.ts",
        "const _ = require('lodash');\nexport const f = _.map;\n",
    );
    let env = [("AGENTKIT_CACHE_DIR", cache.path().to_str().unwrap())];
    let run = repo.run_env(&["learn", "never use lodash"], &env);
    let out = run.stdout();
    assert_eq!(run.code(), 0, "{out}{}", run.stderr());
    assert!(
        out.contains("✓ no-lodash") && out.contains("4 test case(s), 1 existing violation(s)"),
        "{out}"
    );
    assert_eq!(
        calls(model.path()),
        2,
        "the failing proposal went back to the model once"
    );
    let retry = fs::read_to_string(model.path().join("last-prompt")).unwrap();
    assert!(
        retry.contains("invalid but not reported: `const _ = require('lodash')`"),
        "{retry}"
    );

    // The written rule works as a normal rule of the repository.
    assert!(
        repo.read(".agentkit/rule-tests/no-lodash-test.yml")
            .contains("remeda")
    );
    // One id, one document per language.
    let rule = repo.read(".agentkit/rules/no-lodash.yml");
    assert_eq!(rule.matches("id: no-lodash").count(), 2, "{rule}");
    repo.write("src/b.js", "const _ = require('lodash');\n");
    repo.write(".agentkit.yaml", "rule_dirs: [.agentkit/rules]\n");
    assert_eq!(repo.run(&["test", "--require-all"]).code(), 0);
    let check = repo.run(&["check"]).stdout();
    assert!(
        check.contains("src/a.ts") && check.contains("src/b.js"),
        "{check}"
    );
}
