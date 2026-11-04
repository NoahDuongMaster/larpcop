//! `fix`, `baseline` and `test`.

use crate::common::*;

const VAR_RULE: &str = r#"id: no-var
language: TypeScript
severity: error
message: "`var` is function-scoped."
rule:
  pattern: var $NAME = $VALUE
# The match spans the `;`, so the fix restores it (ast-grep semantics).
fix: let $NAME = $VALUE;
"#;

fn repo_with_rule() -> Repo {
    let repo = Repo::new();
    repo.write(".larpcop.yaml", "rule_dirs: [rules]\n");
    repo.write("rules/no-var.yml", VAR_RULE);
    repo
}

#[test]
fn fix_applies_rule_fixes_and_reports_what_is_left() {
    let repo = repo_with_rule();
    repo.write("src/a.ts", "var a = 1;\nvar b = a + 1;\nexport { a, b };\n");

    let check = repo.run(&["check"]);
    assert_eq!(check.code(), 1);
    assert!(
        check.stdout().contains("larpcop fix src/a.ts"),
        "{}",
        check.stdout()
    );

    let dry = repo.run(&["fix", "--dry-run"]);
    assert_eq!(dry.code(), 1);
    assert!(dry.stdout().contains("would fix src/a.ts (2 fix(es))"));
    assert!(repo.read("src/a.ts").starts_with("var a"));

    let fix = repo.run(&["fix"]);
    assert_eq!(fix.code(), 0, "{}", fix.stdout());
    assert_eq!(
        repo.read("src/a.ts"),
        "let a = 1;\nlet b = a + 1;\nexport { a, b };\n"
    );
    assert!(fix.stdout().contains("no violations"));
}

#[test]
fn baseline_hides_known_violations_only() {
    let repo = repo_with_rule();
    repo.write("src/old.ts", "var legacy = 1;\nexport { legacy };\n");
    assert_eq!(repo.run(&["baseline"]).code(), 0);
    repo.commit_all("adopt no-var with a baseline");

    let clean = repo.run(&["check"]);
    assert_eq!(clean.code(), 0, "{}", clean.stdout());
    assert!(clean.stdout().contains("1 known violation(s) hidden"));

    // Edits above the known violation move it; it stays hidden. A new one fails.
    repo.write(
        "src/old.ts",
        "// header\nvar legacy = 1;\nvar fresh = 2;\nexport { legacy, fresh };\n",
    );
    let out = repo.run(&["check"]);
    assert_eq!(out.code(), 1);
    assert!(
        out.stdout().contains("3:1") && !out.stdout().contains("2:1"),
        "{}",
        out.stdout()
    );

    // Fixing the legacy one and pruning shrinks the baseline; nothing is added.
    repo.write(
        "src/old.ts",
        "let legacy = 1;\nvar fresh = 2;\nexport { legacy, fresh };\n",
    );
    assert_eq!(repo.run(&["baseline", "--prune"]).code(), 0);
    assert!(!repo.read(".larpcop-baseline.json").contains("legacy"));
    assert_eq!(repo.run(&["check"]).code(), 1);
}

#[test]
fn baseline_cannot_grow_for_a_locked_rule() {
    let repo = Repo::with_standards();
    repo.write("src/old.ts", "export const a: any = 1;\n");
    assert_eq!(repo.run(&["baseline"]).code(), 0);
    repo.commit_all("baseline legacy any");
    assert_eq!(repo.run(&["check", "--changed"]).code(), 0);

    // Re-baselining to hide a new violation of a locked rule is caught.
    repo.write("src/new.ts", "export const b: any = 2;\n");
    assert_eq!(repo.run(&["baseline"]).code(), 0);
    let out = repo.run(&["check", "--changed"]);
    assert_eq!(out.code(), 1, "{}", out.stdout());
    assert!(
        out.stdout()
            .contains("the baseline grew for `no-explicit-any`")
    );
}

#[test]
fn rule_tests_report_wrong_matches_and_fixes() {
    let repo = repo_with_rule();
    repo.write(
        "rule-tests/no-var-test.yml",
        "id: no-var\nvalid:\n  - let a = 1\ninvalid:\n  - var a = 1\nfixed:\n  - before: var a = 1;\n    after: let a = 1;\n",
    );
    let ok = repo.run(&["test", "--require-all"]);
    assert_eq!(ok.code(), 0, "{}", ok.stdout());
    assert!(ok.stdout().contains("✓ no-var"));

    repo.write(
        "rule-tests/no-var-test.yml",
        "id: no-var\nvalid:\n  - var a = 1\ninvalid:\n  - const a = 1\nfixed:\n  - before: var a = 1;\n    after: const a = 1;\n",
    );
    let bad = repo.run(&["test"]);
    assert_eq!(bad.code(), 1);
    let out = bad.stdout();
    assert!(out.contains("3 of 3 case(s) failed"), "{out}");
    assert!(out.contains("invalid but not reported: `const a = 1`"));
    assert!(out.contains("valid but reported: `var a = 1`"));
    assert!(out.contains("fix of `var a = 1;` gave `let a = 1;`, expected `const a = 1;`"));

    repo.write("rules/no-let.yml", &VAR_RULE.replace("no-var", "no-let"));
    let strict = repo.run(&["test", "--require-all"]);
    assert!(strict.stdout().contains("untested rule(s): no-let"));
}

#[test]
fn agents_cannot_rebaseline_or_edit_the_baseline() {
    let repo = repo_with_rule();
    let dir = repo.path();
    for cmd in [
        "larpcop baseline",
        "bash -c 'larpcop baseline'",
        "echo '{}' > .larpcop-baseline.json",
    ] {
        let input = hook_input(
            "PreToolUse",
            "Bash",
            &dir,
            serde_json::json!({ "command": cmd }),
        );
        let out = repo.run_stdin(&["hook", "claude"], &input);
        assert_eq!(out.code(), 2, "{cmd}: {}", out.stdout());
    }
    let input = hook_input(
        "PreToolUse",
        "Write",
        &dir,
        serde_json::json!({ "file_path": dir.join(".larpcop-baseline.json"), "content": "{}" }),
    );
    assert_eq!(repo.run_stdin(&["hook", "claude"], &input).code(), 2);
}

#[test]
fn a_corrupt_baseline_at_the_base_commit_is_an_error_not_an_empty_one() {
    let repo = Repo::with_standards();
    repo.write("src/old.ts", "export const a: any = 1;\n");
    repo.write(".larpcop-baseline.json", "{ not json");
    repo.commit_all("corrupt baseline");
    repo.write(".larpcop-baseline.json", "{\"version\":1,\"entries\":[]}\n");
    let out = repo.run(&["check", "--changed"]);
    assert_eq!(out.code(), 3, "{}{}", out.stdout(), out.stderr());
    assert!(
        out.stderr().contains("at the base commit"),
        "{}",
        out.stderr()
    );
}
