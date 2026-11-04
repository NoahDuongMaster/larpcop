//! Security rules: secrets, known vulnerabilities and malware (fake OSV.dev),
//! intraprocedural taint.

use crate::common::deps::{fake_api, fake_deps_dev, fake_osv as fake_osv_with, npm_lock, repo};
use crate::common::hook_input;
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

fn fake_osv() -> String {
    let mal = json!({ "id": "MAL-2026-1", "summary": "Malicious code in aaa-evil (npm)" });
    let high = json!({ "id": "GHSA-hhhh-0000-0000", "summary": "Prototype pollution in bbb-old",
        "database_specific": { "severity": "HIGH" },
        "affected": [{ "package": { "name": "bbb-old", "ecosystem": "npm" },
            "ranges": [{ "events": [{ "introduced": "0" }, { "fixed": "1.0.5" }] }] }] });
    // `aaa-evil@` is an install without a version.
    fake_osv_with(
        vec![
            ("aaa-evil@1.0.0", vec!["MAL-2026-1"]),
            ("aaa-evil@", vec!["MAL-2026-1"]),
            ("bbb-old@1.0.0", vec!["GHSA-hhhh-0000-0000"]),
        ],
        vec![
            ("MAL-2026-1", mal.to_string()),
            ("GHSA-hhhh-0000-0000", high.to_string()),
        ],
    )
}

#[test]
fn malware_always_blocks_vulnerabilities_block_new_versions() {
    let osv = fake_osv();
    let env = [("LARPCOP_OSV_API", osv.as_str())];
    let repo = repo("dependencies:\n  vulnerabilities: high\n");
    repo.write(
        "package-lock.json",
        &npm_lock(&[("aaa-evil", "1.0.0"), ("bbb-old", "1.0.0")]),
    );
    repo.commit_all("base");

    // Full audit: both, with the fixed version as the way out.
    let all = repo.run_env(&["check"], &env).stdout();
    assert!(
        all.contains("`aaa-evil@1.0.0` (npm) is a known MALICIOUS package (MAL-2026-1)"),
        "{all}"
    );
    assert!(
        all.contains("known High vulnerability GHSA-hhhh-0000-0000"),
        "{all}"
    );
    assert!(all.contains("Upgrade to a fixed version (1.0.5)"), "{all}");

    // A change that does not touch the lockfile: the old vulnerable pin is not
    // this change's doing, but malware reported since then still blocks.
    repo.write("a.txt", "x\n");
    let run = repo.run_env(&["check", "--changed"], &env);
    assert_eq!(run.code(), 1, "{}", run.stdout());
    assert!(
        run.stdout().contains("MALICIOUS") && !run.stdout().contains("GHSA"),
        "{}",
        run.stdout()
    );

    // Above the threshold only malware is left.
    repo.write(
        ".larpcop.yaml",
        "dependencies:\n  vulnerabilities: critical\n",
    );
    let crit = repo.run_env(&["check"], &env).stdout();
    assert!(
        crit.contains("MALICIOUS") && !crit.contains("GHSA"),
        "{crit}"
    );
}

#[test]
fn advisory_details_are_cached_until_osv_reports_an_edit() {
    let batch = |modified: &str| {
        json!({ "results": [{ "vulns": [{ "id": "GHSA-hhhh-0000-0000", "modified": modified }] }] })
            .to_string()
    };
    let advisory = |summary: &str| {
        json!({ "id": "GHSA-hhhh-0000-0000", "summary": summary,
            "database_specific": { "severity": "HIGH" } })
        .to_string()
    };
    let api = |modified: &str, summary: &str| {
        fake_deps_dev(vec![
            ("/v1/querybatch".into(), batch(modified)),
            ("/v1/vulns/GHSA-hhhh-0000-0000".into(), advisory(summary)),
        ])
        .replace("/v3", "/v1")
    };
    let repo = repo("dependencies:\n  vulnerabilities: high\n");
    repo.write("package-lock.json", &npm_lock(&[("bbb-old", "1.0.0")]));
    let check = |osv: &str| {
        // Each run asks OSV afresh: the advisory cache is what is under test, not the
        // few minutes lockfile scans remember OSV's answers.
        match std::fs::remove_dir_all(repo.path().join(".cache-larpcop/osv-query")) {
            Ok(()) => {}
            Err(e) => assert_eq!(e.kind(), std::io::ErrorKind::NotFound, "{e}"),
        }
        repo.run_env(&["check"], &[("LARPCOP_OSV_API", osv)])
            .stdout()
    };

    assert!(check(&api("2026-01-01T00:00:00Z", "First text")).contains("First text"));
    // Same `modified`: the cached copy, even though the server now says otherwise.
    assert!(check(&api("2026-01-01T00:00:00Z", "Second text")).contains("First text"));
    // Edited upstream: fetched again.
    assert!(check(&api("2026-02-01T00:00:00Z", "Second text")).contains("Second text"));
}

#[test]
fn lockfile_scans_reuse_osv_answers_for_a_few_minutes_but_installs_always_ask() {
    let asked = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&asked);
    let osv = fake_api(move |path, body| {
        if path != "/v1/querybatch" {
            return None;
        }
        counter.fetch_add(1, Ordering::SeqCst);
        let queries = serde_json::from_str::<serde_json::Value>(body).unwrap();
        let none = vec![json!({}); queries["queries"].as_array().unwrap().len()];
        Some(json!({ "results": none }).to_string())
    })
    .replace("/v3", "/v1");
    let env = [("LARPCOP_OSV_API", osv.as_str())];
    let repo = repo("dependencies:\n  vulnerabilities: high\n");
    repo.write("package-lock.json", &npm_lock(&[("bbb-old", "1.0.0")]));
    repo.commit_all("base");

    // Nothing changed between the runs: the second one needs no round trip.
    for _ in 0..2 {
        let run = repo.run_env(&["check", "--changed"], &env);
        assert_eq!(run.code(), 0, "{}", run.stdout());
    }
    assert_eq!(asked.load(Ordering::SeqCst), 1);

    // An install is vetted against what OSV says now, every time.
    let install = hook_input(
        "PreToolUse",
        "Bash",
        &repo.path(),
        json!({ "command": "npm i zod" }),
    );
    for expected in [2, 3] {
        let run = repo.run_stdin_env(&["hook", "claude-code"], &install, &env);
        assert_eq!(run.code(), 0, "{}", run.stderr());
        assert_eq!(asked.load(Ordering::SeqCst), expected);
    }
}

#[test]
fn installs_of_known_bad_packages_are_blocked_before_they_run() {
    let osv = fake_osv();
    let env = [("LARPCOP_OSV_API", osv.as_str())];
    let repo = repo("dependencies:\n  vulnerabilities: high\n");
    let input = |cmd: &str| {
        hook_input(
            "PreToolUse",
            "Bash",
            &repo.path(),
            json!({ "command": cmd }),
        )
    };
    let run = repo.run_stdin_env(
        &["hook", "claude-code"],
        &input("npm i aaa-evil && npm test"),
        &env,
    );
    assert_eq!(run.code(), 2, "{}", run.stderr());
    assert!(
        run.stderr()
            .contains("`aaa-evil` (npm): malicious advisory MAL-2026-1"),
        "{}",
        run.stderr()
    );
    // Unreachable OSV: the install is not vetted, so it does not run.
    let down = [("LARPCOP_OSV_API", "http://127.0.0.1:9/v1")];
    let run = repo.run_stdin_env(&["hook", "claude-code"], &input("npm i zod"), &down);
    assert_eq!(run.code(), 2, "{}", run.stderr());
    assert!(
        run.stderr().contains("could not check this install"),
        "{}",
        run.stderr()
    );
}

#[test]
fn secrets_are_reported_redacted() {
    let repo = repo("secrets: {}\n");
    let token = format!("ghp_{}", "x7Rk2mQ9vTz4LpW8sYb3NcD6fJh1Ga5Ue0Ki");
    repo.write("deploy.sh", &format!("export GH_TOKEN={token}\n"));
    repo.write("ok.sh", "export GH_TOKEN=\"$CI_TOKEN\"\n");
    let run = repo.run(&["check"]);
    let out = run.stdout();
    assert_eq!(run.code(), 1, "{out}");
    assert!(
        out.contains("deploy.sh") && out.contains("github-pat") && !out.contains("ok.sh"),
        "{out}"
    );
    assert!(
        !out.contains(&token[4..]) && out.contains("ghp_…[redacted]"),
        "{out}"
    );
}

#[test]
fn taint_rules_follow_request_data_through_variables() {
    let repo = repo(
        "taint:\n  - id: taint-sql\n    languages: [TypeScript]\n    message: Request data reaches SQL.\n    \
         sources: [\"req.query\"]\n    sinks: [\"$DB.query($SQL)\"]\n    sink_arg: SQL\n    sanitizers: [\"Number($X)\"]\n",
    );
    repo.write(
        "src/users.ts",
        "export async function list(req) {\n  const name = req.query.name;\n  const sql = \"select * from u where n = '\" + name + \"'\";\n  return db.query(sql);\n}\n\
         export async function one(req) {\n  const id = Number(req.query.id);\n  return db.query(\"select * from u where id = \" + id);\n}\n",
    );
    let run = repo.run(&["check", "--format", "json"]);
    let v: serde_json::Value = serde_json::from_str(&run.stdout()).unwrap();
    let hits: Vec<(String, u64)> = v["violations"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| {
            (
                x["rule"].as_str().unwrap().to_string(),
                x["line"].as_u64().unwrap(),
            )
        })
        .collect();
    assert_eq!(hits, [("taint-sql".to_string(), 4)], "{}", run.stdout());
}

#[test]
fn minified_bundles_are_only_searched_for_secrets() {
    let repo = repo(
        "secrets: {}\ntaint:\n  - id: taint-code\n    languages: [JavaScript]\n    message: Request data reaches eval.\n    \
         sources: [\"req.query\"]\n    sinks: [\"eval($X)\"]\n",
    );
    let token = format!("ghp_{}", "x7Rk2mQ9vTz4LpW8sYb3NcD6fJh1Ga5Ue0Ki");
    let body: String = (0..40)
        .map(|i| format!("function f{i}(req){{eval(req.query.c{i});}}"))
        .collect();
    repo.write(
        "public/libs/bundle.js",
        &format!("{body}\nvar t=\"{token}\";\n"),
    );
    repo.write("src/app.js", "function h(req) { eval(req.query.code); }\n");
    let run = repo.run(&["check"]);
    let out = run.stdout();
    assert!(
        out.contains("src/app.js") && out.contains("taint-code"),
        "{out}"
    );
    assert!(
        out.contains("bundle.js") && out.contains("github-pat"),
        "{out}"
    );
    assert_eq!(out.matches("taint-code").count(), 1, "{out}");
}
