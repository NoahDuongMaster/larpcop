//! Security rules: secrets, known vulnerabilities and malware (fake OSV.dev),
//! intraprocedural taint.

mod common;

use common::deps::{fake_deps_dev, npm_lock, repo};
use common::hook_input;
use serde_json::json;

fn fake_osv() -> String {
    let batch = json!({ "results": [
        { "vulns": [{ "id": "MAL-2026-1" }] },
        { "vulns": [{ "id": "GHSA-hhhh-0000-0000" }] },
    ]});
    let mal = json!({ "id": "MAL-2026-1", "summary": "Malicious code in aaa-evil (npm)" });
    let high = json!({ "id": "GHSA-hhhh-0000-0000", "summary": "Prototype pollution in bbb-old",
        "database_specific": { "severity": "HIGH" },
        "affected": [{ "package": { "name": "bbb-old", "ecosystem": "npm" },
            "ranges": [{ "events": [{ "introduced": "0" }, { "fixed": "1.0.5" }] }] }] });
    let api = fake_deps_dev(vec![
        ("/v1/querybatch".into(), batch.to_string()),
        ("/v1/vulns/MAL-2026-1".into(), mal.to_string()),
        ("/v1/vulns/GHSA-hhhh-0000-0000".into(), high.to_string()),
    ]);
    api.replace("/v3", "/v1")
}

#[test]
fn malware_always_blocks_vulnerabilities_block_new_versions() {
    let osv = fake_osv();
    let env = [("AGENTKIT_OSV_API", osv.as_str())];
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
        ".agentkit.yaml",
        "dependencies:\n  vulnerabilities: critical\n",
    );
    let crit = repo.run_env(&["check"], &env).stdout();
    assert!(
        crit.contains("MALICIOUS") && !crit.contains("GHSA"),
        "{crit}"
    );
}

#[test]
fn installs_of_known_bad_packages_are_blocked_before_they_run() {
    let osv = fake_osv();
    let env = [("AGENTKIT_OSV_API", osv.as_str())];
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
    let down = [("AGENTKIT_OSV_API", "http://127.0.0.1:9/v1")];
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
