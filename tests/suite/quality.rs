//! Sonar/Codacy replacements: CI report formats, function metrics, the LSP server.

use crate::common::*;
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

#[test]
fn ci_formats_carry_every_finding() {
    let repo = Repo::with_standards();
    repo.write("src/bad.ts", BAD_TS);
    let out = repo.run(&[
        "check",
        "--output",
        "sarif=r.sarif",
        "--output",
        "gitlab=gl.json",
        "--output",
        "markdown=pr.md",
    ]);
    assert_eq!(out.code(), 1);
    let sarif: Value = serde_json::from_str(&repo.read("r.sarif")).unwrap();
    let run = &sarif["runs"][0];
    assert_eq!(sarif["version"], "2.1.0");
    assert_eq!(run["results"].as_array().unwrap().len(), 2);
    assert_eq!(
        run["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"],
        1
    );
    let gitlab: Value = serde_json::from_str(&repo.read("gl.json")).unwrap();
    assert_eq!(gitlab[0]["location"]["path"], "src/bad.ts");
    assert_ne!(gitlab[0]["fingerprint"], gitlab[1]["fingerprint"]);
    let md = repo.read("pr.md");
    assert!(
        md.starts_with("<!-- larpcop-report -->") && md.contains("| `no-console` | 1 |"),
        "{md}"
    );
}

#[test]
fn metrics_rules_limit_complexity_and_length() {
    let repo = Repo::new();
    repo.write(
        ".larpcop.yaml",
        "metrics:\n  max_complexity: 3\n  max_function_lines: 5\n",
    );
    repo.write(
        "src/a.ts",
        "export function busy(x: number) {\n  if (x > 1) { return 1; }\n  if (x > 2) { return 2; }\n  \
if (x > 3) { return 3; }\n  return 0;\n}\nexport const ok = (y: number) => y + 1;\n",
    );
    let out = repo.run(&["check"]);
    assert_eq!(out.code(), 1);
    let text = out.stdout();
    assert!(
        text.contains("`busy` has cyclomatic complexity 4 (max 3)"),
        "{text}"
    );
    assert!(text.contains("`busy` is 6 lines long (max 5)"), "{text}");
    assert!(!text.contains("`ok`"));
    let metrics = repo.run(&["metrics", "--json"]);
    let m: Value = serde_json::from_str(&metrics.stdout()).unwrap();
    assert_eq!(
        (
            m["functions"].as_u64(),
            m["most_complex"][0]["name"].as_str()
        ),
        (Some(2), Some("busy"))
    );
}

fn send(stdin: &mut impl Write, msg: Value) {
    let body = msg.to_string();
    write!(stdin, "Content-Length: {}\r\n\r\n{body}", body.len()).unwrap();
    stdin.flush().unwrap();
}

fn recv(out: &mut impl BufRead) -> Value {
    let mut len = 0;
    loop {
        let mut line = String::new();
        out.read_line(&mut line).unwrap();
        if let Some(n) = line.strip_prefix("Content-Length: ") {
            len = n.trim().parse().unwrap();
        } else if line == "\r\n" {
            break;
        }
    }
    let mut body = vec![0; len];
    out.read_exact(&mut body).unwrap();
    serde_json::from_slice(&body).unwrap()
}

/// Next message with this method or id, skipping the rest.
fn wait(out: &mut impl BufRead, pred: impl Fn(&Value) -> bool) -> Value {
    loop {
        let m = recv(out);
        if pred(&m) {
            return m;
        }
    }
}

#[test]
fn lsp_publishes_diagnostics_and_offers_fixes() {
    let repo = Repo::new();
    repo.write(".larpcop.yaml", "rule_dirs: [rules]\n");
    repo.write(
        "rules/no-var.yml",
        "id: no-var\nlanguage: TypeScript\nseverity: error\nmessage: no var\nrule:\n  pattern: var $N = $V\nfix: let $N = $V;\n",
    );
    let mut child = Command::new(BIN)
        .arg("lsp")
        .current_dir(repo.path())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut out = BufReader::new(child.stdout.take().unwrap());
    let root = format!("file://{}", repo.path().display()).replace('\\', "/");
    let uri = format!("{root}/src/a.ts");
    send(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": { "rootUri": root, "capabilities": {} } }),
    );
    let init = wait(&mut out, |m| m["id"] == 1);
    assert_eq!(init["result"]["capabilities"]["codeActionProvider"], true);
    send(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "method": "initialized", "params": {} }),
    );
    send(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "method": "textDocument/didOpen", "params": {
        "textDocument": { "uri": uri, "languageId": "typescript", "version": 1, "text": "var a = 1;\n" } } }),
    );
    let diag = wait(&mut out, |m| {
        m["method"] == "textDocument/publishDiagnostics"
    });
    let d = &diag["params"]["diagnostics"][0];
    assert_eq!(
        (d["code"].as_str(), d["source"].as_str()),
        (Some("no-var"), Some("larpcop"))
    );
    assert_eq!(d["range"]["start"], json!({ "line": 0, "character": 0 }));

    send(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "id": 2, "method": "textDocument/codeAction", "params": {
        "textDocument": { "uri": uri }, "range": d["range"], "context": { "diagnostics": [d] } } }),
    );
    let actions = wait(&mut out, |m| m["id"] == 2);
    let edit = &actions["result"][0]["edit"]["changes"][&uri][0];
    assert_eq!(edit["newText"], "let a = 1;\n");

    send(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "method": "textDocument/didChange", "params": {
        "textDocument": { "uri": uri, "version": 2 }, "contentChanges": [{ "text": "let a = 1;\n" }] } }),
    );
    let clean = wait(&mut out, |m| {
        m["method"] == "textDocument/publishDiagnostics"
    });
    assert_eq!(clean["params"]["diagnostics"], json!([]));
    // Regression (real Neovim run): a malformed request killed the server.
    send(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "id": 9, "method": "textDocument/codeAction",
                "params": { "textDocument": { "uri": uri } } }),
    );
    let err = wait(&mut out, |m| m["id"] == 9);
    assert_eq!(err["error"]["code"], -32602);
    send(
        &mut stdin,
        json!({ "jsonrpc": "2.0", "id": 3, "method": "shutdown" }),
    );
    wait(&mut out, |m| m["id"] == 3);
    send(&mut stdin, json!({ "jsonrpc": "2.0", "method": "exit" }));
    assert!(child.wait().unwrap().success());
}

/// The official rule set ships only rules whose fixtures pass.
#[test]
fn recommended_rules_all_have_passing_fixtures() {
    let repo = Repo::new();
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/standards/recommended");
    let out = repo.run(&["test", dir, "--require-all"]);
    assert_eq!(out.code(), 0, "{}{}", out.stdout(), out.stderr());
    assert!(!out.stdout().contains("untested"));
}
