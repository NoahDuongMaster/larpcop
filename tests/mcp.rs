//! `agentkit mcp` spoken to over stdio, as an MCP client would.

mod common;

use common::*;
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

struct Client {
    child: std::process::Child,
    out: BufReader<std::process::ChildStdout>,
    next_id: u64,
}

impl Client {
    fn start(repo: &Repo) -> Self {
        let mut child = Command::new(BIN)
            .args(["mcp"])
            .current_dir(repo.path())
            .env("AGENTKIT_CACHE_DIR", repo.path().join(".cache-agentkit"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let out = BufReader::new(child.stdout.take().unwrap());
        let mut c = Self {
            child,
            out,
            next_id: 0,
        };
        let init = c.call(
            "initialize",
            json!({ "protocolVersion": "2025-06-18", "capabilities": {},
                    "clientInfo": { "name": "test", "version": "0" } }),
        );
        assert_eq!(init["serverInfo"]["name"], "agentkit", "{init}");
        c.send(json!({ "jsonrpc": "2.0", "method": "notifications/initialized" }));
        c
    }

    fn send(&mut self, msg: Value) {
        let stdin = self.child.stdin.as_mut().unwrap();
        writeln!(stdin, "{msg}").unwrap();
        stdin.flush().unwrap();
    }

    fn call(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        self.send(json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }));
        loop {
            let mut line = String::new();
            assert!(self.out.read_line(&mut line).unwrap() > 0, "server closed");
            let msg: Value = serde_json::from_str(&line).unwrap();
            if msg["id"] == id {
                return msg.get("result").cloned().unwrap_or(msg);
            }
        }
    }

    fn tool(&mut self, name: &str, args: Value) -> String {
        let r = self.call("tools/call", json!({ "name": name, "arguments": args }));
        r["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .to_string()
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

#[test]
fn mcp_serves_rules_per_file_and_checks_content_before_writing() {
    let repo = Repo::with_standards();
    repo.write("src/bad.ts", BAD_TS);
    let mut mcp = Client::start(&repo);

    let tools = mcp.call("tools/list", json!({}));
    let names: Vec<&str> = tools["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    for t in ["rules_for", "check_content", "check", "fix", "explain_rule"] {
        assert!(names.contains(&t), "{names:?}");
    }

    // Only the TypeScript rules for a .ts file; only the Python ones for .py.
    let ts = mcp.tool("rules_for", json!({ "path": "src/app.ts" }));
    assert!(
        ts.contains("no-explicit-any") && ts.contains("[locked]"),
        "{ts}"
    );
    assert!(!ts.contains("py-no-bare-except"));
    let py = mcp.tool("rules_for", json!({ "path": "tools/x.py" }));
    assert!(
        py.contains("py-no-bare-except") && !py.contains("no-explicit-any"),
        "{py}"
    );

    let draft = mcp.tool(
        "check_content",
        json!({ "path": "src/new.ts", "content": BAD_TS }),
    );
    assert!(
        draft.contains("no-console") && draft.contains("no-explicit-any"),
        "{draft}"
    );
    let clean = mcp.tool(
        "check_content",
        json!({ "path": "src/new.ts", "content": GOOD_TS }),
    );
    assert!(clean.contains("no violations"), "{clean}");
    assert!(!repo.path().join("src/new.ts").exists());
    // Regression (live run): a file in a directory that does not exist yet was skipped.
    let py = mcp.tool(
        "check_content",
        json!({ "path": "tools/new/x.py", "content": "print(1)\n" }),
    );
    assert!(py.contains("py-no-print"), "{py}");

    let on_disk = mcp.tool("check", json!({ "paths": ["src/bad.ts"] }));
    assert!(on_disk.contains("2 error(s)"), "{on_disk}");
    let explained = mcp.tool("explain_rule", json!({ "id": "no-explicit-any" }));
    assert!(explained.contains("How to comply"), "{explained}");
}
