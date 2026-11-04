//! `larpcop lsp` spoken to over stdio, as an editor would.

use crate::common::*;
use serde_json::{Value, json};
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

/// `file:///home/x` on Unix, `file:///C:/Users/x` on Windows.
fn file_uri(path: &std::path::Path) -> String {
    let p = path.display().to_string().replace('\\', "/");
    if p.starts_with('/') {
        format!("file://{p}")
    } else {
        format!("file:///{p}")
    }
}

struct Editor {
    child: Child,
    stdin: ChildStdin,
    inbox: Receiver<Value>,
    next_id: u64,
}

impl Editor {
    fn start(repo: &Repo) -> Self {
        let mut child = Command::new(BIN)
            .args(["lsp"])
            .current_dir(repo.path())
            .env("LARPCOP_CACHE_DIR", repo.path().join(".cache-larpcop"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let mut out = BufReader::new(child.stdout.take().unwrap());
        let (tx, inbox) = channel();
        std::thread::spawn(move || {
            loop {
                let mut length = 0;
                loop {
                    let mut line = String::new();
                    if out.read_line(&mut line).unwrap_or(0) == 0 {
                        return;
                    }
                    match line.trim().split_once(':') {
                        Some(("Content-Length", n)) => length = n.trim().parse().unwrap(),
                        _ if line.trim().is_empty() => break,
                        _ => {}
                    }
                }
                let mut body = vec![0; length];
                out.read_exact(&mut body).unwrap();
                if tx.send(serde_json::from_slice(&body).unwrap()).is_err() {
                    return;
                }
            }
        });
        let mut editor = Self {
            child,
            stdin,
            inbox,
            next_id: 0,
        };
        let uri = file_uri(&repo.path());
        let init = editor.call("initialize", json!({ "rootUri": uri, "capabilities": {} }));
        assert!(init["result"]["capabilities"].is_object(), "{init}");
        editor.notify("initialized", json!({}));
        editor
    }

    fn send(&mut self, msg: Value) {
        let body = msg.to_string();
        write!(self.stdin, "Content-Length: {}\r\n\r\n{body}", body.len()).unwrap();
        self.stdin.flush().unwrap();
    }

    fn notify(&mut self, method: &str, params: Value) {
        self.send(json!({ "jsonrpc": "2.0", "method": method, "params": params }));
    }

    /// Sends a request; returns its response and every notification that came before it.
    fn call_seen(&mut self, method: &str, params: Value) -> (Value, Vec<Value>) {
        self.next_id += 1;
        let id = self.next_id;
        self.send(json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }));
        let mut seen = Vec::new();
        loop {
            let msg = self.next();
            if msg["id"] == id {
                return (msg, seen);
            }
            seen.push(msg);
        }
    }

    fn call(&mut self, method: &str, params: Value) -> Value {
        self.call_seen(method, params).0
    }

    fn next(&mut self) -> Value {
        self.inbox
            .recv_timeout(Duration::from_secs(30))
            .expect("the language server did not answer")
    }

    /// Next `textDocument/publishDiagnostics`, with the messages that came first.
    fn next_publish(&mut self) -> (Value, Vec<Value>) {
        let mut others = Vec::new();
        loop {
            let msg = self.next();
            if msg["method"] == "textDocument/publishDiagnostics" {
                return (msg, others);
            }
            others.push(msg);
        }
    }

    fn diagnostics(&mut self) -> (Vec<Value>, Vec<Value>) {
        let (msg, others) = self.next_publish();
        (
            msg["params"]["diagnostics"].as_array().unwrap().clone(),
            others,
        )
    }

    fn open(&mut self, uri: &str, text: &str) {
        let doc = json!({ "uri": uri, "languageId": "typescript", "version": 1, "text": text });
        self.notify("textDocument/didOpen", json!({ "textDocument": doc }));
    }

    fn change(&mut self, uri: &str, text: &str) {
        self.notify(
            "textDocument/didChange",
            json!({ "textDocument": { "uri": uri, "version": 2 }, "contentChanges": [{ "text": text }] }),
        );
    }

    fn code_action(&mut self, uri: &str) -> Value {
        let range =
            json!({ "start": { "line": 0, "character": 0 }, "end": { "line": 0, "character": 0 } });
        self.call(
            "textDocument/codeAction",
            json!({ "textDocument": { "uri": uri }, "range": range, "context": { "diagnostics": [] } }),
        )
    }
}

impl Drop for Editor {
    fn drop(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

fn codes(diagnostics: &[Value]) -> Vec<&str> {
    diagnostics
        .iter()
        .filter_map(|d| d["code"].as_str())
        .collect()
}

#[test]
fn diagnostics_follow_the_text_and_an_unchanged_save_is_not_checked_again() {
    let repo = Repo::with_standards();
    repo.write("src/a.ts", BAD_TS);
    let uri = file_uri(&repo.path().join("src/a.ts"));
    let mut editor = Editor::start(&repo);

    editor.open(&uri, BAD_TS);
    let (found, _) = editor.diagnostics();
    assert!(codes(&found).contains(&"no-explicit-any"), "{found:?}");
    editor.change(&uri, GOOD_TS);
    assert_eq!(editor.diagnostics().0.len(), 0);

    // Saving what was just checked publishes nothing: the next thing published is
    // the document opened after the save (documents are checked in the order they changed).
    let other = file_uri(&repo.path().join("src/b.ts"));
    editor.notify(
        "textDocument/didSave",
        json!({ "textDocument": { "uri": uri } }),
    );
    editor.open(&other, BAD_TS);
    let (next, _) = editor.next_publish();
    assert_eq!(next["params"]["uri"], other.as_str(), "{next}");
}

#[test]
fn a_check_that_cannot_run_says_so_instead_of_looking_clean() {
    let repo = Repo::with_standards();
    repo.write("src/a.ts", BAD_TS);
    let good_config = repo.read(".larpcop.yaml");
    let uri = file_uri(&repo.path().join("src/a.ts"));
    let mut editor = Editor::start(&repo);
    editor.open(&uri, BAD_TS);
    assert!(!editor.diagnostics().0.is_empty());

    repo.write(".larpcop.yaml", "extends: [./missing]\n");
    editor.change(&uri, &format!("{BAD_TS}// edited\n"));
    let (found, others) = editor.diagnostics();
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0]["severity"], 1);
    assert!(
        found[0]["message"]
            .as_str()
            .unwrap()
            .contains("cannot check this file"),
        "{found:?}"
    );
    let shown: Vec<_> = others
        .iter()
        .filter(|m| m["method"] == "window/showMessage")
        .collect();
    assert_eq!(shown.len(), 1, "{others:?}");
    assert!(
        shown[0]["params"]["message"]
            .as_str()
            .unwrap()
            .contains("missing")
    );
    // A code action that cannot be computed is an error response, not an empty list.
    let action = editor.code_action(&uri);
    assert!(
        action["error"]["message"]
            .as_str()
            .unwrap()
            .contains("cannot fix"),
        "{action}"
    );

    // The config is fixed: the next change is checked under the new rules.
    repo.write(".larpcop.yaml", &good_config);
    editor.change(&uri, &format!("{BAD_TS}// edited again\n"));
    let (found, _) = editor.diagnostics();
    assert!(codes(&found).contains(&"no-explicit-any"), "{found:?}");
}
