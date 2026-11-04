//! Type questions against a scripted language server (a few lines of Python
//! speaking LSP), so no real server needs to be installed.

use super::hover;
use ast_grep_language::SupportLang;
use std::collections::BTreeMap;
use std::path::Path;
use std::time::{Duration, Instant};

/// Answers hovers with the first line of the document it holds; `hang…` documents
/// are never answered and `reject…` documents get an error response.
const SERVER: &str = r#"
import json, sys
docs = {}
def read():
    headers = {}
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            return None
        line = line.decode().strip()
        if not line:
            break
        key, value = line.split(":", 1)
        headers[key.lower()] = value.strip()
    return json.loads(sys.stdin.buffer.read(int(headers["content-length"])))
def send(msg):
    body = json.dumps(msg).encode()
    sys.stdout.buffer.write(b"Content-Length: %d\r\n\r\n" % len(body) + body)
    sys.stdout.buffer.flush()
while True:
    m = read()
    if m is None:
        break
    method = m.get("method")
    if method == "initialize":
        send({"jsonrpc": "2.0", "id": m["id"], "result": {"capabilities": {}}})
    elif method == "textDocument/didOpen":
        d = m["params"]["textDocument"]
        docs[d["uri"]] = d["text"]
    elif method == "textDocument/didChange":
        docs[m["params"]["textDocument"]["uri"]] = m["params"]["contentChanges"][0]["text"]
    elif method == "textDocument/hover":
        text = docs.get(m["params"]["textDocument"]["uri"], "")
        if text.startswith("hang"):
            continue
        if text.startswith("reject"):
            send({"jsonrpc": "2.0", "id": m["id"], "error": {"code": -32603, "message": "no project"}})
            continue
        send({"jsonrpc": "2.0", "id": m["id"], "result": {"contents": {"kind": "plaintext", "value": text.splitlines()[0]}}})
    elif method == "shutdown":
        send({"jsonrpc": "2.0", "id": m["id"], "result": None})
    elif method == "exit":
        break
"#;

/// A project directory and the `language_servers` override that runs the script
/// there; `None` when there is no Python to run it.
fn project() -> Option<(tempfile::TempDir, BTreeMap<String, Vec<String>>)> {
    let python = std::process::Command::new("python3")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !python {
        eprintln!("skipped: no python3");
        return None;
    }
    let tmp = tempfile::tempdir().unwrap();
    let script = tmp.path().join("server.py");
    std::fs::write(&script, SERVER).unwrap();
    let argv = vec!["python3".to_string(), script.display().to_string()];
    Some((tmp, BTreeMap::from([("typescript".to_string(), argv)])))
}

fn ask(root: &Path, servers: &BTreeMap<String, Vec<String>>, text: &str) -> Option<String> {
    hover(root, servers, SupportLang::TypeScript, "a.ts", text, (0, 0))
}

#[test]
fn a_changed_document_is_sent_again() {
    let Some((tmp, servers)) = project() else {
        return;
    };
    assert_eq!(
        ask(tmp.path(), &servers, "const a: A\n").as_deref(),
        Some("const a: A")
    );
    // The long-lived `lsp` and `mcp` processes see the same file again with other text.
    assert_eq!(
        ask(tmp.path(), &servers, "const a: B\n").as_deref(),
        Some("const a: B")
    );
    assert_eq!(
        ask(tmp.path(), &servers, "const a: A\n").as_deref(),
        Some("const a: A")
    );
}

#[test]
fn a_rejected_question_leaves_the_server_usable() {
    let Some((tmp, servers)) = project() else {
        return;
    };
    assert_eq!(ask(tmp.path(), &servers, "reject\n"), None);
    assert_eq!(ask(tmp.path(), &servers, "fine\n").as_deref(), Some("fine"));
}

#[test]
fn a_server_that_stops_answering_is_asked_once() {
    let Some((tmp, servers)) = project() else {
        return;
    };
    assert_eq!(ask(tmp.path(), &servers, "ok\n").as_deref(), Some("ok"));
    // The timeout of the unit tests is two seconds, that of a real run sixty.
    assert_eq!(ask(tmp.path(), &servers, "hang\n"), None);
    let again = Instant::now();
    assert_eq!(ask(tmp.path(), &servers, "ok again\n"), None);
    assert!(
        again.elapsed() < Duration::from_millis(500),
        "{:?}",
        again.elapsed()
    );
}

#[test]
fn a_slow_server_does_not_hold_up_other_projects() {
    let (Some((slow, servers)), Some((quick, other))) = (project(), project()) else {
        return;
    };
    assert_eq!(ask(slow.path(), &servers, "ok\n").as_deref(), Some("ok"));
    assert_eq!(ask(quick.path(), &other, "ok\n").as_deref(), Some("ok"));
    std::thread::scope(|scope| {
        scope.spawn(|| ask(slow.path(), &servers, "hang\n"));
        std::thread::sleep(Duration::from_millis(300));
        let started = Instant::now();
        assert_eq!(
            ask(quick.path(), &other, "other project\n").as_deref(),
            Some("other project")
        );
        assert!(
            started.elapsed() < Duration::from_millis(1000),
            "{:?}",
            started.elapsed()
        );
    });
}

#[test]
fn a_server_that_cannot_start_gives_no_answer() {
    let tmp = tempfile::tempdir().unwrap();
    let servers = BTreeMap::from([(
        "typescript".to_string(),
        vec!["larpcop-no-such-language-server".to_string()],
    )]);
    assert_eq!(ask(tmp.path(), &servers, "ok\n"), None);
}
