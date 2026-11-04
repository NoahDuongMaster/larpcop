//! Minimal LSP client: enough of the protocol to ask a project's own language
//! server (tsserver, pyright, gopls, rust-analyzer) what a name's type is.

use anyhow::{Context, Result};
use lsp_server::{Message, Notification, Request, RequestId, Response};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::BufReader;
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

/// A language server indexing a whole project can take a while to answer.
const TIMEOUT: Duration = if cfg!(test) {
    Duration::from_secs(2)
} else {
    Duration::from_secs(60)
};
/// Starting a server (an interpreter or a JVM coming up cold) is not a question: the
/// unit tests shorten `TIMEOUT` to see a hang quickly, not to rush the start.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(60);
/// Asking a server to leave must not wait as long as asking it a question.
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

/// The server answered a request with an error: it is still usable.
#[derive(Debug)]
struct Rejected(String);

impl std::fmt::Display for Rejected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Rejected {}

pub(super) struct Client {
    child: Child,
    stdin: ChildStdin,
    inbox: Receiver<Message>,
    next: i32,
    /// Documents the server holds: URI → (version, digest of its text).
    opened: HashMap<String, (i32, u64)>,
    /// The connection failed (no answer in time, a closed pipe): nothing more can be asked.
    broken: bool,
    /// rust-analyzer answers hovers with nothing until it has loaded the
    /// workspace; it says when it has (`experimental/serverStatus`).
    wait_for_quiescence: bool,
    quiescent: bool,
}

impl Client {
    pub(super) fn start(argv: &[String], root: &Path, wait_for_quiescence: bool) -> Result<Self> {
        let (bin, args) = argv
            .split_first()
            .context("empty language server command")?;
        let mut child = Command::new(crate::shell::which(bin))
            .args(args)
            .current_dir(root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("starting `{}`", argv.join(" ")))?;
        let stdin = child.stdin.take().context("stdin")?;
        let mut stdout = BufReader::new(child.stdout.take().context("stdout")?);
        let (tx, inbox) = channel();
        std::thread::spawn(move || {
            while let Ok(Some(msg)) = Message::read(&mut stdout) {
                if tx.send(msg).is_err() {
                    break;
                }
            }
        });
        let mut client = Self {
            child,
            stdin,
            inbox,
            next: 1,
            opened: HashMap::new(),
            // Until the handshake succeeded a server that fails to start is not waited for again.
            broken: true,
            wait_for_quiescence,
            quiescent: false,
        };
        let uri = url(root);
        client.request_within(
            "initialize",
            json!({
                "processId": std::process::id(),
                "rootUri": uri,
                "workspaceFolders": [{ "uri": uri, "name": "root" }],
                "capabilities": {
                    "textDocument": { "hover": { "contentFormat": ["plaintext", "markdown"] } },
                    "experimental": { "serverStatusNotification": true },
                },
                // typescript-language-server answers early requests from a syntax-only
                // server (`import pool`, `any`); the semantic one waits for the project.
                "initializationOptions": { "tsserver": { "useSyntaxServer": "never" } },
            }),
            STARTUP_TIMEOUT,
        )?;
        client.notify("initialized", json!({}))?;
        client.broken = false;
        Ok(client)
    }

    /// Hover text at a 0-based position; the document is sent first (unsaved content counts).
    /// An error that is not the server's answer to this question marks the client broken.
    pub(super) fn hover(
        &mut self,
        path: &Path,
        language_id: &str,
        text: &str,
        line: usize,
        character: usize,
    ) -> Result<Option<String>> {
        let asked = self.ask_hover(path, language_id, text, line, character);
        if let Err(e) = &asked
            && e.downcast_ref::<Rejected>().is_none()
        {
            self.broken = true;
        }
        asked
    }

    /// Nothing can be asked of this server any more.
    pub(super) fn broken(&self) -> bool {
        self.broken
    }

    fn ask_hover(
        &mut self,
        path: &Path,
        language_id: &str,
        text: &str,
        line: usize,
        character: usize,
    ) -> Result<Option<String>> {
        while self.wait_for_quiescence && !self.quiescent {
            let msg = self
                .inbox
                .recv_timeout(TIMEOUT)
                .context("language server never got ready")?;
            self.handle(msg)?;
        }
        let uri = url(path);
        let digest = super::digest(text);
        // The server holds the text it was last sent: a changed document (an editor
        // buffer, a file edited between two questions) is sent again, or the
        // answers would be about the old text.
        match self.opened.get(&uri).copied() {
            None => {
                let doc =
                    json!({ "uri": uri, "languageId": language_id, "version": 1, "text": text });
                self.notify("textDocument/didOpen", json!({ "textDocument": doc }))?;
                self.opened.insert(uri.clone(), (1, digest));
            }
            Some((version, held)) if held != digest => {
                let doc = json!({ "uri": uri, "version": version + 1 });
                let params = json!({ "textDocument": doc, "contentChanges": [{ "text": text }] });
                self.notify("textDocument/didChange", params)?;
                self.opened.insert(uri.clone(), (version + 1, digest));
            }
            Some(_) => {}
        }
        let pos = json!({ "textDocument": { "uri": uri }, "position": { "line": line, "character": character } });
        let result = self.request("textDocument/hover", pos)?;
        Ok(hover_text(&result))
    }

    fn notify(&mut self, method: &str, params: Value) -> Result<()> {
        Message::Notification(Notification::new(method.into(), params)).write(&mut self.stdin)?;
        Ok(())
    }

    fn request(&mut self, method: &str, params: Value) -> Result<Value> {
        self.request_within(method, params, TIMEOUT)
    }

    /// Sends a request and waits for its response, answering the server's own
    /// requests (configuration, progress) with empty results meanwhile.
    fn request_within(&mut self, method: &str, params: Value, timeout: Duration) -> Result<Value> {
        let id = RequestId::from(self.next);
        self.next += 1;
        Message::Request(Request::new(id.clone(), method.into(), params)).write(&mut self.stdin)?;
        loop {
            match self
                .inbox
                .recv_timeout(timeout)
                .context("language server did not answer")?
            {
                Message::Response(r) if r.id == id => {
                    return r
                        .response_result
                        .map_err(|e| Rejected(format!("{method}: {}", e.message)).into());
                }
                other => self.handle(other)?,
            }
        }
    }

    /// Answers the server's own requests (configuration, progress) with empty
    /// results and notes when it reports being idle.
    fn handle(&mut self, msg: Message) -> Result<()> {
        match msg {
            Message::Request(r) => {
                let empty = if r.method == "workspace/configuration" {
                    json!([])
                } else {
                    Value::Null
                };
                Message::Response(Response::new_ok(r.id, empty)).write(&mut self.stdin)?;
            }
            Message::Notification(n) if n.method == "experimental/serverStatus" => {
                self.quiescent |= n.params["quiescent"].as_bool() == Some(true);
            }
            _ => {}
        }
        Ok(())
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        // A broken server gets no handshake: it would only be waited for.
        if !self.broken {
            let _ = self.request_within("shutdown", Value::Null, SHUTDOWN_TIMEOUT);
            let _ = self.notify("exit", Value::Null);
        }
        let _ = self.child.kill();
        // Reaps the process: a long-lived `lsp`/`mcp` run drops clients that went bad.
        let _ = self.child.wait();
    }
}

fn url(path: &Path) -> String {
    let p = path.to_string_lossy().replace('\\', "/");
    let p = if p.starts_with('/') {
        p
    } else {
        format!("/{p}")
    };
    format!("file://{}", percent_encoding::utf8_percent_encode(&p, PATH))
}

const PATH: &percent_encoding::AsciiSet = &percent_encoding::CONTROLS
    .add(b' ')
    .add(b'#')
    .add(b'%')
    .add(b'?');

/// `contents` may be a string, `{kind, value}`, or a list of marked strings.
fn hover_text(result: &Value) -> Option<String> {
    let c = &result["contents"];
    let text = match c {
        Value::String(s) => s.clone(),
        Value::Array(parts) => parts
            .iter()
            .filter_map(|p| p.as_str().or_else(|| p["value"].as_str()))
            .collect::<Vec<_>>()
            .join("\n"),
        _ => c["value"].as_str()?.to_string(),
    };
    (!text.trim().is_empty()).then_some(text)
}

#[cfg(test)]
mod tests {
    #[test]
    fn hover_shapes() {
        let md = serde_json::json!({ "contents": { "kind": "markdown", "value": "```ts\nconst pool: Pool\n```" } });
        assert!(super::hover_text(&md).unwrap().contains("Pool"));
        let list =
            serde_json::json!({ "contents": [{ "language": "go", "value": "var db *sql.DB" }] });
        assert_eq!(super::hover_text(&list).unwrap(), "var db *sql.DB");
        assert!(super::hover_text(&serde_json::Value::Null).is_none());
        assert!(super::url(std::path::Path::new("/a b/c.ts")).ends_with("/a%20b/c.ts"));
    }
}
