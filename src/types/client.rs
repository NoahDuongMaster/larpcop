//! Minimal LSP client: enough of the protocol to ask a project's own language
//! server (tsserver, pyright, gopls, rust-analyzer) what a name's type is.

use anyhow::{Context, Result};
use lsp_server::{Message, Notification, Request, RequestId, Response};
use serde_json::{Value, json};
use std::io::BufReader;
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{Receiver, channel};
use std::time::Duration;

/// A language server indexing a whole project can take a while to answer.
const TIMEOUT: Duration = Duration::from_secs(60);

pub(super) struct Client {
    child: Child,
    stdin: ChildStdin,
    inbox: Receiver<Message>,
    next: i32,
    opened: std::collections::HashSet<String>,
}

impl Client {
    pub(super) fn start(argv: &[String], root: &Path) -> Result<Self> {
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
            opened: Default::default(),
        };
        let uri = url(root);
        client.request(
            "initialize",
            json!({
                "processId": std::process::id(),
                "rootUri": uri,
                "workspaceFolders": [{ "uri": uri, "name": "root" }],
                "capabilities": { "textDocument": { "hover": { "contentFormat": ["plaintext", "markdown"] } } },
                // typescript-language-server answers early requests from a syntax-only
                // server (`import pool`, `any`); the semantic one waits for the project.
                "initializationOptions": { "tsserver": { "useSyntaxServer": "never" } },
            }),
        )?;
        client.notify("initialized", json!({}))?;
        Ok(client)
    }

    /// Hover text at a 0-based position; the document is sent first (unsaved content counts).
    pub(super) fn hover(
        &mut self,
        path: &Path,
        language_id: &str,
        text: &str,
        line: usize,
        character: usize,
    ) -> Result<Option<String>> {
        let uri = url(path);
        if self.opened.insert(uri.clone()) {
            let doc = json!({ "uri": uri, "languageId": language_id, "version": 1, "text": text });
            self.notify("textDocument/didOpen", json!({ "textDocument": doc }))?;
        }
        let pos = json!({ "textDocument": { "uri": uri }, "position": { "line": line, "character": character } });
        let result = self.request("textDocument/hover", pos)?;
        Ok(hover_text(&result))
    }

    fn notify(&mut self, method: &str, params: Value) -> Result<()> {
        Message::Notification(Notification::new(method.into(), params)).write(&mut self.stdin)?;
        Ok(())
    }

    /// Sends a request and waits for its response, answering the server's own
    /// requests (configuration, progress) with empty results meanwhile.
    fn request(&mut self, method: &str, params: Value) -> Result<Value> {
        let id = RequestId::from(self.next);
        self.next += 1;
        Message::Request(Request::new(id.clone(), method.into(), params)).write(&mut self.stdin)?;
        loop {
            match self
                .inbox
                .recv_timeout(TIMEOUT)
                .context("language server did not answer")?
            {
                Message::Response(r) if r.id == id => {
                    return r
                        .response_result
                        .map_err(|e| anyhow::anyhow!("{method}: {}", e.message));
                }
                Message::Request(r) => {
                    let empty = if r.method == "workspace/configuration" {
                        json!([])
                    } else {
                        Value::Null
                    };
                    Message::Response(Response::new_ok(r.id, empty)).write(&mut self.stdin)?;
                }
                _ => {}
            }
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.request("shutdown", Value::Null);
        let _ = self.notify("exit", Value::Null);
        let _ = self.child.kill();
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
