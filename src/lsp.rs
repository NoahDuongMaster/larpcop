//! `larpcop lsp`: the same rules as diagnostics while typing, in any editor
//! with LSP support, plus a code action that applies the rules' fixes.

mod workspace;

use crate::rules::{Level, Violation};
use anyhow::{Context, Result};
use lsp_server::{Connection, ErrorCode, Message, Notification, Request, Response};
use lsp_types::notification::{
    DidChangeTextDocument, DidCloseTextDocument, DidOpenTextDocument, DidSaveTextDocument,
    Notification as _, PublishDiagnostics, ShowMessage,
};
use lsp_types::request::{CodeActionRequest, Request as _};
use lsp_types::{
    CodeAction, CodeActionKind, CodeActionOrCommand, CodeActionParams, Diagnostic,
    DiagnosticSeverity, MessageType, NumberOrString, Position, PublishDiagnosticsParams, Range,
    ServerCapabilities, ShowMessageParams, TextDocumentSyncCapability, TextDocumentSyncKind,
    TextEdit, Uri, WorkspaceEdit,
};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::str::FromStr;
use workspace::Workspace;

struct Server {
    conn: Connection,
    ws: Workspace,
    docs: HashMap<String, String>,
    /// (digest of the text, fingerprint of the project) each document was last
    /// checked under: the same text under the same rules gives the same answer.
    checked: HashMap<String, (u64, u64)>,
    /// The last problem shown to the user, so that one broken file does not
    /// repeat it at every keystroke.
    shown: Option<String>,
}

pub fn serve(dir: PathBuf, extends: Vec<String>) -> Result<()> {
    let (conn, io) = Connection::stdio();
    let caps = ServerCapabilities {
        text_document_sync: Some(TextDocumentSyncCapability::Kind(TextDocumentSyncKind::FULL)),
        code_action_provider: Some(true.into()),
        ..Default::default()
    };
    let init = conn.initialize(serde_json::to_value(caps)?)?;
    let root = init["rootUri"]
        .as_str()
        .or_else(|| init["workspaceFolders"][0]["uri"].as_str())
        .and_then(path_of)
        .unwrap_or(dir);
    let mut server = Server {
        conn,
        ws: Workspace::new(root, extends),
        docs: HashMap::new(),
        checked: HashMap::new(),
        shown: None,
    };
    server.run()?;
    drop(server);
    io.join()?;
    Ok(())
}

fn path_of(uri: &str) -> Option<PathBuf> {
    let raw = uri.strip_prefix("file://")?;
    let decoded = percent_encoding::percent_decode_str(raw)
        .decode_utf8()
        .ok()?;
    // `file:///C:/x` on Windows.
    let p = match decoded.strip_prefix('/') {
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') => rest.to_string(),
        _ => decoded.into_owned(),
    };
    Some(PathBuf::from(p))
}

fn digest(text: &str) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    text.hash(&mut h);
    h.finish()
}

impl Server {
    fn run(&mut self) -> Result<()> {
        while let Ok(first) = self.conn.receiver.recv() {
            // Everything the editor has already sent is read before anything is
            // checked: ten keystrokes queued behind a slow check cost one check.
            let batch: Vec<Message> = std::iter::once(first)
                .chain(self.conn.receiver.try_iter())
                .collect();
            let mut stale: Vec<String> = Vec::new();
            for msg in batch {
                match msg {
                    Message::Request(req) => {
                        if self.conn.handle_shutdown(&req)? {
                            return Ok(());
                        }
                        self.request(req)?;
                    }
                    Message::Notification(n) => self.notification(n, &mut stale)?,
                    Message::Response(_) => {}
                }
            }
            for uri in stale {
                self.check(&uri)?;
            }
        }
        Ok(())
    }

    /// Updates the documents; `stale` collects the ones to check once the queue is empty.
    fn notification(&mut self, n: Notification, stale: &mut Vec<String>) -> Result<()> {
        let uri = n.params["textDocument"]["uri"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        match n.method.as_str() {
            DidOpenTextDocument::METHOD => {
                let text = n.params["textDocument"]["text"]
                    .as_str()
                    .unwrap_or_default();
                self.docs.insert(uri.clone(), text.to_string());
            }
            DidChangeTextDocument::METHOD => {
                // Full sync: the last change holds the whole document.
                if let Some(text) = n.params["contentChanges"]
                    .as_array()
                    .and_then(|c| c.last())
                    .and_then(|c| c["text"].as_str())
                {
                    self.docs.insert(uri.clone(), text.to_string());
                }
            }
            DidSaveTextDocument::METHOD => {}
            DidCloseTextDocument::METHOD => {
                self.docs.remove(&uri);
                self.checked.remove(&uri);
                stale.retain(|u| *u != uri);
                return self.publish(&uri, Vec::new());
            }
            _ => return Ok(()),
        }
        if !stale.contains(&uri) {
            stale.push(uri);
        }
        Ok(())
    }

    fn request(&mut self, req: Request) -> Result<()> {
        let resp = match req.method.as_str() {
            // A malformed request gets an error response; it must not kill the server.
            CodeActionRequest::METHOD => {
                match serde_json::from_value::<CodeActionParams>(req.params) {
                    Ok(params) => match crate::panic::contain(|| self.code_actions(&params)) {
                        Ok(actions) => Response::new_ok(req.id, serde_json::to_value(actions)?),
                        Err(e) => Response::new_err(
                            req.id,
                            ErrorCode::InternalError as i32,
                            format!("larpcop cannot fix this file: {e:#}"),
                        ),
                    },
                    Err(e) => {
                        Response::new_err(req.id, ErrorCode::InvalidParams as i32, e.to_string())
                    }
                }
            }
            _ => Response::new_ok(req.id, serde_json::Value::Null),
        };
        self.conn.sender.send(resp.into()).context("client gone")
    }

    /// Publishes the diagnostics of one document, unless it is exactly what was
    /// last checked. A check that cannot run says so: an empty list would look like
    /// a clean file.
    fn check(&mut self, uri: &str) -> Result<()> {
        let (Some(path), Some(text)) = (path_of(uri), self.docs.get(uri)) else {
            return self.publish(uri, Vec::new());
        };
        let checked = self.ws.ctx().and_then(|(ctx, fingerprint)| {
            let key = (digest(text), fingerprint);
            if self.checked.get(uri) == Some(&key) {
                return Ok(None);
            }
            Ok(Some((
                key,
                crate::panic::contain(|| ctx.check_buffer(&path, text))?,
            )))
        });
        match checked {
            Ok(None) => Ok(()),
            Ok(Some((key, outcome))) => {
                let lines: Vec<&str> = text.lines().collect();
                let diagnostics = outcome
                    .violations
                    .iter()
                    .map(|v| diagnostic(v, &lines))
                    .collect();
                self.checked.insert(uri.to_string(), key);
                self.shown = None;
                self.publish(uri, diagnostics)
            }
            Err(e) => {
                let message = format!("larpcop cannot check this file: {e:#}");
                self.checked.remove(uri);
                if self.shown.as_ref() != Some(&message) {
                    let params = ShowMessageParams {
                        typ: MessageType::ERROR,
                        message: message.clone(),
                    };
                    let n = Notification::new(ShowMessage::METHOD.into(), params);
                    self.conn.sender.send(n.into()).context("client gone")?;
                    self.shown = Some(message.clone());
                }
                let broken = Diagnostic {
                    range: Range::default(),
                    severity: Some(DiagnosticSeverity::ERROR),
                    source: Some("larpcop".into()),
                    message,
                    ..Default::default()
                };
                self.publish(uri, vec![broken])
            }
        }
    }

    // `WorkspaceEdit::changes` is keyed by `Uri` in lsp-types' own API.
    #[allow(clippy::mutable_key_type)]
    fn code_actions(&mut self, params: &CodeActionParams) -> Result<Vec<CodeActionOrCommand>> {
        let uri = params.text_document.uri.as_str().to_string();
        let (Some(path), Some(text)) = (path_of(&uri), self.docs.get(&uri)) else {
            return Ok(Vec::new());
        };
        let Some(fixed) = self.ws.ctx()?.0.fix_buffer(&path, text)? else {
            return Ok(Vec::new());
        };
        let end = Position::new(text.lines().count() as u32 + 1, 0);
        let edit = TextEdit::new(Range::new(Position::new(0, 0), end), fixed);
        let changes = HashMap::from([(Uri::from_str(&uri)?, vec![edit])]);
        Ok(vec![CodeActionOrCommand::CodeAction(CodeAction {
            title: "larpcop: apply rule fixes".into(),
            kind: Some(CodeActionKind::QUICKFIX),
            edit: Some(WorkspaceEdit {
                changes: Some(changes),
                ..Default::default()
            }),
            ..Default::default()
        })])
    }

    fn publish(&self, uri: &str, diagnostics: Vec<Diagnostic>) -> Result<()> {
        let params = PublishDiagnosticsParams {
            uri: Uri::from_str(uri)?,
            diagnostics,
            version: None,
        };
        let n = Notification::new(PublishDiagnostics::METHOD.into(), params);
        self.conn.sender.send(n.into()).context("client gone")
    }
}

/// From the reported column to the end of that line.
fn diagnostic(v: &Violation, lines: &[&str]) -> Diagnostic {
    let line = v.line.saturating_sub(1);
    let col = v.column.saturating_sub(1) as u32;
    let width = lines
        .get(line)
        .map_or(0, |l| l.encode_utf16().count() as u32);
    let severity = match v.level {
        Level::Error => DiagnosticSeverity::ERROR,
        Level::Warning => DiagnosticSeverity::WARNING,
        Level::Info => DiagnosticSeverity::INFORMATION,
        Level::Hint => DiagnosticSeverity::HINT,
    };
    let message = match &v.note {
        Some(note) => format!("{}\n{note}", v.message),
        None => v.message.clone(),
    };
    Diagnostic {
        range: Range::new(
            Position::new(line as u32, col),
            Position::new(line as u32, width.max(col + 1)),
        ),
        severity: Some(severity),
        code: Some(NumberOrString::String(v.rule.clone())),
        source: Some("larpcop".into()),
        message,
        ..Default::default()
    }
}
