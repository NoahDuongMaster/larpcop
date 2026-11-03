//! `larpcop lsp`: the same rules as diagnostics while typing, in any editor
//! with LSP support, plus a code action that applies the rules' fixes.

use crate::context::Ctx;
use crate::rules::{Level, Violation};
use anyhow::{Context, Result};
use lsp_server::{Connection, Message, Notification, Request, Response};
use lsp_types::notification::{
    DidChangeTextDocument, DidCloseTextDocument, DidOpenTextDocument, DidSaveTextDocument,
    Notification as _, PublishDiagnostics,
};
use lsp_types::request::{CodeActionRequest, Request as _};
use lsp_types::{
    CodeAction, CodeActionKind, CodeActionOrCommand, CodeActionParams, Diagnostic,
    DiagnosticSeverity, NumberOrString, Position, PublishDiagnosticsParams, Range,
    ServerCapabilities, TextDocumentSyncCapability, TextDocumentSyncKind, TextEdit, Uri,
    WorkspaceEdit,
};
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;

struct Server {
    conn: Connection,
    root: PathBuf,
    extends: Vec<String>,
    docs: HashMap<String, String>,
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
        root,
        extends,
        docs: HashMap::new(),
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

impl Server {
    fn run(&mut self) -> Result<()> {
        while let Ok(msg) = self.conn.receiver.recv() {
            match msg {
                Message::Request(req) => {
                    if self.conn.handle_shutdown(&req)? {
                        return Ok(());
                    }
                    self.request(req)?;
                }
                Message::Notification(n) => self.notification(n)?,
                Message::Response(_) => {}
            }
        }
        Ok(())
    }

    fn notification(&mut self, n: Notification) -> Result<()> {
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
                return self.publish(&uri, Vec::new());
            }
            _ => return Ok(()),
        }
        let diagnostics = self.diagnostics(&uri).unwrap_or_default();
        self.publish(&uri, diagnostics)
    }

    fn request(&mut self, req: Request) -> Result<()> {
        let resp = match req.method.as_str() {
            // A malformed request gets an error response; it must not kill the server.
            CodeActionRequest::METHOD => {
                match serde_json::from_value::<CodeActionParams>(req.params) {
                    Ok(params) => {
                        let actions = self.code_actions(&params).unwrap_or_default();
                        Response::new_ok(req.id, serde_json::to_value(actions)?)
                    }
                    Err(e) => Response::new_err(
                        req.id,
                        lsp_server::ErrorCode::InvalidParams as i32,
                        e.to_string(),
                    ),
                }
            }
            _ => Response::new_ok(req.id, serde_json::Value::Null),
        };
        self.conn.sender.send(resp.into()).context("client gone")
    }

    fn ctx(&self) -> Result<Ctx> {
        Ctx::new(&self.root, self.extends.clone(), false)
    }

    fn diagnostics(&self, uri: &str) -> Result<Vec<Diagnostic>> {
        let (Some(path), Some(text)) = (path_of(uri), self.docs.get(uri)) else {
            return Ok(Vec::new());
        };
        let outcome = self.ctx()?.check_buffer(&path, text)?;
        let lines: Vec<&str> = text.lines().collect();
        Ok(outcome
            .violations
            .iter()
            .map(|v| diagnostic(v, &lines))
            .collect())
    }

    // `WorkspaceEdit::changes` is keyed by `Uri` in lsp-types' own API.
    #[allow(clippy::mutable_key_type)]
    fn code_actions(&self, params: &CodeActionParams) -> Result<Vec<CodeActionOrCommand>> {
        let uri = params.text_document.uri.as_str().to_string();
        let (Some(path), Some(text)) = (path_of(&uri), self.docs.get(&uri)) else {
            return Ok(Vec::new());
        };
        let Some(fixed) = self.ctx()?.fix_buffer(&path, text)? else {
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
