//! Types and definitions from the project's own language server instead of a
//! type checker of our own: rules ask "what is `db` here?" and get the answer
//! tsserver, pyright, gopls or rust-analyzer would show in an editor. Slower
//! than syntax, and the project's dependencies must be installed, so it is only
//! asked about candidates a syntactic rule already found, and an unavailable
//! server never hides a finding.

mod client;

use ast_grep_language::SupportLang;
use client::Client;
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};

/// (server key, default command, LSP language id).
fn server_for(lang: SupportLang) -> Option<(&'static str, &'static [&'static str], &'static str)> {
    const TS: &[&str] = &["typescript-language-server", "--stdio"];
    Some(match lang {
        SupportLang::TypeScript => ("typescript", TS, "typescript"),
        SupportLang::Tsx => ("typescript", TS, "typescriptreact"),
        SupportLang::JavaScript => ("typescript", TS, "javascript"),
        SupportLang::Python => ("python", &["pyright-langserver", "--stdio"], "python"),
        SupportLang::Go => ("go", &["gopls"], "go"),
        SupportLang::Rust => ("rust", &["rust-analyzer"], "rust"),
        _ => return None,
    })
}

/// One server per (project, command), started on first use and kept for the
/// rest of the run; `None` once it failed to start (it is not retried).
static SERVERS: LazyLock<Mutex<Servers>> = LazyLock::new(Default::default);

/// (project root, server command) → running server.
type Servers = HashMap<(PathBuf, Vec<String>), Option<Client>>;

/// Hover text for the 0-based position in `rel`, or `None` when no server
/// answers for this language.
pub fn hover(
    root: &Path,
    overrides: &BTreeMap<String, Vec<String>>,
    lang: SupportLang,
    rel: &str,
    content: &str,
    (line, character): (usize, usize),
) -> Option<String> {
    let (key, default, language_id) = server_for(lang)?;
    let argv = overrides
        .get(key)
        .cloned()
        .unwrap_or_else(|| default.iter().map(|s| s.to_string()).collect());
    let mut servers = SERVERS.lock().ok()?;
    let client = servers
        .entry((root.to_path_buf(), argv.clone()))
        .or_insert_with(|| Client::start(&argv, root).ok());
    let client = client.as_mut()?;
    client
        .hover(&root.join(rel), language_id, content, line, character)
        .ok()
        .flatten()
}

/// Stops every server (on exit they would be killed anyway; this is polite).
pub fn shutdown() {
    if let Ok(mut s) = SERVERS.lock() {
        s.clear();
    }
}
