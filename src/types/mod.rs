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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

#[cfg(test)]
mod tests;

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
/// rest of the run. The map is locked only to find a server's slot: a question
/// waits for its own server (starting, or busy with another question), never for
/// the servers of other projects.
static SERVERS: LazyLock<Mutex<Servers>> = LazyLock::new(Default::default);

/// (project root, server command) → its slot.
type Servers = HashMap<(PathBuf, Vec<String>), Arc<Slot>>;

#[derive(Default)]
struct Slot {
    state: Mutex<State>,
    /// A question the server rejected was already reported.
    reported: AtomicBool,
}

#[derive(Default)]
enum State {
    /// Not started yet.
    #[default]
    Fresh,
    Running(Client),
    /// Failed to start, or broke down: not started again, not asked again.
    Dead,
}

/// Answers already given: summaries ask about the same sink once per round.
static ANSWERS: LazyLock<Mutex<HashMap<Question, Option<String>>>> =
    LazyLock::new(Default::default);

/// (root, file, hash of its content, line, character).
type Question = (PathBuf, String, u64, usize, usize);

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
    let question = (
        root.to_path_buf(),
        rel.to_string(),
        digest(content),
        line,
        character,
    );
    if let Some(known) = ANSWERS.lock().ok()?.get(&question) {
        return known.clone();
    }
    let answer = ask(root, overrides, lang, rel, content, (line, character));
    ANSWERS.lock().ok()?.insert(question, answer.clone());
    answer
}

fn digest(content: &str) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    content.hash(&mut h);
    h.finish()
}

fn ask(
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
    let slot = SERVERS
        .lock()
        .ok()?
        .entry((root.to_path_buf(), argv.clone()))
        .or_default()
        .clone();
    let mut state = slot.state.lock().ok()?;
    if matches!(*state, State::Fresh) {
        *state = match Client::start(&argv, root, key == "rust") {
            Ok(client) => State::Running(client),
            Err(e) => {
                eprintln!(
                    "larpcop: warning: no type information from `{}`: {e:#}",
                    argv.join(" ")
                );
                State::Dead
            }
        };
    }
    let State::Running(client) = &mut *state else {
        return None;
    };
    match client.hover(&root.join(rel), language_id, content, line, character) {
        Ok(answer) => answer,
        Err(e) if !client.broken() => {
            // The server rejected this question and can answer the next: say so once.
            if !slot.reported.swap(true, Ordering::Relaxed) {
                eprintln!(
                    "larpcop: warning: `{}` rejected a type question: {e:#}",
                    argv.join(" ")
                );
            }
            None
        }
        Err(e) => {
            eprintln!(
                "larpcop: warning: `{}` stopped answering ({e:#}); its types are not used for the rest of this run",
                argv.join(" ")
            );
            *state = State::Dead;
            None
        }
    }
}

/// Stops every server (on exit they would be killed anyway; this is polite).
pub fn shutdown() {
    if let Ok(mut s) = SERVERS.lock() {
        s.clear();
    }
}
