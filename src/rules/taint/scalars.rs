//! Whether a name is declared with a scalar type ([`super::declared::scalar`])
//! is a fact about the tree, the same for every rule and every walk of it, yet
//! each answer scans the enclosing scopes and the declarations in them. A
//! summary walk asks for every tainted name it meets, once per rule, per
//! summary round and per import depth, so the answers are kept per file text
//! and shared by all of them: in the npm `tar` package (99 rules) this scan
//! was most of the run time.

use ast_grep_core::{Doc, Node};
use ast_grep_language::SupportLang;
use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex, MutexGuard, PoisonError};

/// A node of the file: where it is and what it is.
type At = (usize, usize, u16);

/// The answers for one file text, by node.
#[derive(Default)]
pub(super) struct Scalars {
    known: Mutex<HashMap<At, bool>>,
}

/// The answers by file text.
type ByText = HashMap<String, Arc<Scalars>>;

/// By language and file text, which fix the tree (it is parsed from the text
/// with [`crate::rules::macros::expand`]): kept for the run, as the files'
/// summaries are.
static FILES: LazyLock<Mutex<HashMap<SupportLang, ByText>>> = LazyLock::new(Default::default);

/// A map holds only finished answers, so one left by a thread that panicked
/// is as good as any.
fn locked<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The answers for the tree parsed from `content`.
pub(super) fn of(lang: SupportLang, content: &str) -> Arc<Scalars> {
    let mut files = locked(&FILES);
    let by_text = files.entry(lang).or_default();
    if let Some(known) = by_text.get(content) {
        return known.clone();
    }
    by_text.entry(content.to_string()).or_default().clone()
}

impl Scalars {
    /// [`super::declared::scalar`] of `node`, a node of this file's tree.
    pub(super) fn of<D: Doc>(&self, node: &Node<D>) -> bool {
        let r = node.range();
        let at = (r.start, r.end, node.kind_id());
        if let Some(&known) = locked(&self.known).get(&at) {
            return known;
        }
        // Not under the lock: two threads may work out the same answer, which
        // is cheaper than one waiting for the other.
        let answer = super::declared::scalar(node);
        locked(&self.known).insert(at, answer);
        answer
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ast_grep_core::tree_sitter::LanguageExt;

    /// The answers for `name` (its last occurrence) in `src`, from the shared
    /// answers and from [`super::super::declared::scalar`] itself.
    fn answers(lang: SupportLang, src: &str, name: &str) -> (bool, bool) {
        let grep = lang.ast_grep(src);
        let node = grep
            .root()
            .dfs()
            .filter(|n| n.kind() == "identifier" && n.text() == name)
            .last()
            .unwrap();
        let shared = of(lang, src);
        // Asked twice: the second answer comes from the map.
        let first = shared.of(&node);
        assert_eq!(first, shared.of(&node));
        (first, super::super::declared::scalar(&node))
    }

    #[test]
    fn answers_are_those_of_the_scan() {
        let java = SupportLang::Java;
        let src = "class A { void f(String s, long id) { int n = 1; go(n, id, s); } }";
        for (name, scalar) in [("n", true), ("id", true), ("s", false)] {
            assert_eq!(answers(java, src, name), (scalar, scalar), "{name}");
        }
        let js = "function f(id) { const n = Number(id); go(n, id); }";
        assert_eq!(answers(SupportLang::JavaScript, js, "n"), (false, false));
    }

    #[test]
    fn files_differing_in_text_keep_their_own_answers() {
        // The same node (`id`, same place) is a scalar in one text, not in the other.
        let java = SupportLang::Java;
        let int = "class A { void f(int id) { go(id); } }";
        let text = "class A { void f(Str id) { go(id); } }";
        assert_eq!(answers(java, int, "id"), (true, true));
        assert_eq!(answers(java, text, "id"), (false, false));
        assert!(Arc::ptr_eq(&of(java, int), &of(java, int)));
        assert!(!Arc::ptr_eq(&of(java, int), &of(java, text)));
        assert!(!Arc::ptr_eq(&of(java, int), &of(SupportLang::CSharp, int)));
    }
}
