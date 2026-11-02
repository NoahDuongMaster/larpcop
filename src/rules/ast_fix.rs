//! Applying the `fix:` of the ast-grep rules of a file.

use ast_grep_config::RuleConfig;
use ast_grep_language::{LanguageExt, SupportLang};

/// Fixes can expose new matches, so this repeats (bounded); overlapping edits
/// wait for the next pass. Returns the new text and how many fixes were applied.
pub fn apply_fixes(
    lang: SupportLang,
    source: &str,
    rules: &[&RuleConfig<SupportLang>],
) -> (String, usize) {
    let mut text = source.to_string();
    let mut total = 0;
    for _ in 0..5 {
        let grep = lang.ast_grep(&text);
        let mut edits: Vec<_> = rules
            .iter()
            .filter(|r| !r.fixer.is_empty())
            .flat_map(|rule| {
                grep.root()
                    .find_all(&rule.matcher)
                    .map(|m| m.make_edit(&rule.matcher, &rule.fixer[0]))
                    .collect::<Vec<_>>()
            })
            .collect();
        if edits.is_empty() {
            break;
        }
        edits.sort_by_key(|e| e.position);
        let mut bytes = text.clone().into_bytes();
        let mut next_start = usize::MAX;
        for e in edits.iter().rev() {
            if e.position + e.deleted_length > next_start {
                continue;
            }
            let range = e.position..e.position + e.deleted_length;
            bytes.splice(range, e.inserted_text.iter().copied());
            next_start = e.position;
            total += 1;
        }
        match String::from_utf8(bytes) {
            Ok(t) => text = t,
            Err(_) => break,
        }
    }
    (text, total)
}
