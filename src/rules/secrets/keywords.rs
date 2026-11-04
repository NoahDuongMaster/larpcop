//! The keyword prefilter of the secret rules: which of all rules' keywords a
//! text holds, found in one pass over it instead of one pass per keyword.

use anyhow::{Result, anyhow, bail};
use regex::{Regex, RegexBuilder};

pub(super) struct Keywords {
    /// The distinct keywords, sorted; a keyword's index is its id.
    words: Vec<String>,
    /// `starts[i]`: `i` and every other keyword that `words[i]` begins with.
    starts: Vec<Vec<usize>>,
    /// Any keyword, ASCII case-insensitive, longest first.
    any: Regex,
}

impl Keywords {
    /// The prefilter for the (lowercase) keywords of each rule, and the ids of
    /// each rule's keywords.
    pub(super) fn new(lists: &[Vec<String>]) -> Result<(Self, Vec<Vec<usize>>)> {
        let mut words: Vec<String> = lists.iter().flatten().cloned().collect();
        words.sort();
        words.dedup();
        // `found_in` rests on keywords being ASCII (see there); a keyword
        // that is empty would match everywhere.
        if let Some(word) = words.iter().find(|w| w.is_empty() || !w.is_ascii()) {
            bail!("keyword {word:?} is empty or not ASCII");
        }
        let ids = lists
            .iter()
            .map(|list| {
                list.iter()
                    .map(|k| {
                        words
                            .binary_search(k)
                            .map_err(|_| anyhow!("keyword `{k}` is missing"))
                    })
                    .collect()
            })
            .collect::<Result<_>>()?;
        let starts = words
            .iter()
            .map(|w| {
                (0..words.len())
                    .filter(|i| w.starts_with(&words[*i]))
                    .collect()
            })
            .collect();
        // Longest first: at one position the match is the longest keyword
        // there, and `starts` names the shorter ones it also holds.
        let mut longest_first: Vec<&String> = words.iter().collect();
        longest_first.sort_by_key(|w| std::cmp::Reverse(w.len()));
        let alternatives: Vec<String> = longest_first.iter().map(|w| regex::escape(w)).collect();
        let any = RegexBuilder::new(&alternatives.join("|"))
            .case_insensitive(true)
            .unicode(false)
            .build()?;
        Ok((Self { words, starts, any }, ids))
    }

    /// For every keyword id, whether `text.to_lowercase()` contains it.
    pub(super) fn found_in(&self, text: &str) -> Vec<bool> {
        // `to_lowercase` leaves non-ASCII characters non-ASCII except in two
        // places: the Kelvin sign becomes `k`, and `İ` becomes `i` and an
        // accent. A text holding one is lowercased as a whole; any other is
        // searched as it is, ASCII letters in either case, which is the same
        // as searching its lowercase for ASCII keywords.
        let lowered;
        let text = if text.contains('\u{212A}') || text.contains('\u{130}') {
            lowered = text.to_lowercase();
            lowered.as_str()
        } else {
            text
        };
        let mut found = vec![false; self.words.len()];
        let mut missing = self.words.len();
        let mut from = 0;
        // Restarting right after each match start finds the keywords that
        // overlap the one matched.
        while missing > 0
            && let Some(hit) = self.any.find_at(text, from)
        {
            for id in &self.starts[self.id_of(hit.as_str())] {
                if !found[*id] {
                    found[*id] = true;
                    missing -= 1;
                }
            }
            from = hit.start() + 1;
        }
        found
    }

    /// The id of the keyword `matched` spells in any case.
    fn id_of(&self, matched: &str) -> usize {
        self.words
            .binary_search_by(|w| {
                w.bytes()
                    .cmp(matched.bytes().map(|b| b.to_ascii_lowercase()))
            })
            .expect("the regex matches keywords only")
    }
}

#[cfg(test)]
mod tests {
    use super::Keywords;
    use crate::rules::secrets::Secrets;

    fn lists(words: &[&[&str]]) -> Vec<Vec<String>> {
        words
            .iter()
            .map(|l| l.iter().map(|w| w.to_string()).collect())
            .collect()
    }

    /// The prefilter this one replaces: every keyword searched in the lowercase.
    fn found_by_lowercasing(keywords: &Keywords, text: &str) -> Vec<bool> {
        let lower = text.to_lowercase();
        keywords.words.iter().map(|w| lower.contains(w)).collect()
    }

    #[test]
    fn lowercasing_makes_ascii_only_from_ascii_and_two_characters() {
        // The prefilter searches the text as it is, except when it holds
        // these: if Unicode gave a third character an ASCII lowercase, it
        // would miss keywords.
        let to_ascii: Vec<char> = (0x80..=char::MAX as u32)
            .filter_map(char::from_u32)
            .filter(|c| c.to_lowercase().any(|l| l.is_ascii()))
            .collect();
        assert_eq!(to_ascii, ['\u{130}', '\u{212A}']);
    }

    #[test]
    fn overlapping_keywords_are_all_found() {
        let (kw, ids) = Keywords::new(&lists(&[&["key", "keyword"], &["word", "ord"], &["zz"]]))
            .expect("builds");
        assert_eq!(kw.words, ["key", "keyword", "ord", "word", "zz"]);
        assert_eq!(ids, [vec![0, 1], vec![3, 2], vec![4]]);
        assert_eq!(kw.found_in("my KEYWORD"), [true, true, true, true, false]);
        assert_eq!(kw.found_in("a key"), [true, false, false, false, false]);
        assert_eq!(kw.found_in("sword, zZ"), [false, false, true, true, true]);
        assert_eq!(kw.found_in(""), [false; 5]);
    }

    #[test]
    fn keywords_that_cannot_be_searched_are_refused() {
        assert!(Keywords::new(&lists(&[&["clé"]])).is_err());
        assert!(Keywords::new(&lists(&[&[""]])).is_err());
    }

    #[test]
    fn finds_what_lowercasing_finds_in_real_keywords() {
        let secrets = Secrets::new().expect("loads");
        let kw = &secrets.keywords;
        let mut pieces = kw.words.clone();
        // Case, the two characters lowercasing changes, and look-alikes it
        // does not: Kelvin sign, dotted İ, long s, sharp s, final sigma.
        pieces.extend(
            [
                "K", "İ", "ſ", "ß", "Σ", "ΑΣ", "é", "日本", "\n", " ", "-", "_", ".",
            ]
            .map(String::from),
        );
        let mut seed = 0x9E37_79B9_7F4A_7C15_u64;
        let mut next = move |n: usize| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            (seed >> 33) as usize % n
        };
        for _ in 0..3000 {
            let mut text = String::new();
            for _ in 0..1 + next(6) {
                let piece = &pieces[next(pieces.len())];
                match next(3) {
                    0 => text.push_str(&piece.to_uppercase()),
                    _ => text.push_str(piece),
                }
            }
            assert_eq!(
                kw.found_in(&text),
                found_by_lowercasing(kw, &text),
                "{text:?}"
            );
        }
    }
}
