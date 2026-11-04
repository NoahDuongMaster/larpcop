//! Lines of one text, found without rescanning it for every question: the
//! start of each line is located once (on the first question), then a line is
//! a binary search away.

use std::cell::OnceCell;

pub struct LineIndex<'t> {
    text: &'t str,
    /// Byte offset where each line starts; the first is 0.
    starts: OnceCell<Vec<usize>>,
}

impl<'t> LineIndex<'t> {
    pub fn new(text: &'t str) -> Self {
        Self {
            text,
            starts: OnceCell::new(),
        }
    }

    fn starts(&self) -> &[usize] {
        self.starts.get_or_init(|| {
            let breaks = self.text.match_indices('\n').map(|(at, _)| at + 1);
            std::iter::once(0).chain(breaks).collect()
        })
    }

    /// The 0-based line of byte `offset`: the number of line breaks before it.
    pub fn line_of(&self, offset: usize) -> usize {
        // The first start is 0, so at least one start is not after `offset`.
        self.starts().partition_point(|start| *start <= offset) - 1
    }

    /// Line `n` (0-based) exactly as `text.lines().nth(n)` yields it.
    pub fn line(&self, n: usize) -> Option<&'t str> {
        let starts = self.starts();
        let from = *starts.get(n)?;
        let to = starts.get(n + 1).copied().unwrap_or(self.text.len());
        // The piece up to and including its break: `lines` trims the break.
        self.text[from..to].lines().next()
    }
}

#[cfg(test)]
mod tests {
    use super::LineIndex;

    #[test]
    fn lines_and_offsets_agree_with_the_standard_library() {
        let texts = [
            "",
            "\n",
            "a",
            "a\n",
            "a\nb",
            "a\r\nb\r\n",
            "a\rb\n\n\nc\r",
            "héllo\nwörld\n日本語\n",
            "\n\nx",
        ];
        for text in texts {
            let index = LineIndex::new(text);
            for n in 0..text.lines().count() + 3 {
                assert_eq!(index.line(n), text.lines().nth(n), "line {n} of {text:?}");
            }
            for offset in (0..=text.len()).filter(|o| text.is_char_boundary(*o)) {
                let breaks = text[..offset].matches('\n').count();
                assert_eq!(index.line_of(offset), breaks, "offset {offset} of {text:?}");
            }
        }
    }
}
