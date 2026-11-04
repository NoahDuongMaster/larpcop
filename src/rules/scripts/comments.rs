//! Whether a script tag sits inside an HTML comment, for a page read once:
//! the questions come in increasing order, so each byte is looked at once, not
//! once per tag from the start of the page.

pub(super) struct CommentScan<'c> {
    content: &'c str,
    /// Where the page is not read yet.
    from: usize,
    /// A `<!--` was read and no `-->` after it yet.
    open: bool,
}

impl<'c> CommentScan<'c> {
    pub(super) fn new(content: &'c str) -> Self {
        Self {
            content,
            from: 0,
            open: false,
        }
    }

    /// Is `at` inside a comment that opened before it? `at` is where a `<` is
    /// and is not before the previous question: a `<!--` or `-->` cannot span
    /// it, so nothing before it is read twice.
    pub(super) fn holds(&mut self, at: usize) -> bool {
        loop {
            let seen = &self.content[self.from..at];
            if self.open {
                // `<!-->` closes itself: the dashes of the opener count.
                let Some(p) = seen.find("-->") else {
                    self.from = at;
                    return true;
                };
                self.from += p + 3;
                self.open = false;
            } else {
                let Some(p) = seen.find("<!--") else {
                    self.from = at;
                    return false;
                };
                // Back on the opener's dashes, for the `<!-->` case above.
                self.from += p + 2;
                self.open = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CommentScan;

    /// The check this replaces: the last `<!--` before `at` has no `-->` after it.
    fn from_the_start(content: &str, at: usize) -> bool {
        let before = &content[..at];
        before
            .rfind("<!--")
            .is_some_and(|open| before[open..].find("-->").is_none())
    }

    #[test]
    fn answers_as_a_scan_from_the_start_does() {
        let pieces = [
            "<!--", "-->", "<!-->", "<!---->", "<script>", "x", " ", "<", "-", ">", "!", "\n", "é",
        ];
        let mut seed = 0x2545_F491_4F6C_DD1D_u64;
        for _ in 0..3000 {
            let mut content = String::new();
            for _ in 0..(seed % 24) {
                seed = seed
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                content.push_str(pieces[(seed >> 33) as usize % pieces.len()]);
            }
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            let mut scan = CommentScan::new(&content);
            for (at, _) in content.match_indices('<') {
                assert_eq!(
                    scan.holds(at),
                    from_the_start(&content, at),
                    "{content:?} at {at}"
                );
            }
        }
    }
}
