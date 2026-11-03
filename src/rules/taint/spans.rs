use std::ops::Range;

/// Sorted, merged byte spans. Whether a node sits inside one is a binary
/// search instead of a scan of every source and sanitizer in the file, which
/// the walk asks for each node it visits.
#[derive(Clone, Default)]
pub struct Spans {
    v: Vec<Range<usize>>,
}

impl Spans {
    pub fn new(spans: impl IntoIterator<Item = Range<usize>>) -> Spans {
        let mut v: Vec<Range<usize>> = spans.into_iter().filter(|s| s.start < s.end).collect();
        v.sort_by_key(|s| (s.start, std::cmp::Reverse(s.end)));
        let mut merged: Vec<Range<usize>> = Vec::with_capacity(v.len());
        for s in v {
            match merged.last_mut() {
                Some(last) if s.start <= last.end => last.end = last.end.max(s.end),
                _ => merged.push(s),
            }
        }
        Spans { v: merged }
    }

    /// Is `r` inside one of the spans?
    pub fn covers(&self, r: &Range<usize>) -> bool {
        self.index(r).is_some_and(|i| r.end <= self.v[i].end)
    }

    /// Does `r` touch or contain one of the spans?
    pub fn overlaps(&self, r: &Range<usize>) -> bool {
        if r.start == r.end {
            return self.covers(r);
        }
        let i = self.v.partition_point(|s| s.start < r.end);
        i > 0 && self.v[i - 1].end > r.start
    }

    pub fn is_empty(&self) -> bool {
        self.v.is_empty()
    }

    pub fn spans(&self) -> &[Range<usize>] {
        &self.v
    }

    pub fn with_extra(&self, extra: impl IntoIterator<Item = Range<usize>>) -> Spans {
        Spans::new(self.v.iter().cloned().chain(extra))
    }

    /// The last span starting at or before `r.start`.
    fn index(&self, r: &Range<usize>) -> Option<usize> {
        let i = self.v.partition_point(|s| s.start <= r.start);
        (i > 0).then(|| i - 1)
    }
}

#[cfg(test)]
mod tests {
    use super::Spans;

    fn spans(v: &[(usize, usize)]) -> Spans {
        Spans::new(v.iter().map(|(a, b)| *a..*b))
    }

    #[test]
    fn covered_only_inside() {
        let s = spans(&[(10, 20), (30, 40)]);
        assert!(s.covers(&(12..18)));
        assert!(s.covers(&(10..20)));
        assert!(!s.covers(&(5..12)));
        assert!(!s.covers(&(35..45)));
    }

    #[test]
    fn merged_spans_still_cover_everything() {
        let s = spans(&[(10, 20), (18, 26)]);
        assert!(s.covers(&(10..26)));
    }

    #[test]
    fn overlap_finds_a_span_around_or_partly_over_it() {
        let s = spans(&[(10, 20)]);
        assert!(s.overlaps(&(0..11)));
        assert!(s.overlaps(&(15..99)));
        assert!(!s.overlaps(&(20..30)));
    }
}
