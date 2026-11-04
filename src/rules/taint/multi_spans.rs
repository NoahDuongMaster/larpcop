//! Sources and sanitizers of a batch's rules by byte span, each answering for
//! which rules a node lies inside one (or touches one).

use super::multi_mask::{RuleMask, bit};
use super::spans::Spans;
use std::ops::Range;

/// The spans of every rule of a batch.
#[derive(Default)]
pub struct SpanMasks {
    /// Every rule's spans together: a node outside them is outside all.
    any: Spans,
    /// The rules that have spans, with their own.
    rules: Vec<(RuleMask, Spans)>,
}

impl SpanMasks {
    /// The spans of rule `k` being the `k`th of `per_rule`.
    pub fn new<'s>(per_rule: impl IntoIterator<Item = &'s Spans>) -> Self {
        let per_rule: Vec<(usize, &Spans)> = per_rule
            .into_iter()
            .enumerate()
            .filter(|(_, spans)| !spans.is_empty())
            .collect();
        Self {
            any: Spans::new(per_rule.iter().flat_map(|(_, s)| s.spans().iter().cloned())),
            rules: per_rule
                .into_iter()
                .map(|(k, spans)| (bit(k as u8), spans.clone()))
                .collect(),
        }
    }

    /// Which of `among` have `r` inside one of their spans?
    pub fn covers(&self, r: &Range<usize>, among: RuleMask) -> RuleMask {
        if !self.any.covers(r) {
            return 0;
        }
        self.pick(among, |spans| spans.covers(r))
    }

    /// Which of `among` have a span touching or inside `r`?
    pub fn overlaps(&self, r: &Range<usize>, among: RuleMask) -> RuleMask {
        if !self.any.overlaps(r) {
            return 0;
        }
        self.pick(among, |spans| spans.overlaps(r))
    }

    fn pick(&self, among: RuleMask, holds: impl Fn(&Spans) -> bool) -> RuleMask {
        self.rules
            .iter()
            .filter(|(rule, spans)| among & rule != 0 && holds(spans))
            .fold(0, |acc, (rule, _)| acc | rule)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spans_answer_per_rule() {
        let a = Spans::new([10..20, 30..40]);
        let none = Spans::default();
        let b = Spans::new(std::iter::once(15..45));
        let masks = SpanMasks::new([&a, &none, &b]);
        assert_eq!(masks.covers(&(12..18), !0), 0b001);
        assert_eq!(masks.covers(&(16..18), !0), 0b101);
        assert_eq!(masks.covers(&(16..18), 0b100), 0b100);
        assert_eq!(masks.covers(&(35..42), !0), 0b100);
        assert_eq!(masks.covers(&(0..5), !0), 0);
        assert_eq!(masks.overlaps(&(0..11), !0), 0b001);
        assert_eq!(masks.overlaps(&(41..50), !0), 0b100);
        assert_eq!(masks.overlaps(&(50..60), !0), 0);
    }
}
