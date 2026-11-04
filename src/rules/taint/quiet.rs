//! What a walk can leave out because nothing it would look at can be tainted,
//! and what a context works out once for a node however often it is asked.

use super::events::Key;
use super::flow::Ctx;
use ast_grep_core::{Doc, Node};
use std::cell::{OnceCell, RefCell};
use std::collections::{HashMap, HashSet};

/// A nested function (by range), the seed it is walked with (events.rs) and
/// the tainted names it starts from, sorted.
type CapturedKey = (Key, Option<(Key, String, bool)>, Vec<String>);

/// What a context works out more than once for the same node.
#[derive(Default)]
pub(super) struct Memo {
    /// What a nested function writes to the names around it (callbacks.rs).
    pub captured: RefCell<HashMap<CapturedKey, Vec<String>>>,
    /// Whether a callback argument (by range) cleans what it is given (higher.rs).
    pub cleans: RefCell<HashMap<Key, bool>>,
    /// Does some known function read a static field (statics.rs)?
    statics: OnceCell<bool>,
}

impl Ctx {
    /// Can a walk starting from `names` find nothing: no tainted name, no
    /// source, no function returning source data, no call writing outside data?
    /// (Summaries walk with the parameter alone, and most nested functions
    /// never mention it.)
    pub fn nothing_to_follow(&self, names: &HashSet<String>) -> bool {
        names.is_empty()
            && self.sources.is_empty()
            && self.source_texts.is_empty()
            && !self.writes.has_sources()
            && !self.any_sourcing()
    }

    /// Nothing in code reading `text` can be tainted: no source in it
    /// (`holds_source`), no tainted name spelled in it, no call that could
    /// return source data.
    pub(super) fn nothing_below(
        &self,
        text: &str,
        holds_source: bool,
        names: &HashSet<String>,
    ) -> bool {
        !holds_source
            // An entry `m[k]` is spelled through its map's name.
            && !names.iter().any(|n| {
                let needle = match n.find('[') {
                    Some(i) => &n[..i],
                    None => n.as_str(),
                };
                text.contains(needle)
            })
            && !((text.contains('(') || self.bare_calls) && self.any_sourcing())
    }

    /// Can `call` change what is tainted or reach a sink given `names`? Not
    /// when nothing in it can be tainted and no call writes outside data or
    /// reads a static field whatever it is given.
    pub fn matters<D: Doc>(&self, call: &Node<D>, names: &HashSet<String>) -> bool {
        self.writes.has_sources()
            || self.reads_statics()
            || !self.nothing_below(&call.text(), self.sources.overlaps(&call.range()), names)
    }

    fn reads_statics(&self) -> bool {
        *self
            .memo
            .statics
            .get_or_init(|| self.summaries.values().any(|s| !s.statics.is_empty()))
    }
}
