//! Where a tainted local got its taint: from other tainted names only, or
//! from a source (or something not followed) directly. A check that pins
//! names down (`if ($ext == 'jpg' || $ext == 'png')`) also pins values built
//! from nothing tainted but them before the check
//! (`$file = bin2hex(random_bytes(16)) . '.' . $ext`).

use std::collections::{HashMap, HashSet};

#[derive(Default)]
pub(super) struct Origins(HashMap<String, Option<HashSet<String>>>);

impl Origins {
    /// `name` was just tainted from `from` (`None`: a source, or not known).
    /// `adds`: the assignment adds to the old value (`.=`, `+=`, a branch).
    pub(super) fn record(&mut self, name: &str, from: Option<HashSet<String>>, adds: bool) {
        let merged = match (adds, self.0.remove(name)) {
            (true, Some(Some(mut old))) => from.map(|f| {
                old.extend(f);
                old
            }),
            (true, Some(None)) => None,
            _ => from,
        };
        self.0.insert(name.to_string(), merged);
    }

    /// Does any name hold taint built from other tainted names, so that
    /// [`Self::widen`] can add to what a check pins?
    pub(super) fn derives(&self) -> bool {
        self.0
            .values()
            .any(|from| from.as_ref().is_some_and(|f| !f.is_empty()))
    }

    /// `pinned` and every tainted name whose taint came only from pinned names.
    pub(super) fn widen<'s>(
        &self,
        pinned: impl IntoIterator<Item = &'s String>,
        tainted: &HashSet<String>,
    ) -> HashSet<String> {
        let mut out: HashSet<String> = pinned.into_iter().cloned().collect();
        loop {
            let more: Vec<String> = tainted
                .iter()
                .filter(|n| !out.contains(*n))
                .filter(|n| {
                    self.0
                        .get(*n)
                        .and_then(|o| o.as_ref())
                        .is_some_and(|from| !from.is_empty() && from.is_subset(&out))
                })
                .cloned()
                .collect();
            if more.is_empty() {
                return out;
            }
            out.extend(more);
        }
    }
}
