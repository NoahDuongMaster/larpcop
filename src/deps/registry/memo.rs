//! Lookups kept for the length of a run: several pins ask about the same package
//! (or the same version) at once, and the answer is one request.

use anyhow::{Result, anyhow};
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

/// An answer being computed, or computed: its value, or the message of its failure.
type Cell<V> = Arc<OnceLock<Result<V, String>>>;

pub(super) struct Memo<K, V>(Mutex<HashMap<K, Cell<V>>>);

impl<K: Hash + Eq, V: Clone> Memo<K, V> {
    pub fn new() -> Self {
        Self(Mutex::new(HashMap::new()))
    }

    /// `init`'s answer for `key`, computed once however many threads ask at the
    /// same time. A failure is remembered as well: retrying within the run, after
    /// the client's own retries, would only repeat it.
    pub fn get(&self, key: K, init: impl FnOnce() -> Result<V>) -> Result<V> {
        let cell = {
            let mut map = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            Arc::clone(map.entry(key).or_default())
        };
        cell.get_or_init(|| init().map_err(|e| format!("{e:#}")))
            .clone()
            .map_err(|e| anyhow!(e))
    }
}
