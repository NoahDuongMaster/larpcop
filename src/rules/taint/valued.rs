//! `values`: a guard or sanitizer match counts only when every value a
//! metavariable can hold, as far as the file tells (literals, locals,
//! constants), matches a regex. `preg_match($ALLOW, $x)` checks `$x` only
//! for an anchored allow-list (`$re = "/^[0-9]*$/"`), not for `/[a-z]/`; a
//! value that cannot be known does not count.

use crate::rules::values::{Settings, must_hold};
use anyhow::{Context, Result};
use ast_grep_core::{Doc, NodeMatch};
use regex::Regex;
use std::collections::BTreeMap;

#[derive(Default)]
pub(crate) struct Valued(Vec<(String, Regex)>);

impl Valued {
    pub(crate) fn new(id: &str, map: &BTreeMap<String, String>) -> Result<Self> {
        map.iter()
            .map(|(var, re)| {
                let re = Regex::new(re).with_context(|| format!("taint `{id}`: values.{var}"))?;
                Ok((var.trim_start_matches('$').to_string(), re))
            })
            .collect::<Result<_>>()
            .map(Valued)
    }

    /// The matches whose constrained metavariables hold matching values.
    pub(super) fn keep<'a, D: Doc>(
        &self,
        matches: Vec<(NodeMatch<'a, D>, usize)>,
    ) -> Vec<(NodeMatch<'a, D>, usize)> {
        if self.0.is_empty() {
            return matches;
        }
        let settings = Settings::default();
        matches
            .into_iter()
            .filter(|(m, _)| {
                self.0.iter().all(|(var, re)| {
                    m.get_env()
                        .get_match(var)
                        .is_none_or(|n| must_hold(n, re, &settings))
                })
            })
            .collect()
    }
}
