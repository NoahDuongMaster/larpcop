//! Calls that write into an argument (C): `fgets(buf, n, stdin)`,
//! `recv(s, buf, n, 0)` put outside data into `buf` (`source_writes`);
//! `strcpy(dst, src)`, `strncat(dst, src, n)`, `sprintf(dst, fmt, …)` put what
//! they are given into `dst` (`copies`). Entries are `name:index`, or
//! `name:index..` for every argument from `index` on (`scanf:1..`). The name
//! written is the variable the argument points into: `data` in
//! `data + dataLen` or `(char *)(data + dataLen)`.

use super::NAMES;
use super::summary::{args, called_name};
use ast_grep_core::{Doc, Node};
use std::collections::{HashMap, HashSet};

#[derive(Default)]
pub(crate) struct Writes {
    sources: HashMap<String, (usize, bool)>,
    copies: HashMap<String, (usize, bool)>,
}

impl Writes {
    pub(crate) fn new(sources: &[String], copies: &[String]) -> anyhow::Result<Self> {
        Ok(Self {
            sources: parse(sources)?,
            copies: parse(copies)?,
        })
    }

    /// Could `text` call one of the calls that write outside data?
    pub(super) fn reads_input(&self, text: &str) -> bool {
        self.sources.keys().any(|name| {
            text.match_indices('(')
                .any(|(at, _)| text[..at].ends_with(name.as_str()))
        })
    }

    /// Does no call write outside data?
    pub(super) fn is_empty(&self) -> bool {
        self.sources.is_empty() && self.copies.is_empty()
    }

    /// Do some calls write outside data, tainting names out of nothing?
    pub(super) fn has_sources(&self) -> bool {
        !self.sources.is_empty()
    }

    /// The copies only: summaries of what a function does with its
    /// parameters see no source.
    pub(super) fn copies_only(&self) -> Self {
        Self {
            sources: HashMap::new(),
            copies: self.copies.clone(),
        }
    }

    /// The names `call` makes tainted, given what is tainted before it.
    pub(super) fn written<D: Doc>(
        &self,
        call: &Node<D>,
        tainted: impl Fn(&Node<D>) -> bool,
    ) -> Vec<String> {
        let Some(name) = called_name(call) else {
            return Vec::new();
        };
        let all = args(call);
        let outputs = |(at, rest): (usize, bool)| -> Vec<usize> {
            if rest {
                (at..all.len()).collect()
            } else {
                vec![at]
            }
        };
        let targets = if let Some(&spec) = self.sources.get(&name) {
            outputs(spec)
        } else if let Some(&spec) = self.copies.get(&name) {
            let written = outputs(spec);
            let given = all
                .iter()
                .enumerate()
                .any(|(i, a)| !written.contains(&i) && tainted(a));
            if !given {
                return Vec::new();
            }
            written
        } else {
            return Vec::new();
        };
        targets
            .into_iter()
            .filter_map(|i| all.get(i))
            .filter_map(|a| a.dfs().find(|n| NAMES.contains(&n.kind().as_ref())))
            .map(|n| n.text().to_string())
            .collect::<HashSet<_>>()
            .into_iter()
            .collect()
    }
}

pub(super) fn parse(entries: &[String]) -> anyhow::Result<HashMap<String, (usize, bool)>> {
    entries
        .iter()
        .map(|e| {
            let (name, index) = e
                .split_once(':')
                .ok_or_else(|| anyhow::anyhow!("`{e}`: expected `name:index` or `name:index..`"))?;
            let name = name.trim();
            anyhow::ensure!(!name.is_empty(), "`{e}`: the call's name is empty");
            let rest = index.ends_with("..");
            let at = index.trim_end_matches("..").parse::<usize>()?;
            Ok((name.to_string(), (at, rest)))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_entry_needs_a_name() {
        let entry = |e: &str| Writes::new(&[e.to_string()], &[]);
        let err = entry(":0").err().unwrap();
        assert!(err.to_string().contains("name is empty"), "{err}");
        assert!(entry(" :1..").is_err());
        assert!(entry("fgets:0").is_ok());
    }

    #[test]
    fn a_call_is_read_where_a_name_stands_before_a_parenthesis() {
        let w = Writes::new(&["fgets:0".to_string(), "aa:0".to_string()], &[]).unwrap();
        assert!(w.reads_input("x = fgets(buf);"));
        assert!(!w.reads_input("x = fgets;"));
        assert!(!w.reads_input("READ(buf)"));
        // `aa` overlaps itself in `aaa`.
        assert!(w.reads_input("aaa(x)"));
    }
}
