//! An assignment in the walk: the rules that find its value tainted taint
//! the target; the others clean it, for the rest of the scope or, in a
//! branch, up to where the branch ends.

use super::multi_mask::{RuleId, RuleMask, TaintEnv, bit, rules_in};
use super::multi_scope::Scope;
use super::multi_walk::{MultiCtx, MultiReached, MultiSeen};
use super::{NAMES, VARIABLES, destructure};
use ast_grep_core::{Doc, Node};
use std::collections::{HashMap, HashSet};

impl<'a, 'h, D: Doc> MultiCtx<'a, 'h, D> {
    /// `target = value` at `at`; `branch`: where the branch it is in ends;
    /// `field`: the target is a field of the object.
    pub(super) fn assign(
        &self,
        st: &mut Scope<'_>,
        at: usize,
        (left, right): (&Node<'a, D>, &Node<'a, D>),
        branch: Option<usize>,
        field: bool,
        on: &mut dyn FnMut(MultiSeen<'a, D>),
    ) {
        let active = self.hits.active;
        if field {
            let ltext = left.text();
            let tainted = self.tainted_mask(right, &st.env, active);
            if tainted != 0 {
                st.mark(at, &ltext, tainted);
                st.env.or_mask(&ltext, tainted);
                on(MultiSeen::Reached(MultiReached::Field(
                    left.clone(),
                    tainted,
                )));
            }
            self.clean(st, &ltext, active & !tainted, branch);
            return;
        }
        let name = left.text();
        let appended = branch.is_some_and(|end| end == left.parent().map_or(0, |p| p.range().end));
        // Appending to a name that starts safely changes nothing.
        let skip = match appended {
            true => st.prefixed.get(name.as_ref()).copied().unwrap_or(0) & !st.env.get(&name),
            false => 0,
        };
        let rules = active & !skip;
        if rules == 0 {
            return;
        }
        let safe = self.safe_starts(right, rules);
        if !appended {
            self.remember_prefix(st, &name, safe, rules & !safe);
        }
        // PHP `$t += 0`: a number, whatever `$t` held.
        let numeric = self.numbers
            && left.parent().is_some_and(|p| {
                p.kind() == "augmented_assignment_expression" && super::numeric::arithmetic(&p)
            });
        let appended = appended && !numeric;
        let branch = if numeric { None } else { branch };
        let tainted = match numeric {
            true => 0,
            false => self.tainted_mask(right, &st.env, rules & !safe),
        };
        let track = st.track;
        let from = match track {
            true => self.built_from(right, &st.env, tainted),
            false => HashMap::new(),
        };
        if right.kind() == "object_creation_expression" && left.kind() == "identifier" {
            st.built.insert(name.to_string());
        }
        // `m['k'] = v`: that entry only.
        if let Some(entry) = super::entries::entry(left) {
            if tainted != 0 {
                // `$this->input[1] = …`: an entry of an own field.
                if super::fields::is_field(&left.child(0).unwrap_or(left.clone())) {
                    on(MultiSeen::Reached(MultiReached::Field(
                        left.clone(),
                        tainted,
                    )));
                }
                st.env.or_mask(&entry, tainted);
            }
            self.clean(st, &entry, rules & !tainted, branch);
            return;
        }
        for v in left
            .dfs()
            .filter(|n| VARIABLES.contains(&n.kind().as_ref()))
        {
            let vtext = v.text();
            if tainted != 0 {
                let adds = appended || branch.is_some();
                for k in rules_in(tainted).filter(|_| track) {
                    let known = st.env.get(&vtext) & bit(k) != 0;
                    let origins = st.origins.entry(k).or_default();
                    origins.record(&vtext, from.get(&k).cloned(), adds && known);
                }
                st.mark(at, &vtext, tainted);
                st.env.or_mask(&vtext, tainted);
            }
            if NAMES.contains(&left.kind().as_ref()) {
                self.clean(st, &vtext, rules & !tainted, branch);
            }
        }
        let clean = rules & !tainted;
        if clean != 0 && right.kind() == "identifier" && left.kind() == "object_pattern" {
            let object = right.text();
            for k in rules_in(clean) {
                let sources = &self.ctxs[k as usize].source_texts;
                for name in destructure::from_object(left, &object, sources) {
                    st.env.or_mask(&name, bit(k));
                }
            }
        }
    }

    /// `name` is cleaned for `rules`: for good, or in a branch up to where it
    /// ends.
    fn clean(&self, st: &mut Scope<'_>, name: &str, rules: RuleMask, branch: Option<usize>) {
        let removed = st.env.get(name) & rules;
        if removed != 0 {
            st.env.mask_out(name, removed);
            if let Some(end) = branch {
                st.until.push((end, name.to_string(), removed));
            }
        }
    }

    /// Names whose value starts safely (`url = reverse(…)`), per rule.
    fn remember_prefix(&self, st: &mut Scope<'_>, name: &str, safe: RuleMask, unsafe_: RuleMask) {
        if safe != 0 {
            *st.prefixed.entry(name.to_string()).or_default() |= safe;
        }
        if let Some(rules) = st.prefixed.get_mut(name) {
            *rules &= !unsafe_;
            if *rules == 0 {
                st.prefixed.remove(name);
            }
        }
    }

    /// For each of the `tainted` rules that find `value` tainted through
    /// tainted names only, not a source of its own, those names.
    fn built_from(
        &self,
        value: &Node<'a, D>,
        env: &TaintEnv,
        tainted: RuleMask,
    ) -> HashMap<RuleId, HashSet<String>> {
        let mut from: HashMap<RuleId, HashSet<String>> = HashMap::new();
        if tainted == 0 {
            return from;
        }
        let through = tainted & !self.tainted_mask(value, &TaintEnv::new(), tainted);
        for k in rules_in(through) {
            from.insert(k, HashSet::new());
        }
        for c in value.dfs().filter(|c| NAMES.contains(&c.kind().as_ref())) {
            let text = c.text();
            for k in rules_in(env.get(&text) & through) {
                from.entry(k).or_default().insert(text.to_string());
            }
        }
        from
    }
}
