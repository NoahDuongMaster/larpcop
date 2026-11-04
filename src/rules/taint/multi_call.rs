//! A call in the walk: what it writes into its arguments, what it stores in a
//! container, and what the callee's summary does with the arguments (fills an
//! object, sinks a parameter, reads a static field).

use super::NAMES;
use super::multi_mask::{RuleId, RuleMask, TaintEnv, bit, rules_in};
use super::multi_scope::Scope;
use super::multi_summary::MultiSummary;
use super::multi_walk::{MultiCtx, MultiReached, MultiSeen};
use super::summary::args;
use ast_grep_core::{Doc, Node};

impl<'a, 'h, D: Doc> MultiCtx<'a, 'h, D> {
    pub(super) fn step_call(
        &self,
        call: &Node<'a, D>,
        st: &mut Scope<'_>,
        on: &mut dyn FnMut(MultiSeen<'a, D>),
    ) {
        let active = self.hits.active;
        // `fgets(buf, …)`, `strcat(dst, src)`: the written argument.
        for k in rules_in(self.writing) {
            let rule = bit(k);
            let written = self.ctxs[k as usize]
                .writes
                .written(call, |a| self.tainted_mask(a, &st.env, rule) != 0);
            for name in written {
                st.env.or_mask(&name, rule);
            }
        }
        // `list.push(x)`, `map.set(k, x)`, `Object.assign(o, x)`: the
        // container now holds what was put in. `m.put("k", v)`: that entry only.
        if let Some(value) = super::entries::stored(call)
            && let Some(entry) = super::entries::entry(call)
        {
            let tainted = self.tainted_mask(&value, &st.env, active);
            st.env.mask_out(&entry, active & !tainted);
            st.env.or_mask(&entry, tainted);
        } else {
            self.fill_container(call, st);
        }
        let resolved = self.resolve(call);
        if resolved.is_empty() {
            return;
        }
        let given = args(call);
        for res in resolved.iter() {
            let (s, here) = (&res.summary, res.rules);
            // `fill(order, x)`: `order` now holds `x`.
            for &(i, j, by) in &s.fills {
                if let (Some(from), Some(to)) = (given.get(i), given.get(j))
                    && NAMES.contains(&to.kind().as_ref())
                {
                    let tainted = self.tainted_mask(from, &st.env, by & here);
                    st.env.or_mask(&to.text(), tainted);
                }
            }
            for (&i, sinks) in &s.sinks {
                let Some(a) = given.get(i) else { continue };
                let tainted = self.tainted_mask(a, &st.env, here);
                for (rule, into) in sinks {
                    if tainted & bit(*rule) != 0
                        && !self.starts_safe(*rule, a)
                        && !self.conditioned(s, i, *rule, (call, &given), a, &st.env)
                    {
                        on(MultiSeen::Reached(MultiReached::Call {
                            arg: a.clone(),
                            into: into.clone(),
                            rule: *rule,
                        }));
                    }
                }
            }
            // A static field the callee reads, tainted here.
            for (key, into, rule) in &s.statics {
                if self.held(call, key, &st.env) & here & bit(*rule) != 0 {
                    on(MultiSeen::Reached(MultiReached::Call {
                        arg: call.clone(),
                        into: into.clone(),
                        rule: *rule,
                    }));
                }
            }
        }
    }

    /// `list.push(x)`: the variable the call fills holds what its arguments
    /// carry; for a rule whose stream writes carry no taint, only an object
    /// the scope built holds what its setters are given.
    fn fill_container(&self, call: &Node<'a, D>, st: &mut Scope<'_>) {
        let active = self.hits.active;
        let filled = super::containers::filled(call);
        let blocked = if self.writes_clean != 0 && super::containers::writes(call) {
            self.writes_clean
        } else {
            0
        };
        let (filling, setting) = match filled {
            Some(_) => (active & !blocked, blocked),
            None => (0, active),
        };
        let setter = super::containers::set_on(call, &st.built);
        for (container, rules) in [(filled, filling), (setter, setting)] {
            let Some(container) = container.filter(|_| rules != 0) else {
                continue;
            };
            let tainted = args(call).iter().fold(0, |acc, a| {
                acc | self.tainted_mask(a, &st.env, rules & !acc)
            });
            if tainted != 0 {
                for wrapped in super::containers::wrapped(call, &container) {
                    st.env.or_mask(&wrapped, tainted);
                }
                st.env.or_mask(&container, tainted);
            }
        }
    }

    /// Under `safe_prefix`: does `value` start with a matching literal?
    pub(super) fn starts_safe(&self, rule: RuleId, value: &Node<D>) -> bool {
        self.safe_prefix & bit(rule) != 0 && self.ctxs[rule as usize].starts_safe(value)
    }

    /// Of `rules`, those under `safe_prefix` for which `value` starts safely.
    pub(super) fn safe_starts(&self, value: &Node<D>, rules: RuleMask) -> RuleMask {
        rules_in(self.safe_prefix & rules)
            .filter(|k| self.ctxs[*k as usize].starts_safe(value))
            .fold(0, |acc, k| acc | bit(k))
    }

    /// `readFile(() -> ALLOWED.contains(f), f)`: the callee reaches its sink
    /// only when this check holds. Is `arg`, parameter `i`, covered by it?
    fn conditioned(
        &self,
        s: &MultiSummary,
        i: usize,
        rule: RuleId,
        (call, given): (&Node<D>, &[Node<D>]),
        arg: &Node<D>,
        env: &TaintEnv,
    ) -> bool {
        let Some(&(_, (g, applied))) = s
            .conditions
            .get(&i)
            .and_then(|all| all.iter().find(|(r, _)| *r == rule))
        else {
            return false;
        };
        given.get(g).is_some_and(|check| {
            let applied = applied.and_then(|k| given.get(k));
            let guards = &self.ctxs[rule as usize].guards;
            let safe = super::lambdas::validated(check, applied, call, guards);
            super::lambdas::covers(arg, &env.names_of(rule), &safe)
        })
    }

    /// The rules that hold `key` (`Cls[field]`) tainted at `call`: the entry
    /// itself, or its own bare field when `call` is in `Cls`.
    fn held(&self, call: &Node<D>, key: &str, env: &TaintEnv) -> RuleMask {
        let own = env.get(key);
        let Some((class, field)) = super::statics::split(key) else {
            return own;
        };
        let bare = env.get(field) & !own;
        if bare != 0 && super::statics::within(call, class) {
            own | bare
        } else {
            own
        }
    }
}
